"""Connector command runtime with capability and read-back enforcement."""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from typing import Any

from .errors import (
    CapabilityDisabledError,
    CommandNotAllowedError,
    ConnectorStateError,
    ReadBackRequiredError,
    StandardsValidationError,
)
from .interfaces import CapabilityProvider
from .models import (
    CommandOutcome,
    CommandRequest,
    CommandResult,
    ConnectorState,
)
from .registry import ConnectorRegistry
from .standards import (
    SECRET_KEY_NAMES,
    forbidden_paths,
    validate_traceparent,
    validate_tracestate,
)

_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")


def _required_uuid(value: str, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise CommandNotAllowedError(f"{label} must be a UUID") from error
    return str(parsed)


def _validate_result(
    result: CommandResult,
    *,
    prior_operation_id: str | None = None,
) -> CommandResult:
    if not isinstance(result, CommandResult):
        raise CommandNotAllowedError("adapter returned an invalid result type")
    if not result.operation_id or _SAFE_REFERENCE.fullmatch(result.operation_id) is None:
        raise CommandNotAllowedError("adapter result operation_id is invalid")
    if (
        prior_operation_id is not None
        and result.operation_id != prior_operation_id
    ):
        raise CommandNotAllowedError(
            "adapter changed operation_id across one command lifecycle"
        )
    secret_paths = forbidden_paths(result.safe_result, SECRET_KEY_NAMES)
    if secret_paths:
        raise CommandNotAllowedError(
            "adapter safe_result contains forbidden secret fields: "
            + ", ".join(secret_paths)
        )
    if (
        result.provider_reference is not None
        and _SAFE_REFERENCE.fullmatch(result.provider_reference) is None
    ):
        raise CommandNotAllowedError("provider_reference is invalid")
    if result.error_code is not None and not re.fullmatch(
        r"^[A-Z][A-Z0-9_]{1,127}$",
        result.error_code,
    ):
        raise CommandNotAllowedError("adapter error_code is invalid")
    return result


class StaticCapabilityProvider:
    """Small test/development provider. Production uses Middleware persistence."""

    def __init__(self, values: Mapping[tuple[str, str], bool]) -> None:
        self._values = dict(values)

    def is_enabled(self, tenant_id: str, capability: str) -> bool:
        return bool(self._values.get((tenant_id, capability), False))


class ConnectorRuntime:
    def __init__(
        self,
        registry: ConnectorRegistry,
        capabilities: CapabilityProvider,
    ) -> None:
        self._registry = registry
        self._capabilities = capabilities

    def execute(self, request: CommandRequest) -> CommandResult:
        if not request.context.tenant_id:
            raise CommandNotAllowedError("tenant_id is required")
        _required_uuid(request.context.tenant_id, "tenant_id")
        _required_uuid(request.command_id, "command_id")
        _required_uuid(request.context.correlation_id, "correlation_id")
        if not request.context.actor_id or len(request.context.actor_id) > 300:
            raise CommandNotAllowedError("actor_id is invalid")
        if (
            not request.context.causation_id
            or len(request.context.causation_id) > 180
        ):
            raise CommandNotAllowedError("causation_id is invalid")
        if len(request.context.idempotency_key) < 8:
            raise CommandNotAllowedError("idempotency_key is too short")
        if request.command_version < 1:
            raise CommandNotAllowedError("command_version must be positive")
        try:
            validate_traceparent(request.context.traceparent)
            validate_tracestate(request.context.tracestate)
        except StandardsValidationError as error:
            raise CommandNotAllowedError(str(error)) from error

        record = self._registry.get(request.connector_id)
        forbidden = set(record.manifest.forbidden_payload_keys)
        forbidden.update(SECRET_KEY_NAMES)
        secret_paths = forbidden_paths(request.payload, forbidden)
        if secret_paths:
            raise CommandNotAllowedError(
                "payload contains forbidden secret fields: "
                + ", ".join(secret_paths)
            )
        if record.state is not ConnectorState.ACTIVE:
            raise ConnectorStateError(
                f"connector {request.connector_id} is {record.state.value}"
            )

        resolved, policy = self._registry.resolve_command(
            request.command_type
        )
        if resolved.manifest.connector_id != request.connector_id:
            raise CommandNotAllowedError(
                f"{request.command_type} is owned by "
                f"{resolved.manifest.connector_id}, "
                f"not {request.connector_id}"
            )

        for forbidden_prefix in record.manifest.forbidden_command_prefixes:
            if request.command_type.startswith(forbidden_prefix):
                raise CommandNotAllowedError(request.command_type)

        capability = policy.required_capability
        if capability != "NONE":
            snapshot_value = request.context.capability_snapshot.get(
                capability
            )
            authoritative_value = self._capabilities.is_enabled(
                request.context.tenant_id,
                capability,
            )
            if snapshot_value is not True or authoritative_value is not True:
                raise CapabilityDisabledError(capability)

        adapter = self._registry.adapter_factory(request.connector_id)(
            record.manifest
        )
        result = _validate_result(adapter.execute_command(request))

        if result.outcome is CommandOutcome.UNKNOWN:
            result = _validate_result(
                adapter.reconcile_unknown(request, result),
                prior_operation_id=result.operation_id,
            )
            if result.outcome is CommandOutcome.UNKNOWN:
                return result

        if policy.readback_required and result.outcome in {
            CommandOutcome.ACCEPTED,
            CommandOutcome.SUBMITTED,
            CommandOutcome.COMPLETED,
        }:
            result = _validate_result(
                adapter.read_back(request, result),
                prior_operation_id=result.operation_id,
            )
            if result.outcome in {
                CommandOutcome.ACCEPTED,
                CommandOutcome.SUBMITTED,
                CommandOutcome.UNKNOWN,
            }:
                raise ReadBackRequiredError(
                    "authoritative read-back did not reach a terminal state "
                    f"for {request.command_id}"
                )

        return result

    def test_connection(
        self,
        connector_id: str,
        configuration: Mapping[str, Any],
    ) -> Any:
        record = self._registry.get(connector_id)
        adapter = self._registry.adapter_factory(connector_id)(
            record.manifest
        )
        errors = adapter.validate_configuration(
            record.manifest,
            configuration,
        )
        if errors:
            return {
                "ok": False,
                "code": "CONFIGURATION_INVALID",
                "errors": errors,
            }
        result = adapter.test_connection(
            record.manifest,
            configuration,
        )
        secret_paths = forbidden_paths(
            result.safe_details,
            SECRET_KEY_NAMES,
        )
        if secret_paths:
            raise CommandNotAllowedError(
                "connection test leaked forbidden fields: "
                + ", ".join(secret_paths)
            )
        return result

    def health(self, connector_id: str) -> Any:
        record = self._registry.get(connector_id)
        adapter = self._registry.adapter_factory(connector_id)(
            record.manifest
        )
        result = adapter.health()
        secret_paths = forbidden_paths(
            result.safe_details,
            SECRET_KEY_NAMES,
        )
        if secret_paths:
            raise CommandNotAllowedError(
                "health result leaked forbidden fields: "
                + ", ".join(secret_paths)
            )
        return result
