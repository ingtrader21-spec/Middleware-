"""Canonical connector execution contract and capability registry."""
from __future__ import annotations
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping

class ProviderErrorCode(StrEnum):
    PROVIDER_AUTH_FAILED = "PROVIDER_AUTH_FAILED"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_REJECTED = "PROVIDER_REJECTED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    PROVIDER_MALFORMED_RESPONSE = "PROVIDER_MALFORMED_RESPONSE"
    PROVIDER_REFERENCE_MISMATCH = "PROVIDER_REFERENCE_MISMATCH"
    REMOTE_STATE_UNKNOWN = "REMOTE_STATE_UNKNOWN"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    EFFECT_DISABLED = "EFFECT_DISABLED"
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    CANCEL_UNSUPPORTED = "CANCEL_UNSUPPORTED"


class ReconciliationState(StrEnum):
    CONSISTENT = "CONSISTENT"
    LOCAL_BEHIND = "LOCAL_BEHIND"
    REMOTE_BEHIND = "REMOTE_BEHIND"
    REMOTE_UNKNOWN = "REMOTE_UNKNOWN"
    PARTIAL = "PARTIAL"
    REFERENCE_MISMATCH = "REFERENCE_MISMATCH"
    REPAIR_REQUIRED = "REPAIR_REQUIRED"


class EffectClass(StrEnum):
    READ_ONLY = "READ_ONLY"
    LOCAL_MUTATION = "LOCAL_MUTATION"
    EXTERNAL_MUTATION = "EXTERNAL_MUTATION"
    COMMUNICATION = "COMMUNICATION"
    TELEPHONY = "TELEPHONY"
    AUTOMATION = "AUTOMATION"
    PROVISIONING = "PROVISIONING"
    # Backward-compatible SDK names; canonical values remain explicit.
    READ = "READ_ONLY"
    WRITE = "LOCAL_MUTATION"
    EXTERNAL = "EXTERNAL_MUTATION"

@dataclass(frozen=True, slots=True)
class ExecutionContext:
    tenant_id: str
    environment: str
    correlation_id: str
    actor_id: str
    command_id: str = ""
    causation_id: str | None = None
    operation: str = ""
    connector_id: str = ""
    attempt: int = 1
    timeout_seconds: float = 30.0
    deadline_epoch: float | None = None
    effect_class: EffectClass = EffectClass.READ_ONLY
    idempotency_key: str | None = None
    cancellation_requested: bool = False
    effects_allowed: bool = False
    operation_snapshot: Mapping[str, Any] = field(default_factory=dict)
    payload: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class ConnectorCapability:
    operation: str
    effect: EffectClass = EffectClass.READ_ONLY
    cancellable: bool = False

@dataclass(frozen=True, slots=True)
class ConnectorDescriptor:
    connector_id: str
    provider: str
    version: str
    capabilities: tuple[ConnectorCapability, ...]
    implementation_version: str = "1"
    environments: frozenset[str] = frozenset({"development", "local", "test"})
    tenants: frozenset[str] | None = None
    denied_tenants: frozenset[str] = frozenset()
    dependencies: tuple[str, ...] = ()
    configuration_references: tuple[str, ...] = ()
    enabled: bool = True

@dataclass(frozen=True, slots=True)
class ConnectorError:
    code: str | ProviderErrorCode
    message: str
    retryable: bool = False
    provider_code: str | None = None

@dataclass(frozen=True, slots=True)
class ConnectorResult:
    ok: bool
    status: str
    connector_id: str = ""
    connector_version: str = ""
    operation: str = ""
    command_id: str = ""
    data: Mapping[str, Any] = field(default_factory=dict)
    provider_reference: str | None = None
    provider_status: str | None = None
    local_status: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    retry_hint: Mapping[str, Any] = field(default_factory=dict)
    reconciliation_required: bool = False
    error: ConnectorError | None = None

class ConnectorFailure(RuntimeError):
    def __init__(self, error: ConnectorError):
        super().__init__(error.message)
        self.error = error

class Connector(ABC):
    descriptor: ConnectorDescriptor

    @abstractmethod
    async def execute(self, operation: str, payload: Mapping[str, Any], context: ExecutionContext) -> ConnectorResult: ...

    @abstractmethod
    async def health(self, context: ExecutionContext) -> ConnectorResult: ...

    async def capability(self, context: ExecutionContext) -> tuple[ConnectorCapability, ...]:
        return self.descriptor.capabilities

    async def readback(self, reference: str, context: ExecutionContext) -> ConnectorResult:
        return ConnectorResult(False, "unsupported", error=ConnectorError(ProviderErrorCode.CAPABILITY_UNSUPPORTED, "readback is not supported"))

    async def reconcile(self, reference: str, context: ExecutionContext) -> ConnectorResult:
        return ConnectorResult(False, "unsupported", error=ConnectorError(ProviderErrorCode.CAPABILITY_UNSUPPORTED, "reconcile is not supported"))

    async def cancel(self, reference: str, context: ExecutionContext) -> ConnectorResult:
        return ConnectorResult(False, "unsupported", error=ConnectorError(ProviderErrorCode.CANCEL_UNSUPPORTED, "cancel is not supported"))

class ConnectorRegistry:
    def __init__(self) -> None:
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        connector_id = connector.descriptor.connector_id
        if connector_id in self._connectors:
            raise ValueError(f"connector already registered: {connector_id}")
        self._connectors[connector_id] = connector

    def get(self, connector_id: str, context: ExecutionContext) -> Connector:
        connector = self._connectors.get(connector_id)
        if connector is None:
            raise ConnectorFailure(ConnectorError("CONNECTOR_NOT_FOUND", "connector is not registered"))
        descriptor = connector.descriptor
        if not descriptor.enabled:
            raise ConnectorFailure(ConnectorError("CONNECTOR_DISABLED", "connector is disabled"))
        if context.environment not in descriptor.environments:
            raise ConnectorFailure(ConnectorError("ENVIRONMENT_NOT_ALLOWED", "connector is unavailable in this environment"))
        if context.tenant_id in descriptor.denied_tenants or (descriptor.tenants is not None and context.tenant_id not in descriptor.tenants):
            raise ConnectorFailure(ConnectorError("TENANT_NOT_ALLOWED", "connector is unavailable for this tenant"))
        return connector


    def get_connector(self, connector_id: str, context: ExecutionContext) -> Connector:
        return self.get(connector_id, context)

    def find_by_provider(self, provider: str) -> tuple[Connector, ...]:
        return tuple(self._connectors[key] for key in sorted(self._connectors) if self._connectors[key].descriptor.provider == provider)

    def resolve_operation(self, operation: str, context: ExecutionContext) -> Connector:
        matches = [
            connector
            for connector in self._connectors.values()
            if any(
                cap.operation == operation
                or (cap.operation.endswith(".") and operation.startswith(cap.operation))
                for cap in connector.descriptor.capabilities
            )
        ]
        visible = []
        for connector in matches:
            try:
                visible.append(self.get(connector.descriptor.connector_id, context))
            except ConnectorFailure:
                continue
        if len(visible) != 1:
            code = "CAPABILITY_UNSUPPORTED" if not visible else "PROVIDER_ERROR"
            raise ConnectorFailure(ConnectorError(code, "operation does not resolve to exactly one available connector"))
        return visible[0]

    def list_connectors(self, context: ExecutionContext) -> tuple[ConnectorDescriptor, ...]:
        return self.descriptors(context)

    def list_capabilities(self, connector_id: str, context: ExecutionContext) -> tuple[ConnectorCapability, ...]:
        return self.get(connector_id, context).descriptor.capabilities

    def is_available(self, connector_id: str, context: ExecutionContext) -> bool:
        try:
            self.get(connector_id, context)
            return True
        except ConnectorFailure:
            return False

    def descriptors(self, context: ExecutionContext) -> tuple[ConnectorDescriptor, ...]:
        visible = []
        for connector_id in sorted(self._connectors):
            try:
                visible.append(self.get(connector_id, context).descriptor)
            except ConnectorFailure:
                pass
        return tuple(visible)

    async def execute(self, connector_id: str, operation: str, payload: Mapping[str, Any], context: ExecutionContext) -> ConnectorResult:
        connector = self.get(connector_id, context)
        capability = next(
            (
                item
                for item in connector.descriptor.capabilities
                if item.operation == operation
                or (item.operation.endswith(".") and operation.startswith(item.operation))
            ),
            None,
        )
        if capability is None:
            raise ConnectorFailure(ConnectorError(ProviderErrorCode.CAPABILITY_UNSUPPORTED, "connector operation is not supported"))
        if capability.effect is not EffectClass.READ_ONLY and not context.effects_allowed:
            raise ConnectorFailure(ConnectorError(ProviderErrorCode.EFFECT_DISABLED, "connector effects are disabled by policy"))
        try:
            async with asyncio.timeout(context.timeout_seconds):
                result = await connector.execute(operation, payload, context)
                return ConnectorResult(
                    ok=result.ok,
                    status=result.status,
                    connector_id=connector.descriptor.connector_id,
                    connector_version=connector.descriptor.version,
                    operation=operation,
                    command_id=context.command_id,
                    data=result.data,
                    provider_reference=result.provider_reference,
                    provider_status=result.provider_status,
                    local_status=result.local_status or result.status,
                    started_at=result.started_at,
                    completed_at=result.completed_at,
                    retry_hint=result.retry_hint,
                    reconciliation_required=result.reconciliation_required,
                    error=result.error,
                )
        except TimeoutError as exc:
            raise ConnectorFailure(ConnectorError(ProviderErrorCode.PROVIDER_TIMEOUT, "connector execution timed out", retryable=True)) from exc
        except asyncio.CancelledError:
            raise
        except ConnectorFailure:
            raise
        except Exception as exc:
            raise ConnectorFailure(ConnectorError(ProviderErrorCode.PROVIDER_ERROR, "connector provider failed", provider_code=type(exc).__name__)) from exc
