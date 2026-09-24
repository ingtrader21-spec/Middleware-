"""Registry-only telephony command dispatcher."""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from app.core.endpoint_registry import ResolutionRequest
from app.core.endpoint_registry import ResolvedEndpoint
from app.core.service_client import CommonServiceClient
from app.core.telephony_commands import (
    MUTATION_ENDPOINTS,
    READBACK_ENDPOINTS,
    TelephonyCommandRequest,
    normalized_actual_state,
    payload_hash,
)


class TelephonyClientError(RuntimeError):
    pass


class TelephonyReadbackPending(TelephonyClientError):
    """An acknowledged adapter operation is not yet visible to readback."""


class TargetAttestor(Protocol):
    async def attest(
        self,
        *,
        route: ResolvedEndpoint,
        environment: str,
        endpoint_key: str,
        configuration_checksum: str,
        correlation_id: str,
    ) -> bool: ...


class TelephonyServiceClient:
    def __init__(
        self, common_client: CommonServiceClient, attestor: TargetAttestor
    ) -> None:
        self.common_client = common_client
        self.attestor = attestor

    def _route(
        self, command: TelephonyCommandRequest, endpoint_key: str, *, mutation: bool
    ) -> ResolutionRequest:
        return ResolutionRequest(
            environment=command.environment,
            service_key="telephony-adapter",
            endpoint_key=endpoint_key,
            business_unit_public_id=command.business_unit_public_id,
            campaign_public_id=command.campaign_public_id,
            mutation=mutation,
        )

    async def dispatch(
        self, command_id: str, command: TelephonyCommandRequest, *, traceparent: str
    ) -> dict[str, Any]:
        endpoint_key = MUTATION_ENDPOINTS[command.command_type]
        route_request = self._route(command, endpoint_key, mutation=True)
        route = await self.common_client.resolver.resolve(route_request)
        if not route.target_attestation_required:
            raise TelephonyClientError(
                "telephony mutation route must require attestation"
            )
        if not await self.attestor.attest(
            route=route,
            environment=command.environment,
            endpoint_key=endpoint_key,
            configuration_checksum=route.configuration_checksum,
            correlation_id=command.correlation_id,
        ):
            raise TelephonyClientError("telephony target attestation failed")
        dispatch_key = payload_hash(
            {
                "command_public_id": command.command_public_id or command_id,
                "resolved_endpoint_id": route.endpoint_id,
                "endpoint_configuration_version": route.endpoint_version_id,
            }
        )
        try:
            response = await self.common_client.request_resolved(
                route,
                {
                    "command_id": command_id,
                    **command.model_dump(mode="json"),
                },
                idempotency_key=dispatch_key,
                request_id=command_id,
                correlation_id=command.correlation_id,
                causation_id=command.causation_id,
                traceparent=traceparent,
            )
        except httpx.TimeoutException:
            operation_public_id = "OPR-" + dispatch_key[:32]
            return {
                "operation_id": operation_public_id,
                "operation_public_id": operation_public_id,
                "adapter_operation_id": dispatch_key,
                "adapter_service_key": route.service_key,
                "endpoint_id": route.endpoint_id,
                "endpoint_version_id": route.endpoint_version_id,
                "endpoint_key": endpoint_key,
                "readback_endpoint_key": READBACK_ENDPOINTS[command.command_type],
                "target_configuration_checksum": route.configuration_checksum,
                "target_attested": True,
                "desired_hash": payload_hash(command.desired_state()),
                "ambiguous": True,
            }
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict) or not result.get("operation_id"):
            raise TelephonyClientError("invalid telephony operation acknowledgement")
        adapter_operation_id = str(result["operation_id"])
        if len(adapter_operation_id) > 144:
            raise TelephonyClientError("telephony operation ID is invalid")
        operation_public_id = (
            "OPR-"
            + payload_hash(
                {
                    "command_public_id": command.command_public_id or command_id,
                    "adapter_operation_id": adapter_operation_id,
                }
            )[:32]
        )
        return {
            "operation_id": operation_public_id,
            "operation_public_id": operation_public_id,
            "adapter_operation_id": adapter_operation_id,
            "adapter_service_key": route.service_key,
            "endpoint_id": route.endpoint_id,
            "endpoint_version_id": route.endpoint_version_id,
            "endpoint_key": endpoint_key,
            "readback_endpoint_key": READBACK_ENDPOINTS[command.command_type],
            "target_configuration_checksum": route.configuration_checksum,
            "target_attested": True,
            "desired_hash": payload_hash(command.desired_state()),
        }

    async def readback(
        self,
        command: TelephonyCommandRequest,
        operation: dict[str, Any],
        *,
        traceparent: str,
    ) -> dict[str, Any]:
        endpoint_key = READBACK_ENDPOINTS[command.command_type]
        response = await self.common_client.request(
            self._route(command, endpoint_key, mutation=False),
            {
                "operation_id": operation["operation_id"],
                "aggregate_public_id": command.aggregate_public_id,
                "allocation_reservation_id": command.payload.allocation_reservation_id,
            },
            idempotency_key=command.idempotency_key,
            request_id=str(operation["operation_id"]),
            correlation_id=command.correlation_id,
            causation_id=command.causation_id,
            traceparent=traceparent,
        )
        if response.status_code == 404:
            raise TelephonyReadbackPending(
                "acknowledged telephony operation is not yet visible"
            )
        response.raise_for_status()
        actual = response.json()
        if not isinstance(actual, dict):
            raise TelephonyClientError("invalid telephony readback")
        try:
            normalized = normalized_actual_state(command, actual)
        except ValueError as exc:
            raise TelephonyClientError(str(exc)) from exc
        actual_hash = payload_hash(normalized)
        return {
            "actual": actual,
            "normalized_actual": normalized,
            "actual_hash": actual_hash,
            "readback_matches": actual_hash == operation["desired_hash"],
        }

    async def aclose(self) -> None:
        await self.common_client.aclose()


class RegistryTargetAttestor:
    def __init__(self, common_client: CommonServiceClient) -> None:
        self.common_client = common_client

    async def attest(
        self,
        *,
        route: ResolvedEndpoint,
        environment: str,
        endpoint_key: str,
        configuration_checksum: str,
        correlation_id: str,
    ) -> bool:
        route_identity_hash = payload_hash(
            {
                "service_key": route.service_key,
                "endpoint_key": route.endpoint_key,
                "endpoint_id": route.endpoint_id,
                "endpoint_version_id": route.endpoint_version_id,
                "configuration_checksum": route.configuration_checksum,
                "method": route.method,
                "base_url_hash": payload_hash(route.base_url),
                "path_hash": payload_hash(route.path),
            }
        )
        response = await self.common_client.request(
            ResolutionRequest(
                environment=environment,
                service_key="telephony-adapter",
                endpoint_key="telephony.service.attest",
                mutation=False,
            ),
            {
                "endpoint_key": endpoint_key,
                "configuration_checksum": configuration_checksum,
                "endpoint_version_id": route.endpoint_version_id,
                "route_identity_hash": route_identity_hash,
            },
            idempotency_key=correlation_id,
            request_id=correlation_id,
            correlation_id=correlation_id,
            causation_id=endpoint_key,
            traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
        )
        response.raise_for_status()
        value = response.json()
        return bool(
            isinstance(value, dict)
            and value.get("service_key") == "telephony-adapter"
            and value.get("endpoint_key") == endpoint_key
            and value.get("configuration_checksum") == configuration_checksum
            and value.get("endpoint_version_id") == route.endpoint_version_id
            and value.get("route_identity_hash") == route_identity_hash
        )
