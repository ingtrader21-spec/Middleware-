import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from app.api.v1.commands import (
    OperationRegistration,
    OperationTransition,
    TerminalResultRequest,
)
from app.adapters.telephony.client import (
    TelephonyClientError,
    TelephonyReadbackPending,
    TelephonyServiceClient,
)
from app.core.telephony_commands import (
    DISABLED_ADAPTER_ENDPOINT_DEFAULTS,
    LOGICAL_ENDPOINT_KEYS,
    MUTATION_ENDPOINTS,
    READBACK_ENDPOINTS,
    TelephonyCommandRequest,
    TelephonyCommandType,
    payload_hash,
    stable_result_idempotency_key,
)
from app.workers.telephony_commands import (
    _run_while_lease,
    _validate_policy_for_dispatch,
)
from tests.test_endpoint_registry import endpoint


def command(**changes):
    values = {
        "schema_version": "1.0",
        "command_type": "telephony.asterisk.endpoint.apply",
        "aggregate_type": "agent",
        "aggregate_public_id": "AGT-SYNTHETIC-001",
        "aggregate_version": 4,
        "environment": "staging",
        "business_unit_public_id": "BU-SYNTHETIC-001",
        "campaign_public_id": "CMP-SYNTHETIC-001",
        "idempotency_key": "IDM-0000000000000001",
        "correlation_id": "COR-SYNTHETIC-001",
        "causation_id": "CAU-SYNTHETIC-001",
        "policy_decision_id": str(uuid4()),
        "policy_decision_hash": "a" * 64,
        "payload": {
            "endpoint_public_id": "EPT-SYNTHETIC-001",
            "agent_public_id": "AGT-SYNTHETIC-001",
            "allocation_reservation_id": "RSV-SYNTHETIC-001",
            "desired_state_version": 3,
        },
    }
    values.update(changes)
    return TelephonyCommandRequest.model_validate(values)


def policy_bound_command(*, expiration: str):
    value = command()
    context = {
        "decision_id": value.policy_decision_id,
        "correlation_id": value.correlation_id,
        "allow": True,
        "enforced": True,
        "action": value.policy_scope()["action"],
        "resource": "telephony.endpoint",
        "expiration": expiration,
        "authorization_scope": value.policy_scope(),
    }
    value = value.model_copy(update={"policy_decision_hash": payload_hash(context)})
    decision: Any = SimpleNamespace(
        correlation_id=value.correlation_id,
        allowed=True,
        context=context,
    )
    return value, decision


def test_dispatch_policy_is_revalidated_immediately_before_external_work():
    value, decision = policy_bound_command(expiration="2099-01-01T00:00:00+00:00")
    _validate_policy_for_dispatch(value, decision)

    expired, expired_decision = policy_bound_command(
        expiration="2000-01-01T00:00:00+00:00"
    )
    with pytest.raises(TelephonyClientError, match="authorization expired"):
        _validate_policy_for_dispatch(expired, expired_decision)


def test_all_command_routes_are_registry_keys_with_readback():
    assert set(MUTATION_ENDPOINTS.values()) <= LOGICAL_ENDPOINT_KEYS
    assert set(READBACK_ENDPOINTS.values()) <= LOGICAL_ENDPOINT_KEYS
    assert set(MUTATION_ENDPOINTS) == set(TelephonyCommandType)
    assert set(READBACK_ENDPOINTS) == set(TelephonyCommandType)
    assert "telephony.vicidial.runtime.read" in LOGICAL_ENDPOINT_KEYS
    assert "telephony.asterisk.contacts.revoke_all" in LOGICAL_ENDPOINT_KEYS
    assert all(
        defaults
        == {
            "enabled": False,
            "kill_switch": True,
            "redirects_allowed": False,
            "target_attestation_required": True,
        }
        for defaults in DISABLED_ADAPTER_ENDPOINT_DEFAULTS.values()
    )


def test_canonical_nested_command_contract_is_normalized_without_extension():
    requested_at = datetime.now(UTC)
    value = TelephonyCommandRequest.model_validate(
        {
            "schema_version": "1.0",
            "command_public_id": str(uuid4()),
            "command_type": "telephony.asterisk.endpoint.apply",
            "aggregate": {
                "type": "agent",
                "public_id": "AGT-SYNTHETIC-001",
                "version": 6,
            },
            "environment": "staging",
            "organization_public_id": "ORG-CODESTRA",
            "business_unit_public_id": "BU-SYNTHETIC-001",
            "campaign_public_id": "CMP-SYNTHETIC-001",
            "target": {
                "system": "ASTERISK",
                "resource_type": "ENDPOINT",
                "public_id": "EPT-SYNTHETIC-001",
            },
            "allocation": {
                "reservation_public_id": "RSV-SYNTHETIC-001",
                "reservation_generation": 3,
                "reservation_hash": "sha256:" + "1" * 64,
            },
            "desired_state": {
                "version": 6,
                "hash": "sha256:" + "2" * 64,
                "enabled": False,
                "context_key": "campaign-agent-restricted",
                "external_route_allowed": False,
                "transfer_allowed": False,
            },
            "idempotency_key": "IDM-SYNTHETIC-001",
            "correlation_id": "COR-SYNTHETIC-001",
            "causation_id": "CAU-SYNTHETIC-001",
            "policy_hash": "sha256:" + "3" * 64,
            "requested_at": requested_at.isoformat(),
            "expires_at": (requested_at + timedelta(minutes=5)).isoformat(),
        }
    )
    assert value.payload.endpoint_public_id == "EPT-SYNTHETIC-001"
    assert value.payload.allocation_reservation_id == "RSV-SYNTHETIC-001"
    assert "extension" not in value.model_dump_json()


def test_operation_transition_and_result_contracts_are_strict():
    registration = OperationRegistration.model_validate(
        {
            "schema_version": "1.0",
            "operation_public_id": "OPR-SYNTHETIC-001",
            "command_public_id": "CMD-SYNTHETIC-001",
            "adapter_service_key": "codestra-telephony-adapter-staging",
            "adapter_operation_id": "ADP-OP-SYNTHETIC-001",
            "target_system": "ASTERISK",
            "target_resource_type": "ENDPOINT",
            "target_public_id": "EPT-SYNTHETIC-001",
            "desired_state_version": 6,
            "desired_state_hash": "sha256:" + "1" * 64,
            "idempotency_key": "IDM-OPR-SYNTHETIC-001",
            "correlation_id": "COR-SYNTHETIC-001",
            "registered_at": "2026-07-29T20:00:01Z",
        }
    )
    transition_binding = {
        "schema_version": "1.0",
        "command_public_id": registration.command_public_id,
        "state": "APPLYING",
        "target_system": registration.target_system,
        "target_resource_type": registration.target_resource_type,
        "target_public_id": registration.target_public_id,
        "desired_state_version": registration.desired_state_version,
        "adapter_service_key": registration.adapter_service_key,
        "environment": "staging",
        "correlation_id": registration.correlation_id,
        "transition_sequence": 1,
        "occurred_at": "2026-07-29T20:00:02Z",
    }
    transition = OperationTransition.model_validate(
        {
            **transition_binding,
            "transition_hash": "sha256:"
            + payload_hash(
                OperationTransition.model_validate(
                    {
                        **transition_binding,
                        "transition_hash": "sha256:" + "0" * 64,
                    }
                ).model_dump(mode="json", exclude={"transition_hash"})
            ),
        }
    )
    assert transition.transition_sequence == 1
    result = TerminalResultRequest.model_validate(
        {
            "schema_version": "1.0",
            "result_public_id": "RES-SYNTHETIC-001",
            "command_public_id": registration.command_public_id,
            "operation_public_id": registration.operation_public_id,
            "target_system": "ASTERISK",
            "target_resource_type": "ENDPOINT",
            "target_public_id": "EPT-SYNTHETIC-001",
            "application_status": "APPLIED",
            "readback_status": "READBACK_VERIFIED",
            "requested_state_version": 6,
            "applied_state_version": 6,
            "observed_state_version": 6,
            "application_hash": "sha256:" + "2" * 64,
            "readback_hash": "sha256:" + "3" * 64,
            "result_hash": "sha256:" + "4" * 64,
            "adapter_service_key": registration.adapter_service_key,
            "adapter_configuration_checksum": "sha256:" + "5" * 64,
            "correlation_id": registration.correlation_id,
            "policy_hash": "sha256:" + "6" * 64,
            "applied_at": "2026-07-29T20:00:02Z",
            "readback_at": "2026-07-29T20:00:03Z",
            "safe_summary": "Endpoint applied and verified.",
        }
    )
    assert stable_result_idempotency_key(
        result.command_public_id,
        result.operation_public_id,
        result.target_public_id,
        result.observed_state_version,
        result.result_hash,
    ) == stable_result_idempotency_key(
        result.command_public_id,
        result.operation_public_id,
        result.target_public_id,
        result.observed_state_version,
        result.result_hash,
    )


@pytest.mark.parametrize(
    "field",
    [
        "extension",
        "server_b_ip",
        "adapter_base_url",
        "ami_address",
        "vicidial_database_host",
        "context_name",
        "trunk_name",
        "customer_number",
    ],
)
def test_command_rejects_application_selected_resources(field):
    value = command().model_dump(mode="json")
    value["payload"][field] = "forbidden"
    with pytest.raises(ValidationError):
        TelephonyCommandRequest.model_validate(value)


def test_call_control_is_outside_telephony_client_scope():
    for command_type in (
        "telephony.asterisk.internal_call.create",
        "telephony.asterisk.call.hangup",
    ):
        with pytest.raises(ValidationError):
            command(command_type=command_type)


class Resolver:
    def __init__(self, *, attestation_required=True):
        self.requests = []
        self.attestation_required = attestation_required

    async def resolve(self, request):
        self.requests.append(request)
        value = endpoint()
        return type(value)(
            **{
                **value.__dict__,
                "service_key": "telephony-adapter",
                "endpoint_key": request.endpoint_key,
                "target_attestation_required": self.attestation_required,
                "configuration_checksum": "sha256:" + "b" * 64,
            }
        )


class CommonClient:
    def __init__(self, resolver):
        self.resolver = resolver
        self.calls = []

    async def request_resolved(self, route, payload, **kwargs):
        self.calls.append((route, payload, kwargs))
        request = httpx.Request("POST", "https://invalid")
        return httpx.Response(202, json={"operation_id": str(uuid4())}, request=request)

    async def request(self, route, payload, **kwargs):
        self.calls.append((route, payload, kwargs))
        request = httpx.Request("POST" if route.mutation else "GET", "https://invalid")
        if route.mutation:
            return httpx.Response(
                202, json={"operation_id": str(uuid4())}, request=request
            )
        return httpx.Response(
            200,
            json={
                "desired_state": {
                    "endpoint_public_id": "EPT-SYNTHETIC-001",
                    "agent_public_id": "AGT-SYNTHETIC-001",
                    "allocation_reservation_id": "RSV-SYNTHETIC-001",
                    "desired_state_version": 3,
                    "state": "DISABLED",
                }
            },
            request=request,
        )


class Attestor:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.calls = []

    async def attest(self, **kwargs):
        self.calls.append(kwargs)
        return self.allowed


@pytest.mark.asyncio
async def test_external_operation_is_cancelled_when_lease_renewal_fails():
    operation_cancelled = asyncio.Event()

    async def slow_operation():
        try:
            await asyncio.Future()
        finally:
            operation_cancelled.set()

    async def failed_heartbeat():
        await asyncio.sleep(0)
        raise RuntimeError("synthetic lease database failure")

    heartbeat = asyncio.create_task(failed_heartbeat())
    with pytest.raises(RuntimeError, match="synthetic lease database failure"):
        await _run_while_lease(slow_operation(), heartbeat)
    assert operation_cancelled.is_set()


@pytest.mark.asyncio
async def test_completed_operation_does_not_cancel_shared_lease_heartbeat():
    async def heartbeat_loop():
        await asyncio.Future()

    heartbeat = asyncio.create_task(heartbeat_loop())
    result = await _run_while_lease(
        asyncio.sleep(0, result={"operation_id": "synthetic"}), heartbeat
    )
    assert result == {"operation_id": "synthetic"}
    assert not heartbeat.done()
    heartbeat.cancel()
    with pytest.raises(asyncio.CancelledError):
        await heartbeat


@pytest.mark.asyncio
async def test_dispatch_uses_registry_common_client_attestation_and_readback():
    resolver = Resolver()
    common = CommonClient(resolver)
    attestor = Attestor()
    client = TelephonyServiceClient(common, attestor)
    value = command()
    operation = await client.dispatch(
        "CMD-SYNTHETIC-001",
        value,
        traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
    )
    assert resolver.requests[0].service_key == "telephony-adapter"
    assert resolver.requests[0].endpoint_key == "telephony.asterisk.endpoints.apply"
    assert resolver.requests[0].mutation is True
    assert attestor.calls[0]["configuration_checksum"].startswith("sha256:")
    assert common.calls[0][2]["idempotency_key"] == payload_hash(
        {
            "command_public_id": "CMD-SYNTHETIC-001",
            "resolved_endpoint_id": endpoint().endpoint_id,
            "endpoint_configuration_version": endpoint().endpoint_version_id,
        }
    )
    readback = await client.readback(
        value,
        operation,
        traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
    )
    assert common.calls[1][0].endpoint_key == "telephony.asterisk.endpoints.read"
    assert common.calls[1][0].mutation is False
    assert readback["actual_hash"]
    assert readback["readback_matches"] is True


@pytest.mark.asyncio
async def test_dispatch_fails_closed_without_attestation():
    client = TelephonyServiceClient(CommonClient(Resolver()), Attestor(False))
    with pytest.raises(TelephonyClientError, match="attestation failed"):
        await client.dispatch(
            "CMD-SYNTHETIC-001",
            command(),
            traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
        )


@pytest.mark.asyncio
async def test_post_write_timeout_returns_ambiguous_operation_for_readback():
    resolver = Resolver()
    common = CommonClient(resolver)

    async def timeout_after_possible_write(route, payload, **kwargs):
        raise httpx.ReadTimeout("synthetic ambiguous timeout")

    common.request_resolved = timeout_after_possible_write
    client = TelephonyServiceClient(common, Attestor())
    operation = await client.dispatch(
        "CMD-SYNTHETIC-AMBIGUOUS",
        command(),
        traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
    )
    assert operation["ambiguous"] is True
    assert operation["operation_public_id"].startswith("OPR-")
    assert operation["adapter_operation_id"]


@pytest.mark.asyncio
async def test_acknowledged_operation_not_yet_visible_is_retryable():
    resolver = Resolver()
    common = CommonClient(resolver)

    async def pending_readback(route, payload, **kwargs):
        request = httpx.Request("GET", "https://invalid")
        return httpx.Response(404, json={"status": "pending"}, request=request)

    common.request = pending_readback
    client = TelephonyServiceClient(common, Attestor())
    with pytest.raises(TelephonyReadbackPending, match="not yet visible"):
        await client.readback(
            command(),
            {
                "operation_id": str(uuid4()),
                "desired_hash": "a" * 64,
            },
            traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
        )


@pytest.mark.asyncio
async def test_dispatch_rejects_route_that_does_not_require_attestation():
    client = TelephonyServiceClient(
        CommonClient(Resolver(attestation_required=False)), Attestor()
    )
    with pytest.raises(TelephonyClientError, match="must require attestation"):
        await client.dispatch(
            "CMD-SYNTHETIC-001",
            command(),
            traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
        )


@pytest.mark.parametrize(
    ("command_type", "payload"),
    [
        (
            "telephony.vicidial.user.apply",
            {
                "endpoint_public_id": "EPT-WRONG-001",
                "allocation_reservation_id": "RSV-001",
                "desired_state_version": 1,
            },
        ),
        (
            "telephony.vicidial.phone.apply",
            {
                "agent_public_id": "AGT-WRONG-001",
                "allocation_reservation_id": "RSV-001",
                "desired_state_version": 1,
            },
        ),
        (
            "telephony.asterisk.contacts.revoke_all",
            {
                "agent_public_id": "AGT-WRONG-001",
                "allocation_reservation_id": "RSV-001",
                "desired_state_version": 1,
            },
        ),
    ],
)
def test_command_specific_target_is_required(command_type, payload):
    with pytest.raises(ValidationError):
        command(command_type=command_type, payload=payload)
