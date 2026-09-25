"""Five missions: closed schemas, durable execution, and verified tenant authority."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.commands import CommandEnvelope, CommandPolicyRegistry
from app.control_plane_auth import CONTROL_PLANE_CALLERS, authorize_command
from app.identity_missions import MISSION_COMMANDS, READBACKS, authorize_mission
from app.platform.adapters.identity_services import (
    IdentityServiceAdapter,
    payload_digest,
)
from app.platform.adapter import Outcome, ReadbackStatus
from app.platform.api import KernelCommandRequest
from app.security import AuthorizationError
from tests.test_identity_service_adapters import command, context, operation, token
from tests.test_platform_security_matrix import stack, token as signed_token, headers  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
PAYLOADS: dict[str, dict[str, Any]] = {
    "face-id.access.evaluate.v1": {
        "subject_ref": "subject-1",
        "zone_ref": "zone-1",
        "occurred_at": "2026-09-24T12:00:00Z",
    },
    "face-id.presence.enter.v1": dict.fromkeys(
        ("event_ref", "camera_ref", "zone_ref", "subject_ref"), "ref-1"
    ),
    "face-id.presence.exit.v1": dict.fromkeys(
        ("event_ref", "camera_ref", "zone_ref", "subject_ref"), "ref-1"
    ),
    "camera-gateway.ptz.move.v1": {
        "camera_ref": "camera-1",
        "pan": 0.5,
        "tilt": -1,
        "zoom": 0,
        "duration_ms": 2000,
    },
    "camera-gateway.ptz.stop.v1": {"camera_ref": "camera-1"},
}
RESULTS: dict[str, dict[str, Any]] = {
    "face-id.access.evaluate.v1": {
        "decision_ref": "decision-1",
        "decision": "deny",
        "policy_ref": "policy-1",
        "evaluated_at": "2026-09-24T12:00:00Z",
        "door_effect": False,
    },
    "face-id.presence.enter.v1": {"event_ref": "ref-1"},
    "face-id.presence.exit.v1": {"event_ref": "ref-1"},
    "camera-gateway.ptz.move.v1": {
        "camera_ref": "camera-1",
        "motion_state": "stopped",
        "stop_reason": "duration_elapsed",
    },
    "camera-gateway.ptz.stop.v1": {
        "camera_ref": "camera-1",
        "motion_state": "stopped",
        "stop_reason": "explicit_stop",
    },
}


def mission(name):
    base = command(name.split(".")[0]).model_dump()
    if ".presence." in name:
        base["idempotency_key"] = "presence:" + PAYLOADS[name]["event_ref"]
    return CommandEnvelope.model_validate(
        {
            **base,
            "command_type": name,
            "capability": MISSION_COMMANDS[name][0],
            "payload": PAYLOADS[name],
        }
    )


@pytest.mark.parametrize("name", MISSION_COMMANDS)
def test_closed_contract_and_disabled_policy(name):
    cmd = mission(name)
    policy = CommandPolicyRegistry.load()
    assert policy.resolve(name).capability == cmd.capability
    assert policy.capabilities[cmd.capability] is False
    request = cmd.model_dump(exclude={"target", "capability"})
    KernelCommandRequest.model_validate(request)
    for payload in (
        {},
        {**cmd.payload, "image": "base64"},
        {**cmd.payload, "embedding": [0.1]},
        {**cmd.payload, "sql": "SELECT 1"},
    ):
        with pytest.raises(ValidationError):
            KernelCommandRequest.model_validate({**request, "payload": payload})
    assert not authorize_mission(name, ("platform.command",))


@pytest.mark.parametrize(
    "field,value",
    [
        ("pan", 1.01),
        ("tilt", -1.01),
        ("zoom", True),
        ("zoom", -0.1),
        ("duration_ms", 99),
        ("duration_ms", 0),
        ("duration_ms", 2001),
        ("duration_ms", 1.5),
    ],
)
def test_ptz_bounds(field, value):
    cmd = mission("camera-gateway.ptz.move.v1")
    with pytest.raises(ValidationError):
        CommandEnvelope.model_validate(
            {**cmd.model_dump(), "payload": {**cmd.payload, field: value}}
        )


@pytest.mark.parametrize(
    "occurred_at",
    ["today", "2026-09-24", "2026-09-24T12:00:00", "2026-99-99T12:00:00Z"],
)
def test_access_time_must_have_offset(occurred_at):
    cmd = mission("face-id.access.evaluate.v1")
    with pytest.raises(ValidationError):
        CommandEnvelope.model_validate(
            {**cmd.model_dump(), "payload": {**cmd.payload, "occurred_at": occurred_at}}
        )


@pytest.mark.parametrize("name", MISSION_COMMANDS)
@pytest.mark.asyncio
async def test_mission_readback_binding_and_no_biometrics(name):
    cmd = mission(name)
    result = dict(RESULTS[name])
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(
            202 if req.method == "POST" else 200,
            json={
                **cmd.model_dump(mode="json"),
                "operation_id": "op-1",
                "state": "completed",
                "payload_sha256": payload_digest(cmd.payload),
                "result": result,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = IdentityServiceAdapter(
            cmd.target, origin="https://service.internal.invalid", token_supplier=token
        )
        ctx = context(cmd, client)
        assert (await adapter.execute(cmd, ctx)).outcome == Outcome.ACCEPTED
        read = await adapter.readback(operation(cmd), ctx)
        assert read.status == ReadbackStatus.MATCHED
        assert read.evidence.items() >= result.items()
        result["embedding"] = [0.1]
        assert (
            await adapter.readback(operation(cmd), ctx)
        ).status == ReadbackStatus.UNAVAILABLE
        before = len(calls)
        assert (
            await adapter.execute(cmd, replace(ctx, tenant_id="foreign"))
        ).outcome == Outcome.REJECTED
        assert len(calls) == before


@pytest.mark.parametrize("name", READBACKS)
@pytest.mark.asyncio
async def test_readonly_observability_tenant_and_workload_binding(name):
    calls = []
    cmd = command("postgresql")
    body = {
        "tenant_id": cmd.tenant_id,
        "database_ref": "db-1",
        "observed_at": "2026-09-24T12:00:00Z",
        "status": "unknown",
        "evidence_refs": [],
    }

    body["checks"] = dict.fromkeys(
        READBACKS[name]["schema"]["properties"]["checks"]["properties"], None
    )

    async def credential(audience, scope, tenant):
        assert (audience, scope, tenant) == (
            "postgresql",
            "connector.postgresql.read",
            cmd.tenant_id,
        )
        return "workload-jwt"

    def handler(req):
        calls.append(req)
        assert req.method == "GET" and req.headers["x-tenant-id"] == cmd.tenant_id
        assert req.url.path == READBACKS[name]["path"] + "/db-1"
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = IdentityServiceAdapter(
            "postgresql",
            origin="https://service.internal.invalid",
            token_supplier=credential,
        )
        ctx = context(cmd, client)
        assert (
            await adapter.read_observability(name, "db-1", ctx)
        ).status == ReadbackStatus.MATCHED
        body["tenant_id"] = "foreign"
        assert (
            await adapter.read_observability(name, "db-1", ctx)
        ).status == ReadbackStatus.MISMATCH
        body["tenant_id"] = cmd.tenant_id
        body["sql"] = "raw"
        assert (
            await adapter.read_observability(name, "db-1", ctx)
        ).status == ReadbackStatus.UNAVAILABLE
        before = len(calls)
        assert (
            await adapter.read_observability("/restore", "db-1", ctx)
        ).status == ReadbackStatus.MISMATCH
        assert (
            await adapter.read_observability(name, "../db-1", ctx)
        ).status == ReadbackStatus.MISMATCH
        assert len(calls) == before


@pytest.mark.parametrize(
    "role", ["operator", "reviewer", "enrollment", "security-admin", "service"]
)
@pytest.mark.parametrize("name", MISSION_COMMANDS)
def test_client_authorization_matrix(role, name):
    matrix = json.loads(
        (ROOT / "contracts/platform/face-id-authorization.v1.json").read_text()
    )
    client = "face-id-" + role
    profile = matrix["clients"][client]
    allowed = any(
        name.startswith(prefix) for prefix in profile["allowed_command_prefixes"]
    )
    if allowed:
        authorize_command(
            CONTROL_PLANE_CALLERS[client], command_type=name, target=name.split(".")[0]
        )
        assert authorize_mission(name, tuple(profile["scopes"]))
    else:
        with pytest.raises(AuthorizationError):
            authorize_command(
                CONTROL_PLANE_CALLERS[client],
                command_type=name,
                target=name.split(".")[0],
            )


@pytest.mark.parametrize(
    "claims,expected",
    [
        ({"aud": "face-id"}, 401),
        ({"scope": "connector.face-id.command"}, 403),
        ({"azp": "connector-face-id"}, 401),
        ({"tenant_ids": ["foreign"]}, 403),
        ({"scope": "platform.command"}, 403),
    ],
)
def test_workload_and_tenant_tokens_cannot_bypass_ingress(stack, claims, expected):  # noqa: F811
    cmd = mission("face-id.access.evaluate.v1")
    body = cmd.model_dump(mode="json")
    bearer = signed_token(
        stack.settings,
        **{
            "azp": "face-id-operator",
            "sub": cmd.requested_by,
            "tenant_ids": [cmd.tenant_id],
            "scope": "platform.command face-id.access.evaluate",
            **claims,
        },
    )
    with TestClient(stack.app) as client:
        response = client.post(
            "/platform/v1/commands", json=body, headers=headers(body, bearer)
        )
    assert response.status_code == expected
    assert not stack.store._outbox


def test_cross_tenant_operation_unavailable(stack):  # noqa: F811
    import asyncio

    cmd = mission("face-id.access.evaluate.v1")
    asyncio.run(stack.store.submit(cmd, authenticated_client_id="face-id-operator"))
    with TestClient(stack.app) as client:
        for role in ("operator", "reviewer", "enrollment", "security-admin", "service"):
            bearer = signed_token(
                stack.settings,
                azp="face-id-" + role,
                tenant_ids=["foreign"],
                scope="platform.command.read",
            )
            for suffix in ("", "/timeline"):
                path = f"/platform/v1/operations/{cmd.command_id}{suffix}"
                response = client.get(
                    path, headers={"Authorization": "Bearer " + bearer}
                )
                assert response.status_code == 404
                response = client.get(
                    path,
                    headers={
                        "Authorization": "Bearer " + bearer,
                        "X-Tenant-ID": cmd.tenant_id,
                    },
                )
                assert response.status_code == 403
        bearer = signed_token(
            stack.settings,
            azp="face-id-reviewer",
            tenant_ids=[cmd.tenant_id],
            scope="platform.command.read",
        )
        assert (
            client.get(
                f"/platform/v1/operations/{cmd.command_id}",
                headers={"Authorization": "Bearer " + bearer},
            ).status_code
            == 200
        )


@pytest.mark.parametrize("name", MISSION_COMMANDS)
@pytest.mark.asyncio
async def test_durable_mission_deduplication_and_readback(name, test_settings):
    from tests.test_identity_service_adapters import assert_kernel_delivery

    await assert_kernel_delivery(mission(name), test_settings, RESULTS[name])


def test_presence_key_cannot_evade_event_uniqueness():
    cmd = mission("face-id.presence.enter.v1")
    with pytest.raises(ValidationError, match="presence idempotency"):
        CommandEnvelope.model_validate(
            {**cmd.model_dump(), "idempotency_key": "different-key"}
        )
    assert mission("face-id.presence.exit.v1").idempotency_key == cmd.idempotency_key


@pytest.mark.parametrize(
    "sid", ["face-id", "face-liveness", "camera-gateway", "postgresql"]
)
@pytest.mark.parametrize(
    "changed",
    [
        {"aud": "middleware-api"},
        {"scope": "platform.command"},
        {"azp": "face-id-operator"},
    ],
)
@pytest.mark.asyncio
async def test_workload_receiver_jwt_audience_scope_client(
    sid, changed, test_settings, monkeypatch
):
    from app.security import KeycloakJwtVerifier, SecurityError
    from tests.test_platform_security_matrix import Keys

    monkeypatch.setattr("app.security.PyJWKClient", Keys)
    settings = test_settings.model_copy(update={"keycloak_audience": sid})
    verifier = KeycloakJwtVerifier(settings)
    claims = {
        "aud": sid,
        "azp": "connector-" + sid,
        "scope": f"connector.{sid}.read",
        "tenant_id": "tenant-1",
    }
    good = signed_token(settings, **claims)
    assert (
        await verifier.verify(
            "Bearer " + good,
            expected_client_id="connector-" + sid,
            required_scope=f"connector.{sid}.read",
        )
    )["tenant_id"] == "tenant-1"
    bad = signed_token(settings, **{**claims, **changed})
    with pytest.raises(SecurityError):
        await verifier.verify(
            "Bearer " + bad,
            expected_client_id="connector-" + sid,
            required_scope=f"connector.{sid}.read",
        )


def test_published_mission_contracts_do_not_drift():
    from scripts.validate_identity_missions import validate

    validate()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_motion_is_rejected(value):
    from app.identity_missions import validate_schema

    with pytest.raises(ValueError):
        validate_schema(
            MISSION_COMMANDS["camera-gateway.ptz.move.v1"][1],
            {**PAYLOADS["camera-gateway.ptz.move.v1"], "pan": value},
        )


@pytest.mark.parametrize(
    "name,result",
    [
        (
            "camera-gateway.ptz.move.v1",
            {
                "camera_ref": "camera-1",
                "motion_state": "moving",
                "stop_reason": "duration_elapsed",
            },
        ),
        (
            "camera-gateway.ptz.stop.v1",
            {
                "camera_ref": "camera-1",
                "motion_state": "stopped",
                "stop_reason": "unknown",
            },
        ),
        (
            "face-id.access.evaluate.v1",
            {**RESULTS["face-id.access.evaluate.v1"], "door_effect": True},
        ),
        (
            "face-id.access.evaluate.v1",
            {**RESULTS["face-id.access.evaluate.v1"], "decision": "unlock"},
        ),
    ],
)
def test_no_unlock_or_unconfirmed_stop_result(name, result):
    from app.identity_missions import MISSION_RESULTS, validate_schema

    with pytest.raises(ValueError):
        validate_schema(MISSION_RESULTS[name], result)


@pytest.mark.asyncio
async def test_presence_direction_conflict_and_tenant_scoped_keys():
    from app.commands import CommandConflict, MemoryCommandStore

    store = MemoryCommandStore()
    enter = mission("face-id.presence.enter.v1")
    await store.submit(enter, authenticated_client_id="face-id-service")
    with pytest.raises(CommandConflict):
        await store.submit(
            mission("face-id.presence.exit.v1"),
            authenticated_client_id="face-id-service",
        )
    foreign = CommandEnvelope.model_validate(
        {**enter.model_dump(), "tenant_id": "tenant-2"}
    )
    await store.submit(foreign, authenticated_client_id="face-id-service")
    assert len(store._outbox) == 2
