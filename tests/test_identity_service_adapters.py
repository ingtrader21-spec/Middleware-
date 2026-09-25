"""Service contract and private adapter conformance without provider effects."""

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from app.api.v1.platform import ServiceCreate
from app.commands import CommandEnvelope, CommandOperation, CommandPolicyRegistry
from app.identity_service_contract import SERVICE_COMMANDS
from app.platform.adapter import (
    AdapterConfigurationError,
    AdapterContext,
    Outcome,
    ReadbackStatus,
    assert_adapter,
)
from app.platform.adapters.identity_services import (
    IdentityServiceAdapter,
    payload_digest,
)
from app.platform.registry import AdapterRegistry
from app.platform.runtime import default_adapters
from app.platform.safety import SafetySwitches

ROOT = Path(__file__).resolve().parents[1]


async def token(audience, scope, tenant_id):
    assert tenant_id in {"tenant-1", "readiness"}
    assert audience in SERVICE_COMMANDS
    assert scope in {f"connector.{audience}.command", f"connector.{audience}.read"}
    return "workload-jwt"


def command(sid):
    cap, cmd, fields = SERVICE_COMMANDS[sid]
    return CommandEnvelope(
        command_id=uuid4(),
        command_type=cmd,
        command_version="1.0",
        target=sid,
        tenant_id="tenant-1",
        requested_by="actor-1",
        correlation_id="corr-1",
        idempotency_key="idem-service-1",
        capability=cap,
        payload={f: "ref-1" for f in fields},
    )


def operation(cmd):
    body = cmd.model_dump(exclude={"payload"})
    return CommandOperation(
        **body,
        state="accepted",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def context(cmd, client):
    return AdapterContext(
        tenant_id=cmd.tenant_id,
        command_id=str(cmd.command_id),
        correlation_id=cmd.correlation_id,
        attempt=1,
        timeout_seconds=3,
        environment="test",
        deployment_sha="test",
        http=client,
        payload=cmd.payload,
        trace_context={"traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01"},
    )


@pytest.mark.parametrize("sid", SERVICE_COMMANDS)
@pytest.mark.asyncio
async def test_submit_readback_and_reconcile(sid):
    cmd = command(sid)
    requests = []

    def handler(req):
        requests.append(req)
        assert req.headers["authorization"] == "Bearer workload-jwt"
        assert req.headers["x-tenant-id"] == cmd.tenant_id
        assert req.headers["x-correlation-id"] == cmd.correlation_id
        assert "traceparent" in req.headers
        if req.url.path == "/health/ready":
            return httpx.Response(200)
        body = {
            **cmd.model_dump(mode="json"),
            "operation_id": "op-1",
            "payload_sha256": payload_digest(cmd.payload),
            "state": "completed",
        }
        if req.method == "POST":
            assert req.headers["idempotency-key"] == cmd.idempotency_key
            sent = json.loads(req.content)
            spec = json.loads(
                (
                    ROOT
                    / "contracts/platform/identity-services-adapter.v1.openapi.json"
                ).read_text()
            )
            Draft202012Validator(
                spec["paths"]["/internal/v1/commands"]["post"]["requestBody"][
                    "content"
                ]["application/json"]["schema"]
            ).validate(sent)
        return httpx.Response(202 if req.method == "POST" else 200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = IdentityServiceAdapter(
            sid, origin="https://service.internal.invalid", token_supplier=token
        )
        ctx = context(cmd, client)
        assert_adapter(adapter)
        assert (await adapter.readiness(ctx)).ready
        assert (await adapter.execute(cmd, ctx)).outcome == Outcome.ACCEPTED
        # No provider handle: reconciliation must still find the command.
        assert (
            await adapter.reconcile(operation(cmd), ctx)
        ).status == ReadbackStatus.MATCHED
        assert requests[-1].url.path == f"/internal/v1/commands/{cmd.command_id}"
        assert (
            await adapter.cancel(operation(cmd), ctx)
        ).outcome == Outcome.UNSUPPORTED
        assert not adapter.capabilities().safe_reexecution
        count = len(requests)
        assert (
            await adapter.readback(operation(cmd), replace(ctx, tenant_id="foreign"))
        ).status == ReadbackStatus.MISMATCH
        assert len(requests) == count


@pytest.mark.parametrize("status", [202, 301, 429, 500, 502, 503])
@pytest.mark.asyncio
async def test_ambiguous_submission_never_retries_blindly(status):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(status, json={}))
    ) as client:
        cmd = command("face-id")
        adapter = IdentityServiceAdapter(
            "face-id", origin="https://service.internal.invalid", token_supplier=token
        )
        assert (
            await adapter.execute(cmd, context(cmd, client))
        ).outcome == Outcome.UNKNOWN


@pytest.mark.parametrize(
    "error,expected",
    [(httpx.ConnectTimeout, Outcome.TRANSIENT), (httpx.ReadTimeout, Outcome.UNKNOWN)],
)
@pytest.mark.asyncio
async def test_transport_classification(error, expected):
    def handler(req):
        raise error("do not persist transport details")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        cmd = command("face-id")
        adapter = IdentityServiceAdapter(
            "face-id", origin="https://service.internal.invalid", token_supplier=token
        )
        assert (await adapter.execute(cmd, context(cmd, client))).outcome == expected
        assert (
            await adapter.readback(operation(cmd), context(cmd, client))
        ).status == ReadbackStatus.UNAVAILABLE


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("tenant_id", "foreign", ReadbackStatus.MISMATCH),
        ("payload_sha256", "0" * 64, ReadbackStatus.MISMATCH),
        ("idempotency_key", "foreign-key", ReadbackStatus.MISMATCH),
        ("state", "accepted", ReadbackStatus.UNAVAILABLE),
        ("state", "failed", ReadbackStatus.MISMATCH),
    ],
)
@pytest.mark.asyncio
async def test_readback_requires_bound_completed_evidence(field, value, expected):
    cmd = command("camera-gateway")
    body = {
        **cmd.model_dump(mode="json"),
        "operation_id": "op-1",
        "payload_sha256": payload_digest(cmd.payload),
        "state": "completed",
        field: value,
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=body))
    ) as client:
        adapter = IdentityServiceAdapter(
            cmd.target, origin="https://service.internal.invalid", token_supplier=token
        )
        assert (
            await adapter.readback(operation(cmd), context(cmd, client))
        ).status == expected


@pytest.mark.parametrize("sid", SERVICE_COMMANDS)
def test_source_registration_disabled_and_catalog_contract(sid, test_settings):
    policies = CommandPolicyRegistry.load()
    registry = AdapterRegistry(policies)
    adapter = IdentityServiceAdapter(
        sid, origin=f"https://{sid}.internal.invalid", token_supplier=token
    )
    registry.register(adapter)
    registry.validate()
    policy = policies.resolve(SERVICE_COMMANDS[sid][1])
    assert policy.target == sid and policy.readback_required
    assert policies.capabilities[policy.capability] is False
    switches = SafetySwitches.load()
    assert switches.provider_kill_switches[sid] is True
    assert switches.gates[policy.capability].environments == ("staging",)
    assert (
        default_adapters(
            test_settings.model_copy(update={"app_env": "production"}), http=None
        )
        == ()
    )
    catalog = json.loads(
        (ROOT / "contracts/platform/identity-services.catalog.v1.json").read_text()
    )
    entry = next(x for x in catalog["entries"] if x["service_id"] == sid)
    ServiceCreate.model_validate(entry)
    routes = json.loads((ROOT / "connectors/generated/kong-routes.v1.json").read_text())
    assert not any(x["connector_id"] == sid for x in routes["routes"])


@pytest.mark.parametrize("sid", SERVICE_COMMANDS)
def test_raw_data_and_unknown_commands_rejected_before_ledger(sid):
    body = command(sid).model_dump()
    for payload in [
        {**body["payload"], "image": "raw"},
        {k: "https://provider.invalid/raw" for k in body["payload"]},
        {},
        {k: "a" * 129 for k in body["payload"]},
    ]:
        with pytest.raises(ValidationError):
            CommandEnvelope.model_validate({**body, "payload": payload})
    with pytest.raises(ValidationError):
        CommandEnvelope.model_validate({**body, "command_type": sid + ".arbitrary.v1"})


@pytest.mark.parametrize(
    "origin",
    [
        "http://service",
        "https://u:p@service",
        "https://service/path",
        "https://service?x=1",
        "https://service#fragment",
    ],
)
def test_untrusted_origin_rejected(origin):
    with pytest.raises(AdapterConfigurationError):
        IdentityServiceAdapter("postgresql", origin=origin, token_supplier=token)


@pytest.mark.parametrize("sid", SERVICE_COMMANDS)
def test_public_request_checks_reference_contract_before_envelope(sid):
    from app.platform.api import KernelCommandRequest

    body = command(sid).model_dump(mode="json", exclude={"target", "capability"})
    assert (
        KernelCommandRequest.model_validate(body).command_type
        == SERVICE_COMMANDS[sid][1]
    )
    with pytest.raises(ValidationError):
        KernelCommandRequest.model_validate(
            {**body, "payload": {"sql": "DELETE FROM service_private_data"}}
        )


@pytest.mark.parametrize("status", [400, 401, 403, 409, 422])
@pytest.mark.asyncio
async def test_definitive_rejections(status):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(status))
    ) as client:
        cmd = command("postgresql")
        adapter = IdentityServiceAdapter(
            cmd.target, origin="https://service.internal.invalid", token_supplier=token
        )
        assert (
            await adapter.execute(cmd, context(cmd, client))
        ).outcome == Outcome.REJECTED


@pytest.mark.parametrize(
    "status,expected",
    [(404, ReadbackStatus.NOT_FOUND), (503, ReadbackStatus.UNAVAILABLE)],
)
@pytest.mark.asyncio
async def test_readback_absence_is_not_completion(status, expected):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(status))
    ) as client:
        cmd = command("postgresql")
        adapter = IdentityServiceAdapter(
            cmd.target, origin="https://service.internal.invalid", token_supplier=token
        )
        assert (
            await adapter.reconcile(operation(cmd), context(cmd, client))
        ).status == expected


@pytest.mark.parametrize("sid", SERVICE_COMMANDS)
@pytest.mark.asyncio
async def test_kernel_outbox_idempotency_and_worker_readback(sid, test_settings):
    await assert_kernel_delivery(command(sid), test_settings)


async def assert_kernel_delivery(cmd, test_settings, result=None):
    from app.commands import CommandConflict, CommandService, MemoryCommandStore
    from app.control_plane_auth import ControlPlaneCaller
    from app.platform.memory import MemoryExecutionBus
    from app.platform.principal import KernelPrincipal
    from app.platform.runtime import build_platform_runtime
    from app.platform.safety import SafetyGate

    sid = cmd.target
    base = CommandPolicyRegistry.load()
    policies = CommandPolicyRegistry(
        policies=base.policies, capabilities={**base.capabilities, cmd.capability: True}
    )
    store = MemoryCommandStore()
    commands = CommandService(store=store, policies=policies)
    switches = SafetySwitches.load()
    # Test-only admission of a MockTransport; source defaults stay disabled.
    gate = replace(
        switches.gates[cmd.capability], environments=("test",), umbrella_controls=()
    )
    switches = replace(
        switches,
        gates={**switches.gates, cmd.capability: gate},
        provider_kill_switches={**switches.provider_kill_switches, sid: False},
    )
    principal = KernelPrincipal(
        subject=cmd.requested_by,
        client_id="middleware-api",
        tenants=(cmd.tenant_id,),
        roles=(),
        scopes=(
            "platform.command",
            "face-id.access.evaluate",
            "face-id.presence.write",
            "face-id.watchlist.write",
            "face-id.enrollment.review",
            "camera-gateway.ptz.control",
            "camera-gateway.events.write",
        ),
        caller=ControlPlaneCaller(
            client_id="middleware-api",
            command_scope="platform.command",
            status_scope="platform.command.read",
            allowed_command_prefixes=(sid + ".",),
            allowed_targets=frozenset({sid}),
            connector_commands_allowed=True,
            compatibility_only=False,
        ),
    )
    posts = []

    def handler(req):
        if req.url.path == "/health/ready":
            return httpx.Response(200)
        if req.method == "POST":
            posts.append(req)
        return httpx.Response(
            202 if req.method == "POST" else 200,
            json={
                **cmd.model_dump(mode="json"),
                "operation_id": "op-1",
                "state": "completed",
                "payload_sha256": payload_digest(cmd.payload),
                **({"result": result} if result is not None else {}),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = IdentityServiceAdapter(
            sid, origin="https://service.internal.invalid", token_supplier=token
        )
        runtime = build_platform_runtime(
            test_settings,
            commands=commands,
            http=client,
            pool=None,
            service_id="middleware-integration-api",
            adapters=(adapter,),
            safety=SafetyGate(test_settings, policies, switches=switches),
        )
        assert runtime.registry_error is None
        await runtime.kernel.submit(cmd, principal)
        duplicate = await runtime.kernel.submit(cmd, principal)
        assert duplicate.duplicate and len(store._outbox) == 1 and posts == []
        changed = cmd.model_copy(
            update={"payload": {k: "ref-changed" for k in cmd.payload}}
        )
        with pytest.raises(CommandConflict):
            await runtime.kernel.submit(changed, principal)
        bus = MemoryExecutionBus(store, runtime.dispatch)
        assert await bus.run_once()
        result = await commands.get(cmd.tenant_id, cmd.command_id)
        assert result.state == "completed" and len(posts) == 1
        assert result.readback_evidence_sha256
        assert not await bus.run_once()
