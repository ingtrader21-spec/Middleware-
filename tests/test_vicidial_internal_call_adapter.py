"""Contract tests for Middleware -> restricted Server B calls; no live call."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.calling_contract import CAPABILITY, CLIENT_ID, HANGUP, ORIGINATE, CallingGrant, CallPrincipal
from app.temporal_workflows import CommandExecutionRequest
from app.vicidial_internal_call_adapter import (
    VicidialInternalCallAdapter, VicidialInternalCallError,
    VicidialInternalCallPreDispatchRejected, VicidialInternalCallUnknown,
)

SOURCE_SHA = "a" * 40
SECRET = b"synthetic-hmac-value-with-32-bytes-minimum"


@pytest.fixture(autouse=True)
def emulate_root_owned_policy(monkeypatch):
    """CI is non-root; only the fstat ownership observation is synthesized."""
    actual_fstat = os.fstat

    def root_fstat(descriptor):
        value = actual_fstat(descriptor)
        return SimpleNamespace(
            st_mode=value.st_mode, st_uid=0, st_size=value.st_size,
        )

    monkeypatch.setattr("app.calling_contract.os.fstat", root_fstat)


def principal():
    return CallPrincipal(tenant_id="tenant-test", subject="subject-appolon",
                         employee_id="employee-appolon", campaign_id="TEST_SYN",
                         business_unit="business-test", extension="6901")


def policy(path: Path):
    now = datetime.now(UTC)
    grant = CallingGrant(
        authorization_reference="CHG-APPOLON-TEST-0001", principal=principal(),
        destination="internal:TEST_ECHO", caller_id="+12025550123", lead_id=17,
        not_before=now-timedelta(minutes=1), expires_at=now+timedelta(minutes=10),
        source_sha=SOURCE_SHA,
    )
    path.write_text(grant.model_dump_json())
    path.chmod(0o600)
    return grant


def command(grant):
    return CommandExecutionRequest(
        command_id="11111111-1111-5111-8111-111111111111",
        command_type=ORIGINATE, command_version="1.0", target="vicidial-restricted",
        tenant_id="tenant-test", requested_by="subject-appolon",
        correlation_id="correlation-appolon-0001", idempotency_key="originate-appolon-0001",
        capability=CAPABILITY, authenticated_client_id=CLIENT_ID,
        payload={
            "actor": principal().model_dump(mode="json"),
            "originate": {
                "employee_id": "employee-appolon", "campaign": "TEST_SYN",
                "business_unit": "business-test", "destination": "internal:TEST_ECHO",
                "destination_class": "internal_test", "destination_country": "ZZ",
                "destination_timezone": "UTC", "caller_id": "+12025550123",
                "lead_model": "crm.lead", "lead_id": 17, "recording_requested": False,
            },
            "authorization_reference": grant.authorization_reference,
            "policy_sha256": grant.digest(),
        },
    )


def hangup_command(grant):
    original = command(grant)
    return CommandExecutionRequest(
        command_id="22222222-2222-5222-8222-222222222222",
        command_type=HANGUP, command_version="1.0", target="vicidial-restricted",
        tenant_id=original.tenant_id, requested_by=original.requested_by,
        correlation_id=original.correlation_id, idempotency_key="hangup-appolon-0001",
        capability=CAPABILITY, authenticated_client_id=CLIENT_ID,
        payload={
            **original.payload, "origin_operation_id": original.command_id,
            "call_id": "codestra-unique-1", "reason": "Agent hangup",
        },
    )


def environment(tmp_path):
    secret = tmp_path / "hmac"
    secret.write_bytes(SECRET)
    secret.chmod(0o600)
    grant = policy(tmp_path / "policy.json")
    return grant, {
        "CODESTRA_INTERNAL_CALL_POLICY_FILE": str(tmp_path / "policy.json"),
        "VICIDIAL_INTERNAL_CALL_BASE_URL": "https://server-b.internal",
        "VICIDIAL_INTERNAL_CALL_EXPECTED_HOST": "server-b.internal",
        "VICIDIAL_INTERNAL_CALL_HMAC_FILE": str(secret),
        "VICIDIAL_INTERNAL_CALL_SERVICE_IDENTITY": "codestra-middleware",
    }


def test_downstream_contract_lock_matches_adapter_routes():
    lock = json.loads(Path("config/vicidial-internal-call-contract.lock.json").read_text())
    assert lock["tested_sha"] == "8bb08bb72f121c4304f72604765afb342234269c"
    assert lock["protected_release"] is True
    assert lock["routes"] == {
        "originate": VicidialInternalCallAdapter.ORIGINATE_PATH,
        "readback": "/v1/calls/internal/{operation_id}",
        "hangup": "/v1/calls/internal/{operation_id}/hangup",
    }


@pytest.mark.asyncio
async def test_exact_hmac_v2_backend_path_and_body(tmp_path):
    grant, env = environment(tmp_path)
    captured = []

    async def endpoint(request):
        raw = await request.aread()
        captured.append((request, raw))
        return httpx.Response(200, request=request, json={
            "status": "accepted", "operation_id": command(grant).command_id,
            "asterisk_uniqueid": "codestra-unique-1", "created_at": "2026-09-05T19:00:00Z",
            "duplicate": False,
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
    result = await adapter.execute(command(grant))
    assert result.status == "accepted"
    request, body = captured[0]
    timestamp = request.headers["X-Request-Timestamp"]
    nonce = request.headers["X-Request-Nonce"]
    canonical = "\n".join((
        "v2", "POST", "/v1/calls/internal/originate", "codestra-middleware",
        "telephony:internal-call", timestamp, nonce, command(grant).command_id,
        hashlib.sha256(body).hexdigest(),
    ))
    assert hmac.compare_digest(
        request.headers["X-Request-Signature"],
        hmac.new(SECRET, canonical.encode(), hashlib.sha256).hexdigest(),
    )
    assert request.url.path == "/v1/calls/internal/originate"
    assert json.loads(body)["destination"] == "internal:TEST_ECHO"
    await client.aclose()


@pytest.mark.asyncio
async def test_timeout_is_unknown_and_never_self_retries(tmp_path):
    grant, env = environment(tmp_path)
    attempts = 0
    async def endpoint(request):
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("synthetic", request=request)
    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
    with pytest.raises(VicidialInternalCallUnknown):
        await adapter.execute(command(grant))
    assert attempts == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_policy_change_after_enqueue_fails_before_network(tmp_path):
    grant, env = environment(tmp_path)
    called = False
    async def endpoint(request):
        nonlocal called
        called = True
        return httpx.Response(500, request=request)
    changed = grant.model_copy(update={"lead_id": 18})
    Path(env["CODESTRA_INTERNAL_CALL_POLICY_FILE"]).write_text(changed.model_dump_json())
    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
    with pytest.raises(VicidialInternalCallPreDispatchRejected, match="changed"):
        await adapter.execute(command(grant))
    assert called is False
    await client.aclose()


@pytest.mark.asyncio
async def test_authenticated_server_policy_denial_is_conclusive_no_effect(tmp_path):
    grant, env = environment(tmp_path)
    sends = 0

    async def endpoint(request):
        nonlocal sends
        sends += 1
        return httpx.Response(
            403, request=request,
            json={"detail": "internal call authorization expired"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(
        SimpleNamespace(source_sha=SOURCE_SHA), env, client,
    )
    with pytest.raises(
        VicidialInternalCallPreDispatchRejected,
        match="conclusively rejected",
    ):
        await adapter.execute(command(grant))
    assert sends == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_unrecognized_forbidden_response_is_not_conclusive(tmp_path):
    grant, env = environment(tmp_path)

    async def endpoint(request):
        return httpx.Response(403, request=request, json={"detail": "other denial"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(
        SimpleNamespace(source_sha=SOURCE_SHA), env, client,
    )
    with pytest.raises(VicidialInternalCallError) as caught:
        await adapter.execute(command(grant))
    assert not isinstance(caught.value, VicidialInternalCallPreDispatchRejected)
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_failure", ["deleted", "unreadable", "malformed"])
async def test_policy_loading_failure_is_conclusive_no_send(
    tmp_path, monkeypatch, policy_failure,
):
    grant, env = environment(tmp_path)
    policy_path = Path(env["CODESTRA_INTERNAL_CALL_POLICY_FILE"])
    if policy_failure == "deleted":
        policy_path.unlink()
    elif policy_failure == "unreadable":
        monkeypatch.setattr(
            "app.calling_contract.os.open",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                PermissionError("synthetic unreadable policy")
            ),
        )
    else:
        policy_path.write_text("{not-json")
    sends = 0

    async def endpoint(request):
        nonlocal sends
        sends += 1
        return httpx.Response(500, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(
        SimpleNamespace(source_sha=SOURCE_SHA), env, client,
    )
    with pytest.raises(
        VicidialInternalCallPreDispatchRejected,
        match="policy is unavailable or invalid",
    ):
        await adapter.execute(command(grant))
    assert sends == 0
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["origin", "tls", "headers"])
async def test_request_preparation_failure_is_conclusive_no_send(
    tmp_path, monkeypatch, failure,
):
    grant, env = environment(tmp_path)
    sends = 0

    async def endpoint(request):
        nonlocal sends
        sends += 1
        return httpx.Response(200, request=request, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(
        SimpleNamespace(source_sha=SOURCE_SHA), env, client,
    )
    if failure == "origin":
        env.pop("VICIDIAL_INTERNAL_CALL_BASE_URL")
    elif failure == "tls":
        monkeypatch.setattr(
            adapter, "_client_or_create",
            lambda: (_ for _ in ()).throw(ssl.SSLError("synthetic TLS setup")),
        )
    else:
        monkeypatch.setattr(
            adapter, "_headers",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                UnicodeError("synthetic header encoding")
            ),
        )
    with pytest.raises(
        VicidialInternalCallPreDispatchRejected,
        match="request preparation failed",
    ):
        await adapter.execute(command(grant))
    assert sends == 0
    await client.aclose()


@pytest.mark.parametrize("field,value", [
    ("extension", "6101"), ("campaign_id", "PRODUCTION"),
])
def test_wrong_identity_is_rejected(field, value, tmp_path):
    grant, env = environment(tmp_path)
    request = command(grant)
    actor = request.payload["actor"] | {field: value}
    request = CommandExecutionRequest(**{**request.__dict__, "payload": request.payload | {"actor": actor}})
    adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env,
                                          httpx.AsyncClient(transport=httpx.MockTransport(lambda r: None)))
    with pytest.raises(VicidialInternalCallError):
        adapter._originate(request)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    "requested_by", "tenant_id", "actor_extension", "destination",
])
async def test_hangup_binding_mismatch_fails_before_network(change, tmp_path):
    grant, env = environment(tmp_path)
    request = hangup_command(grant)
    values = request.__dict__.copy()
    if change == "requested_by":
        values["requested_by"] = "subject-other"
    elif change == "tenant_id":
        values["tenant_id"] = "tenant-other"
    elif change == "actor_extension":
        values["payload"] = request.payload | {
            "actor": request.payload["actor"] | {"extension": "6101"},
        }
    else:
        values["payload"] = request.payload | {
            "originate": request.payload["originate"] | {"destination": "internal:OTHER"},
        }
    request = CommandExecutionRequest(**values)
    called = False

    async def endpoint(http_request):
        nonlocal called
        called = True
        return httpx.Response(200, request=http_request, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(endpoint))
    adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
    with pytest.raises(VicidialInternalCallError, match="hangup"):
        await adapter.execute(request)
    assert called is False
    await client.aclose()


def lifecycle_evidence(grant):
    request = command(grant)
    return {
        "operation_id": request.command_id, "correlation_id": request.correlation_id,
        "dispatch_state": "accepted", "asterisk_uniqueid": "codestra-unique-1",
        "linkedid": "codestra-linked-1", "call_id": "gateway-call-1",
        "call_state": "completed", "terminal": True,
        "created_at": "2026-09-05T19:00:00Z", "answered_at": "2026-09-05T19:00:01Z",
        "ended_at": "2026-09-05T19:00:03Z", "duration_seconds": 3,
        "talk_duration_seconds": 2, "evidence": {"call_state": "completed"},
        "tenant_id": request.tenant_id, "subject": principal().subject,
        "employee_id": principal().employee_id, "username": "appolon",
        "extension": "6901", "campaign": "TEST_SYN",
        "authorization_reference": grant.authorization_reference,
        "internal_only": True, "external_dialing": False, "recording": False,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["redirect", "invalid_length", "oversized", "missing_uniqueid"])
async def test_unverifiable_originate_response_is_unknown_without_retry(tmp_path, failure):
    grant, env = environment(tmp_path)
    attempts = []

    async def endpoint(request):
        attempts.append(request)
        response = {"operation_id": command(grant).command_id, "status": "accepted",
                    "asterisk_uniqueid": "codestra-unique-1"}
        headers = {}
        if failure == "invalid_length":
            headers["content-length"] = "not-a-number"
        elif failure == "oversized":
            headers["content-length"] = "65537"
        elif failure == "missing_uniqueid":
            response.pop("asterisk_uniqueid")
        return httpx.Response(302 if failure == "redirect" else 200,
                              json=response, headers=headers, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(endpoint)) as client:
        adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
        with pytest.raises(VicidialInternalCallUnknown):
            await adapter.execute(command(grant))
    assert len(attempts) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("operation_id", "other-operation"), ("correlation_id", "other-correlation"),
    ("asterisk_uniqueid", "other-call"), ("tenant_id", "other-tenant"),
    ("subject", "other-subject"), ("employee_id", "other-employee"),
    ("authorization_reference", "CHG-OTHER-AUTHORIZATION"),
    ("extension", "6101"), ("campaign", "OTHER"),
    ("internal_only", False), ("external_dialing", True), ("hangup", "success"),
])
async def test_hangup_response_must_bind_original_call(tmp_path, field, value):
    grant, env = environment(tmp_path)
    attempts = []

    async def endpoint(request):
        attempts.append(request)
        result = lifecycle_evidence(grant) | {"hangup": "requested", field: value}
        return httpx.Response(200, json=result, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(endpoint)) as client:
        adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
        with pytest.raises(VicidialInternalCallUnknown, match="acknowledgement"):
            await adapter.execute(hangup_command(grant))
    assert len(attempts) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("hangup,status", [
    ("requested", "accepted"), ("already_terminal", "accepted"),
    ("dispatch_unknown", "dispatch_unknown"),
])
async def test_bound_hangup_preserves_unknown_outcome(tmp_path, hangup, status):
    grant, env = environment(tmp_path)

    async def endpoint(request):
        return httpx.Response(200, json=lifecycle_evidence(grant) | {"hangup": hangup}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(endpoint)) as client:
        result = await VicidialInternalCallAdapter(
            SimpleNamespace(source_sha=SOURCE_SHA), env, client,
        ).execute(hangup_command(grant))
    assert result.status == status
    assert result.provider_operation_id == "codestra-unique-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [
    ("authorization_reference", "CHG-OTHER-AUTHORIZATION"),
    ("asterisk_uniqueid", "other-call"),
])
async def test_readback_requires_original_authorization_and_call(tmp_path, field, value):
    grant, env = environment(tmp_path)

    async def endpoint(request):
        return httpx.Response(200, json=lifecycle_evidence(grant) | {field: value}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(endpoint)) as client:
        adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
        with pytest.raises(VicidialInternalCallError, match="binding mismatch"):
            await adapter.readback(hangup_command(grant))


@pytest.mark.asyncio
async def test_matching_terminal_readback_succeeds(tmp_path):
    grant, env = environment(tmp_path)

    async def endpoint(request):
        return httpx.Response(200, json=lifecycle_evidence(grant), request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(endpoint)) as client:
        result = await VicidialInternalCallAdapter(
            SimpleNamespace(source_sha=SOURCE_SHA), env, client,
        ).readback(hangup_command(grant))
    assert result.status == "matched"
    assert result.readback_evidence["authorization_reference"] == grant.authorization_reference


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['originate', 'hangup', 'denial'])
@pytest.mark.parametrize('malformed', [[], {}])
async def test_unhashable_response_fields_remain_classified(tmp_path, kind, malformed):
    grant, env = environment(tmp_path)
    attempts = []

    async def endpoint(request):
        attempts.append(request)
        if kind == 'denial':
            return httpx.Response(403, json={'detail': malformed}, request=request)
        result = lifecycle_evidence(grant) | {'status': 'accepted', 'hangup': 'requested'}
        result['hangup' if kind == 'hangup' else 'status'] = malformed
        return httpx.Response(200, json=result, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(endpoint)) as client:
        adapter = VicidialInternalCallAdapter(SimpleNamespace(source_sha=SOURCE_SHA), env, client)
        expected = VicidialInternalCallError if kind == 'denial' else VicidialInternalCallUnknown
        with pytest.raises(expected):
            await adapter.execute(hangup_command(grant) if kind == 'hangup' else command(grant))
    assert len(attempts) == 1
