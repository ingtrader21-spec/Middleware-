"""Real-database regressions for the Mission 3 agent provisioning saga.

These tests run only when a disposable PostgreSQL is available (see
tests/integration/conftest.py and scripts/integration_ci.sh, the same
convention tests/test_ai_job_platform.py uses) - they are the tests
required-ci.yml actually exercises against the real database after
`alembic upgrade head`.
"""

from __future__ import annotations

import os
import time
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1 import agent_provisioning
from app.core.config import settings
from app.telnexa_sender_profile_adapter import TelnexaSenderProfileAdapterError

ISSUER = "https://identity.example.invalid/realms/agent-provisioning-test"
AUDIENCE = "middleware-api-test"

pytestmark = pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)


@pytest.fixture
def authority(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Keys:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=private.public_key())

    monkeypatch.setattr(jwt, "PyJWKClient", Keys)
    for key, value in {
        "keycloak_issuer": ISSUER,
        "keycloak_audience": AUDIENCE,
        "keycloak_jwks_url": ISSUER + "/certs",
        "agent_provisioning_authorized_parties": "provisioning-service",
        "agent_provisioning_policy_revision": "7",
        "live_identity_provisioning_enabled": False,
        "live_writes_enabled": False,
    }.items():
        monkeypatch.setattr(settings, key, value)

    def token(
        scope="identity.request integration.configure tenant.provision",
        subject="provisioning-service-subject",
        azp="provisioning-service",
        tenant_ids=("COD",),
        **overrides,
    ):
        current = int(time.time())
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "azp": azp,
            "sub": subject, "iat": current, "exp": current + 300,
            "jti": str(uuid4()), "scope": scope, "tenant_ids": list(tenant_ids),
            **overrides,
        }
        return jwt.encode(claims, private, algorithm="RS256")

    return token


@pytest_asyncio.fixture
async def client():
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def isolated_session():
        async with session_factory() as session:
            yield session

    app = FastAPI()
    app.include_router(agent_provisioning.router)
    app.dependency_overrides[agent_provisioning.get_session] = isolated_session

    async with engine.begin() as connection:
        await connection.execute(text("DELETE FROM agent_provisioning_audit"))
        await connection.execute(text("DELETE FROM agent_provisioning_step"))
        await connection.execute(text("DELETE FROM agent_provisioning_request"))
        await connection.execute(
            text("DELETE FROM idempotency_record WHERE scope = 'agent_provisioning'")
        )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()
    await engine.dispose()


def _body(**overrides) -> dict:
    body = {
        "request_id": f"req_{uuid4().hex[:12]}",
        "tenant_id": "COD",
        "employee_id": "COD.2026.00016",
        "identity": {"email": "appolon1908@gmail.com", "first_name": "A", "last_name": "P"},
        "campaigns": [{"campaign_id": "TEST_SYN", "role": "supervisor"}],
        "channels": {"odoo": True, "phone": True, "webrtc": True, "sms": False, "email": False},
        "telephony": {
            "existing_extension": "6101", "incoming_allowed": True,
            "outgoing_allowed": True, "max_webrtc_sessions": 1,
        },
    }
    body.update(overrides)
    return body


def _headers(token: str, *, idempotency_key: str | None = None, policy_revision: str = "7") -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": idempotency_key or uuid4().hex,
        "X-Correlation-ID": str(uuid4()),
        "X-Policy-Revision": policy_revision,
    }


@pytest.mark.asyncio
async def test_missing_bearer_token_is_rejected_before_any_db_write(client, authority):
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(),
        headers={"Idempotency-Key": uuid4().hex, "X-Policy-Revision": "7"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_wrong_scope_is_denied(client, authority):
    token = authority(scope="some.other.scope")
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(),
        headers=_headers(token),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_tenant_claim_mismatch_is_denied(client, authority):
    token = authority(tenant_ids=("OTHER_TENANT",))
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(tenant_id="COD"),
        headers=_headers(token),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_stale_policy_revision_is_rejected(client, authority):
    token = authority()
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(),
        headers=_headers(token, policy_revision="stale-revision"),
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_kill_switch_closed_lands_in_partial_with_honest_step_records(client, authority):
    """The default posture (both kill switches closed) must never claim a
    channel is live. Odoo needs every step visible, not just the final
    state - this is the "display every step of its progress" requirement.
    """
    token = authority()
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(),
        headers=_headers(token),
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["state"] == "PARTIAL"
    assert payload["keycloak_subject"] is None

    steps_by_operation = {step["operation"]: step for step in payload["steps"]}
    assert steps_by_operation["create_user"]["state"] == "skipped"
    assert steps_by_operation["create_user"]["error_code"] == "KILL_SWITCH_CLOSED"
    assert steps_by_operation["provision_phone"]["system"] == "vicidial"
    assert steps_by_operation["provision_phone"]["state"] == "skipped"
    assert steps_by_operation["provision_phone"]["error_code"] == "KILL_SWITCH_CLOSED"
    assert steps_by_operation["provision_webrtc"]["state"] == "skipped"
    assert steps_by_operation["provision_webrtc"]["error_code"] == "KILL_SWITCH_CLOSED"
    assert "provision_sms" not in steps_by_operation
    assert "provision_email" not in steps_by_operation

@pytest.mark.asyncio
async def test_optional_entitlements_are_echoed_and_unsupported_capabilities_are_gated(
    client, authority,
):
    """Approved optional intent must survive the canonical command boundary.

    Middleware has no voicemail/recording/monitoring adapters yet, so those
    requested capabilities are durable blocked steps rather than an implicit
    success.  A disabled agent desktop must also suppress Keycloak role
    assignment even when the request contains a campaign.
    """
    token = authority()
    entitlements = {
        "agent_desktop": False,
        "voicemail": True,
        "recording_access": True,
        "monitoring_access": True,
    }
    body = _body(
        channels={"odoo": True, "phone": False, "webrtc": False, "sms": False, "email": False},
        entitlements=entitlements,
    )
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["entitlements"] == entitlements
    assert payload["state"] == "PARTIAL"

    steps_by_operation = {step["operation"]: step for step in payload["steps"]}
    assert steps_by_operation["assign_approved_roles"]["state"] == "skipped"
    assert steps_by_operation["assign_approved_roles"]["error_code"] == "ENTITLEMENT_DISABLED"
    for operation in ("provision_voicemail", "grant_recording_access", "grant_monitoring_access"):
        assert steps_by_operation[operation]["system"] == "odoo"
        assert steps_by_operation[operation]["state"] == "blocked"
        assert steps_by_operation[operation]["error_code"] == "CAPABILITY_ADAPTER_NOT_CONFIGURED"


async def _internal_id_for(request_id: str) -> str:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text("SELECT id FROM agent_provisioning_request WHERE request_id = :rid"),
                {"rid": request_id},
            )
            return str(result.scalar_one())
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_get_returns_the_same_saga_and_steps_as_create(client, authority):
    token = authority()
    body = _body()
    create_response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert create_response.status_code == 202
    request_pk = await _internal_id_for(body["request_id"])

    get_response = await client.get(
        f"/platform/v1/agent-provisioning/requests/{request_pk}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_response.status_code == 200
    assert get_response.json() == create_response.json()


@pytest.mark.asyncio
async def test_idempotency_key_replay_returns_the_identical_response(client, authority):
    token = authority()
    body = _body()
    key = uuid4().hex
    first = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token, idempotency_key=key),
    )
    second = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token, idempotency_key=key),
    )
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()


@pytest.mark.asyncio
async def test_idempotency_key_reused_with_a_different_body_is_rejected(client, authority):
    token = authority()
    key = uuid4().hex
    first = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(),
        headers=_headers(token, idempotency_key=key),
    )
    assert first.status_code == 202
    second = await client.post(
        "/platform/v1/agent-provisioning/requests",
        json=_body(request_id=f"req_{uuid4().hex[:12]}"),
        headers=_headers(token, idempotency_key=key),
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_duplicate_request_id_is_rejected(client, authority):
    token = authority()
    request_id = f"req_{uuid4().hex[:12]}"
    first = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(request_id=request_id),
        headers=_headers(token),
    )
    assert first.status_code == 202
    second = await client.post(
        "/platform/v1/agent-provisioning/requests", json=_body(request_id=request_id),
        headers=_headers(token),
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_suspend_reactivate_and_revoke_transition_lifecycle(client, authority):
    token = authority()
    body = _body()
    create_response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert create_response.status_code == 202
    request_pk = await _internal_id_for(body["request_id"])

    suspend_response = await client.post(
        f"/platform/v1/agent-provisioning/requests/{request_pk}/suspend",
        json={"reason": "security review"}, headers=_headers(token),
    )
    assert suspend_response.status_code == 200
    assert suspend_response.json()["state"] == "SUSPENDED"

    reactivate_response = await client.post(
        f"/platform/v1/agent-provisioning/requests/{request_pk}/reactivate",
        json={"reason": "review cleared"}, headers=_headers(token),
    )
    assert reactivate_response.status_code == 200
    assert reactivate_response.json()["state"] == "PARTIAL"

    revoke_response = await client.post(
        f"/platform/v1/agent-provisioning/requests/{request_pk}/revoke",
        json={"reason": "offboarding"}, headers=_headers(token),
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["state"] == "REVOKED"

    blocked_response = await client.post(
        f"/platform/v1/agent-provisioning/requests/{request_pk}/reconcile",
        json={"reason": "retry after revoke"}, headers=_headers(token),
    )
    assert blocked_response.status_code == 409


@pytest.mark.asyncio
async def test_real_identity_failure_emits_provision_failed_outbox_event(
    client, authority, monkeypatch,
):
    """Mission 4E: n8n reacts only to a real outbox event, never decides
    identity/provisioning state itself. Forcing a genuine adapter error
    (not a kill-switch gate) must land the saga FAILED and enqueue exactly
    one platform.user.provision_failed row for the existing outbox worker
    to deliver - this test does not touch n8n at all, only the event it
    would eventually receive.
    """
    from app.adapters.keycloak.lifecycle_client import (
        KeycloakLifecycleAdapter,
        KeycloakLifecycleError,
    )

    async def _boom(self, email):
        raise KeycloakLifecycleError("synthetic adapter failure")

    monkeypatch.setattr(settings, "live_identity_provisioning_enabled", True)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "query_user_by_email", _boom)

    token = authority()
    body = _body(channels={"odoo": True, "phone": False, "webrtc": False, "sms": False, "email": False})
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert response.status_code == 202
    assert response.json()["state"] == "FAILED"

    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT topic, status, payload FROM outbox_event "
                    "WHERE topic = 'platform.user.provision_failed' "
                    "AND payload->>'request_id' = :rid"
                ),
                {"rid": body["request_id"]},
            )
            rows = result.all()
    finally:
        await engine.dispose()
    assert len(rows) == 1
    assert rows[0].status == "pending"
    assert rows[0].payload["state"] == "FAILED"


@pytest.mark.asyncio
async def test_phone_and_webrtc_channels_reach_effective_when_adapters_succeed(
    client, authority, monkeypatch,
):
    """Mission 6: with both the identity and telephony kill switches open
    and every adapter call succeeding, the saga must actually report
    EFFECTIVE for phone/webrtc - not remain PARTIAL forever the way the
    pre-Mission-6 stub always did (CHANNEL_ADAPTER_NOT_IMPLEMENTED)."""
    from app.adapters.keycloak.lifecycle_client import KeycloakLifecycleAdapter
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class _KeycloakRecord:
        keycloak_subject: str
        enabled: bool = True

    async def _query_user(self, email):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _create_user(self, email, first_name, last_name):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _assign_roles(self, subject, roles):
        return None

    monkeypatch.setattr(KeycloakLifecycleAdapter, "query_user_by_email", _query_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "create_user", _create_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "assign_approved_roles", _assign_roles)

    calls: list[tuple[str, dict]] = []

    class _FakeVicidialClient:
        def __init__(self, _settings):
            pass

        def sync_agent(self, payload):
            calls.append(("sync_agent", payload))
            return {"actual": {"user_id": payload["agent"]["user_id"], "active": False}}

        def reserve_extension(self, payload):
            calls.append(("reserve_extension", payload))
            return {"actual": {"extension": "6203", "active": True}}

        def adopt_extension(self, payload):
            calls.append(("adopt_extension", payload))
            return {"actual": {"extension": payload["adoption"]["extension"], "active": True}}

        def provision_webrtc(self, payload):
            calls.append(("provision_webrtc", payload))
            return {"extension": "6203", "credential": "synthetic", "expires_at": "later"}

        def close(self):
            pass

    monkeypatch.setattr(settings, "live_identity_provisioning_enabled", True)
    monkeypatch.setattr(settings, "vicidial_write_enabled", True)
    monkeypatch.setattr(settings, "live_writes_enabled", True)
    monkeypatch.setattr(agent_provisioning, "VicidialMtlsClient", _FakeVicidialClient)

    token = authority()
    body = _body(
        channels={"odoo": True, "phone": True, "webrtc": True, "sms": False, "email": False},
        campaigns=[{
            "campaign_id": "TEST_SYN", "role": "supervisor",
            "vicidial_user_id": "COD0016", "vicidial_user_group": "COD_TEST_SDR",
            "vicidial_supervisor_subject": "supervisor-cod",
        }],
        telephony={
            "existing_extension": None, "extension_pool": "moneybee",
            "incoming_allowed": True, "outgoing_allowed": True, "max_webrtc_sessions": 1,
        },
    )
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["state"] == "EFFECTIVE", payload["steps"]

    steps_by_operation = {step["operation"]: step for step in payload["steps"]}
    assert steps_by_operation["reserve_extension"]["state"] == "succeeded"
    assert steps_by_operation["reserve_extension"]["external_reference"] == "6203"
    assert steps_by_operation["provision_webrtc"]["state"] == "succeeded"
    assert [name for name, _ in calls] == ["sync_agent", "reserve_extension", "provision_webrtc"]


@pytest.mark.asyncio
async def test_phone_channel_blocked_when_vicidial_identifiers_missing(
    client, authority, monkeypatch,
):
    """Requesting phone/webrtc without the VICIdial-specific campaign
    fields must fail closed with a clear, distinct error code - not crash,
    and not silently proceed with a guessed identifier."""
    monkeypatch.setattr(settings, "vicidial_write_enabled", True)
    monkeypatch.setattr(settings, "live_writes_enabled", True)

    token = authority()
    body = _body(
        channels={"odoo": True, "phone": True, "webrtc": False, "sms": False, "email": False},
        campaigns=[{"campaign_id": "TEST_SYN", "role": "supervisor"}],
    )
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["state"] == "PARTIAL"
    steps_by_operation = {step["operation"]: step for step in payload["steps"]}
    assert steps_by_operation["provision_phone"]["error_code"] == "CHANNEL_CONFIGURATION_INCOMPLETE"


@pytest.mark.asyncio
async def test_reconcile_resumes_past_a_partial_webrtc_failure_without_redoing_prior_steps(
    client, authority, monkeypatch,
):
    """Root cause of the original reconciliation gap: Vicidialer-Codestra's
    per-resource optimistic-concurrency claim ("agent:<id>"/
    "extension:<id>"/"webrtc:<id>") only ever accepts expected_version=0
    once - a second call against an already-advanced resource key raises
    StaleResourceVersion. The fix is to never re-issue a call this saga's
    own AgentProvisioningStep history already shows as "succeeded" for
    this exact request. This test forces sync_agent and reserve_extension
    to succeed, provision_webrtc to fail on the first attempt (a
    transient VicidialMtlsError - the kind that leaves Vicidialer's
    webrtc:<id> resource key untouched), then reconciles and asserts:
    sync_agent/reserve_extension are NOT called a second time (proving no
    double-allocation and no StaleResourceVersion retry of an
    already-succeeded step), provision_webrtc IS retried and this time
    succeeds, and the saga reaches EFFECTIVE.
    """
    from app.adapters.keycloak.lifecycle_client import KeycloakLifecycleAdapter
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class _KeycloakRecord:
        keycloak_subject: str
        enabled: bool = True

    async def _query_user(self, email):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _create_user(self, email, first_name, last_name):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _assign_roles(self, subject, roles):
        return None

    monkeypatch.setattr(KeycloakLifecycleAdapter, "query_user_by_email", _query_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "create_user", _create_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "assign_approved_roles", _assign_roles)

    from app.adapters.vicidial.mtls_client import VicidialMtlsError

    calls: list[str] = []
    webrtc_should_fail = {"value": True}

    class _FlakyVicidialClient:
        def __init__(self, _settings):
            pass

        def sync_agent(self, payload):
            calls.append("sync_agent")
            return {"actual": {"user_id": payload["agent"]["user_id"], "active": False}}

        def reserve_extension(self, payload):
            calls.append("reserve_extension")
            return {"actual": {"extension": "6204", "active": True}}

        def adopt_extension(self, payload):
            calls.append("adopt_extension")
            return {"actual": {"extension": payload["adoption"]["extension"], "active": True}}

        def provision_webrtc(self, payload):
            calls.append("provision_webrtc")
            if webrtc_should_fail["value"]:
                raise VicidialMtlsError("synthetic transient failure")
            return {"extension": "6204", "credential": "synthetic", "expires_at": "later"}

        def close(self):
            pass

    monkeypatch.setattr(settings, "live_identity_provisioning_enabled", True)
    monkeypatch.setattr(settings, "vicidial_write_enabled", True)
    monkeypatch.setattr(settings, "live_writes_enabled", True)
    monkeypatch.setattr(agent_provisioning, "VicidialMtlsClient", _FlakyVicidialClient)

    token = authority()
    body = _body(
        channels={"odoo": True, "phone": True, "webrtc": True, "sms": False, "email": False},
        campaigns=[{
            "campaign_id": "TEST_SYN", "role": "supervisor",
            "vicidial_user_id": "COD0017", "vicidial_user_group": "COD_TEST_SDR",
            "vicidial_supervisor_subject": "supervisor-cod",
        }],
        telephony={
            "existing_extension": None, "extension_pool": "moneybee",
            "incoming_allowed": True, "outgoing_allowed": True, "max_webrtc_sessions": 1,
        },
    )
    create_response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert create_response.status_code == 202
    first = create_response.json()
    assert first["state"] == "FAILED"
    assert calls == ["sync_agent", "reserve_extension", "provision_webrtc"]
    steps_by_operation = {step["operation"]: step for step in first["steps"]}
    assert steps_by_operation["sync_agent"]["state"] == "succeeded"
    assert steps_by_operation["reserve_extension"]["state"] == "succeeded"
    assert steps_by_operation["reserve_extension"]["external_reference"] == "6204"
    assert steps_by_operation["provision_webrtc"]["state"] == "failed"

    webrtc_should_fail["value"] = False
    calls.clear()
    request_pk = await _internal_id_for(body["request_id"])
    reconcile_response = await client.post(
        f"/platform/v1/agent-provisioning/requests/{request_pk}/reconcile",
        json={"reason": "retry after transient webrtc failure"}, headers=_headers(token),
    )
    assert reconcile_response.status_code == 200
    second = reconcile_response.json()

    # The whole point of the fix: sync_agent/reserve_extension must NOT be
    # called again on reconcile - only the step that actually failed.
    assert calls == ["provision_webrtc"]
    assert second["state"] == "EFFECTIVE", second["steps"]
    steps_by_operation = {step["operation"]: step for step in second["steps"]}
    assert steps_by_operation["provision_webrtc"]["state"] == "succeeded"

    # No double allocation: still exactly one succeeded
    # reserve_extension/adopt_extension step across both attempts.
    extension_steps = [
        step for step in second["steps"]
        if step["operation"] in ("reserve_extension", "adopt_extension")
        and step["state"] == "succeeded"
    ]
    assert len(extension_steps) == 1


@pytest.mark.asyncio
async def test_email_and_sms_channels_reach_effective_when_adapters_succeed(
    client, authority, monkeypatch,
):
    """Milestones 8/9: with both write-enable switches open and the Klyrow/
    Telnexa adapters succeeding, the saga must report EFFECTIVE for email/sms
    - not the pre-Mission-8/9 CHANNEL_ADAPTER_NOT_IMPLEMENTED stub."""
    from app.adapters.keycloak.lifecycle_client import KeycloakLifecycleAdapter
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class _KeycloakRecord:
        keycloak_subject: str
        enabled: bool = True

    async def _query_user(self, email):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _create_user(self, email, first_name, last_name):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _assign_roles(self, subject, roles):
        return None

    monkeypatch.setattr(KeycloakLifecycleAdapter, "query_user_by_email", _query_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "create_user", _create_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "assign_approved_roles", _assign_roles)

    calls: list[tuple[str, dict]] = []

    class _FakeKlyrowAdapter:
        def __init__(self, _settings):
            pass

        async def provision_sender_identity(self, **kwargs):
            calls.append(("provision_sender_identity", kwargs))
            return {"id": "sender-identity-1", "status": "ACTIVE"}

    class _FakeTelnexaAdapter:
        def __init__(self, _settings):
            pass

        async def provision_sender_profile(self, **kwargs):
            calls.append(("provision_sender_profile", kwargs))
            return {"id": "sender-profile-1", "status": "requested"}

    monkeypatch.setattr(settings, "live_identity_provisioning_enabled", True)
    monkeypatch.setattr(settings, "klyrow_write_enabled", True)
    monkeypatch.setattr(settings, "telnexa_write_enabled", True)
    monkeypatch.setattr(settings, "live_writes_enabled", True)
    monkeypatch.setattr(settings, "klyrow_default_domain_claim_id", "claim-cod")
    monkeypatch.setattr(agent_provisioning, "KlyrowSenderIdentityAdapter", _FakeKlyrowAdapter)
    monkeypatch.setattr(agent_provisioning, "TelnexaSenderProfileAdapter", _FakeTelnexaAdapter)

    token = authority()
    body = _body(
        channels={"odoo": True, "phone": False, "webrtc": False, "sms": True, "email": True},
        campaigns=[{
            "campaign_id": "TEST_SYN", "role": "supervisor",
            "campaign_email": "maria.transport@codestra.agency",
            "sms_sender": "CODESTRA",
        }],
    )
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["state"] == "EFFECTIVE", payload["steps"]

    steps_by_operation = {step["operation"]: step for step in payload["steps"]}
    assert steps_by_operation["provision_sender_identity"]["state"] == "succeeded"
    assert steps_by_operation["provision_sender_identity"]["external_reference"] == "sender-identity-1"
    assert steps_by_operation["provision_sender_profile"]["state"] == "succeeded"
    assert steps_by_operation["provision_sender_profile"]["external_reference"] == "sender-profile-1"
    assert {name for name, _ in calls} == {"provision_sender_identity", "provision_sender_profile"}


@pytest.mark.asyncio
async def test_email_channel_blocked_when_campaign_email_missing(
    client, authority, monkeypatch,
):
    monkeypatch.setattr(settings, "klyrow_write_enabled", True)
    monkeypatch.setattr(settings, "live_writes_enabled", True)
    monkeypatch.setattr(settings, "klyrow_default_domain_claim_id", "claim-cod")

    token = authority()
    body = _body(
        channels={"odoo": True, "phone": False, "webrtc": False, "sms": False, "email": True},
        campaigns=[{"campaign_id": "TEST_SYN", "role": "supervisor"}],
    )
    response = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["state"] != "EFFECTIVE", payload["steps"]
    steps_by_operation = {step["operation"]: step for step in payload["steps"]}
    assert steps_by_operation["provision_sender_identity"]["state"] == "blocked"
    assert steps_by_operation["provision_sender_identity"]["error_code"] == "CHANNEL_CONFIGURATION_INCOMPLETE"


@pytest.mark.asyncio
async def test_sms_reconcile_does_not_replay_a_succeeded_sender_profile_step(
    client, authority, monkeypatch,
):
    """Retry-safety mirror of the phone/webrtc reconcile fix: a /reconcile
    call after a succeeded provision_sender_profile step must not call the
    Telnexa adapter again (Telnexa's real POST /api/v1/senders has no
    idempotency key of its own, so double-invoking would double-create)."""
    from app.adapters.keycloak.lifecycle_client import KeycloakLifecycleAdapter
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class _KeycloakRecord:
        keycloak_subject: str
        enabled: bool = True

    async def _query_user(self, email):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _create_user(self, email, first_name, last_name):
        return _KeycloakRecord(keycloak_subject="kc-subject-synthetic-0016")

    async def _assign_roles(self, subject, roles):
        return None

    monkeypatch.setattr(KeycloakLifecycleAdapter, "query_user_by_email", _query_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "create_user", _create_user)
    monkeypatch.setattr(KeycloakLifecycleAdapter, "assign_approved_roles", _assign_roles)

    calls: list[str] = []

    class _FlakyTelnexaAdapter:
        attempt = 0

        def __init__(self, _settings):
            pass

        async def provision_sender_profile(self, **kwargs):
            _FlakyTelnexaAdapter.attempt += 1
            calls.append("provision_sender_profile")
            if _FlakyTelnexaAdapter.attempt == 1:
                raise TelnexaSenderProfileAdapterError("synthetic transient failure")
            return {"id": "sender-profile-1", "status": "approved"}

    monkeypatch.setattr(settings, "live_identity_provisioning_enabled", True)
    monkeypatch.setattr(settings, "telnexa_write_enabled", True)
    monkeypatch.setattr(settings, "live_writes_enabled", True)
    monkeypatch.setattr(agent_provisioning, "TelnexaSenderProfileAdapter", _FlakyTelnexaAdapter)

    token = authority()
    body = _body(
        channels={"odoo": True, "phone": False, "webrtc": False, "sms": True, "email": False},
        campaigns=[{
            "campaign_id": "TEST_SYN", "role": "supervisor", "sms_sender": "CODESTRA",
        }],
    )
    first = await client.post(
        "/platform/v1/agent-provisioning/requests", json=body,
        headers=_headers(token),
    )
    assert first.status_code == 202
    first_payload = first.json()
    assert first_payload["state"] in ("FAILED", "PARTIAL"), first_payload["steps"]

    request_pk = await _internal_id_for(body["request_id"])
    reconcile = await client.post(
        f"/platform/v1/agent-provisioning/requests/{request_pk}/reconcile",
        json={"reason": "retry after synthetic transient failure"},
        headers=_headers(token),
    )
    assert reconcile.status_code == 200
    second_payload = reconcile.json()
    assert second_payload["state"] == "EFFECTIVE", second_payload["steps"]
    assert calls == ["provision_sender_profile", "provision_sender_profile"]

    succeeded_steps = [
        step for step in second_payload["steps"]
        if step["operation"] == "provision_sender_profile" and step["state"] == "succeeded"
    ]
    assert len(succeeded_steps) == 1
