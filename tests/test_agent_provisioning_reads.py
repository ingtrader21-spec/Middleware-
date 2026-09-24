"""Real-database regressions for the Milestone 3 read-side API.

Same convention as tests/test_agent_provisioning.py: runs only when a
disposable PostgreSQL is available. Provisions one real request through the
write-side saga (with all provider-write kill switches closed, so it lands
PARTIAL/gated rather than calling any real adapter), then asserts the
read-side endpoints in app.api.v1.agent_provisioning_reads report exactly
what that write produced - proving these are real reads of saga state, not
schema-shape-only tests.
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

from app.api.v1 import agent_provisioning, agent_provisioning_reads
from app.core.config import settings

ISSUER = "https://identity.example.invalid/realms/agent-provisioning-reads-test"
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
    app.include_router(agent_provisioning_reads.router)
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
        "campaigns": [{
            "campaign_id": "TEST_SYN", "role": "supervisor",
            "campaign_email": "a.p@codestra-test.invalid", "sms_sender": "CODESTRA",
        }],
        "channels": {"odoo": True, "phone": True, "webrtc": True, "sms": True, "email": True},
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


async def _provision(client, authority, **body_overrides) -> dict:
    response = await client.post(
        "/platform/v1/agent-provisioning/requests",
        json=_body(**body_overrides), headers=_headers(authority()),
    )
    assert response.status_code == 202, response.text
    return response.json()


@pytest.mark.asyncio
async def test_get_user_requires_bearer_token(client, authority):
    response = await client.get("/platform/v1/users/COD.2026.00016?tenant_id=COD")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_user_unknown_employee_is_404(client, authority):
    response = await client.get(
        "/platform/v1/users/no-such-employee?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_user_wrong_tenant_claim_is_denied(client, authority):
    await _provision(client, authority)
    token = authority(tenant_ids=("OTHER_TENANT",))
    response = await client.get(
        "/platform/v1/users/COD.2026.00016?tenant_id=COD",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_user_reflects_actual_saga_state(client, authority):
    created = await _provision(client, authority)
    response = await client.get(
        "/platform/v1/users/COD.2026.00016?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["employee_id"] == "COD.2026.00016"
    assert body["primary_email"] == "appolon1908@gmail.com"
    assert body["state"] == created["state"]
    # every channel is gated (kill switches closed in this fixture), never
    # silently reported as EFFECTIVE
    assert body["state"] in {"PARTIAL", "FAILED"}


@pytest.mark.asyncio
async def test_get_user_campaigns_returns_desired_assignments(client, authority):
    await _provision(client, authority)
    response = await client.get(
        "/platform/v1/users/COD.2026.00016/campaigns?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["campaigns"][0]["campaign_id"] == "TEST_SYN"
    assert body["campaigns"][0]["role"] == "supervisor"


@pytest.mark.asyncio
async def test_get_user_entitlements_reports_gated_not_effective(client, authority):
    await _provision(client, authority)
    response = await client.get(
        "/platform/v1/users/COD.2026.00016/entitlements?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    channels = {c["channel"]: c for c in response.json()["channels"]}
    assert set(channels) == {"odoo", "phone", "webrtc", "sms", "email"}
    for name in ("phone", "webrtc", "sms", "email"):
        assert channels[name]["desired_enabled"] is True
        # kill switches are closed in this fixture - nothing may claim to
        # be effective
        assert channels[name]["effective_access"] is False
        # never a real credential/secret in a read response
        assert "secret" not in str(channels[name]).lower()
        assert "password" not in str(channels[name]).lower()


@pytest.mark.asyncio
async def test_telephony_assignments_lists_the_provisioned_employee(client, authority):
    await _provision(client, authority)
    response = await client.get(
        "/platform/v1/telephony/assignments?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert any(item["employee_id"] == "COD.2026.00016" for item in body["items"])
    match = next(item for item in body["items"] if item["employee_id"] == "COD.2026.00016")
    assert match["desired_extension"] == "6101"
    assert match["phone"]["effective_access"] is False


@pytest.mark.asyncio
async def test_telephony_assignments_wrong_tenant_is_denied(client, authority):
    await _provision(client, authority)
    token = authority(tenant_ids=("OTHER_TENANT",))
    response = await client.get(
        "/platform/v1/telephony/assignments?tenant_id=COD",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_email_identities_lists_campaign_email(client, authority):
    await _provision(client, authority)
    response = await client.get(
        "/platform/v1/email/identities?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    match = next(item for item in body["items"] if item["employee_id"] == "COD.2026.00016")
    assert match["campaign_email"] == "a.p@codestra-test.invalid"
    assert match["effective_access"] is False


@pytest.mark.asyncio
async def test_sms_identities_lists_campaign_sender(client, authority):
    await _provision(client, authority)
    response = await client.get(
        "/platform/v1/sms/identities?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    match = next(item for item in body["items"] if item["employee_id"] == "COD.2026.00016")
    assert match["sms_sender"] == "CODESTRA"


@pytest.mark.asyncio
async def test_telephony_assignments_pagination_cursor_advances(client, authority):
    for i in range(3):
        await _provision(
            client, authority,
            request_id=f"req_page_{i}_{uuid4().hex[:8]}",
            employee_id=f"COD.2026.{90000 + i}",
        )
    first_page = await client.get(
        "/platform/v1/telephony/assignments?tenant_id=COD&limit=2",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert first_page.status_code == 200
    first_body = first_page.json()
    assert len(first_body["items"]) == 2
    assert first_body["next_cursor"] is not None

    second_page = await client.get(
        f"/platform/v1/telephony/assignments?tenant_id=COD&limit=2&cursor={first_body['next_cursor']}",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert second_page.status_code == 200
    second_body = second_page.json()
    first_ids = {item["employee_id"] for item in first_body["items"]}
    second_ids = {item["employee_id"] for item in second_body["items"]}
    assert first_ids.isdisjoint(second_ids)


@pytest.mark.asyncio
async def test_email_identities_campaign_id_filter_scopes_results(client, authority):
    await _provision(client, authority)
    await _provision(
        client, authority,
        request_id=f"req_other_campaign_{uuid4().hex[:8]}",
        employee_id="COD.2026.00099",
        campaigns=[{
            "campaign_id": "OTHER_CAMPAIGN", "role": "agent",
            "campaign_email": "other@codestra-test.invalid", "sms_sender": "CODESTRA2",
        }],
    )

    scoped_to_test_syn = await client.get(
        "/platform/v1/email/identities?tenant_id=COD&campaign_id=TEST_SYN",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert scoped_to_test_syn.status_code == 200
    ids = {item["employee_id"] for item in scoped_to_test_syn.json()["items"]}
    assert "COD.2026.00016" in ids
    assert "COD.2026.00099" not in ids

    scoped_to_other = await client.get(
        "/platform/v1/email/identities?tenant_id=COD&campaign_id=OTHER_CAMPAIGN",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert scoped_to_other.status_code == 200
    ids = {item["employee_id"] for item in scoped_to_other.json()["items"]}
    assert "COD.2026.00099" in ids
    assert "COD.2026.00016" not in ids

    # No filter: unscoped behavior is unchanged, both are visible.
    unscoped = await client.get(
        "/platform/v1/email/identities?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    ids = {item["employee_id"] for item in unscoped.json()["items"]}
    assert {"COD.2026.00016", "COD.2026.00099"} <= ids


@pytest.mark.asyncio
async def test_email_identities_read_is_audited(client, authority):
    await _provision(client, authority)
    response = await client.get(
        "/platform/v1/email/identities?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200

    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    async with engine.connect() as connection:
        rows = (
            await connection.execute(
                text(
                    "SELECT action, actor_subject FROM agent_provisioning_audit "
                    "WHERE action = 'email_identity.read'"
                )
            )
        ).fetchall()
    await engine.dispose()
    assert len(rows) >= 1
    assert rows[0].actor_subject == "provisioning-service-subject"


@pytest.mark.asyncio
async def test_email_identities_read_rate_limited(client, authority, monkeypatch):
    monkeypatch.setattr(agent_provisioning_reads, "_SENDER_IDENTITY_READS_PER_MINUTE", 3)
    agent_provisioning_reads._sender_identity_read_requests.clear()
    token = authority(tenant_ids=("RATE_LIMIT_TEST_TENANT",))
    headers = {"Authorization": f"Bearer {token}"}

    for _ in range(3):
        response = await client.get(
            "/platform/v1/email/identities?tenant_id=RATE_LIMIT_TEST_TENANT",
            headers=headers,
        )
        assert response.status_code == 200

    limited = await client.get(
        "/platform/v1/email/identities?tenant_id=RATE_LIMIT_TEST_TENANT",
        headers=headers,
    )
    assert limited.status_code == 429
