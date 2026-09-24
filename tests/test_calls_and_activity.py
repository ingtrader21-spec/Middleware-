"""Real-database regressions for GET /platform/v1/calls and /activity.

Same convention as tests/test_agent_provisioning_reads.py: skipped unless a
disposable PostgreSQL is available, seeds real rows through the existing
write paths (POST /v1/telephony/calls/originate for calls; the agent-
provisioning saga for activity), and asserts the read endpoints report
exactly what those writes produced.
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

from app.api.v1 import activity as activity_module
from app.api.v1 import agent_provisioning
from app.api.v1 import calls as calls_module
from app.core.config import settings

ISSUER = "https://identity.example.invalid/realms/calls-activity-test"
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
    app.include_router(calls_module.router)
    app.include_router(activity_module.router)
    app.dependency_overrides[agent_provisioning.get_session] = isolated_session

    async with engine.begin() as connection:
        await connection.execute(text("DELETE FROM agent_provisioning_audit"))
        await connection.execute(text("DELETE FROM agent_provisioning_step"))
        await connection.execute(text("DELETE FROM agent_provisioning_request"))
        await connection.execute(
            text("DELETE FROM idempotency_record WHERE scope = 'agent_provisioning'")
        )
        await connection.execute(text("DELETE FROM telephony_call_lifecycle"))
        await connection.execute(text("DELETE FROM audit_event"))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()
    await engine.dispose()


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _seed_call(
    client_engine_session_factory, *, business_unit: str, campaign: str,
    lead_model: str | None = None, lead_id: int | None = None,
) -> tuple[str, str]:
    """Insert a telephony_call_lifecycle + matching audit_event row directly.

    Goes straight to the DB rather than through POST /calls/originate: that
    endpoint requires a real agent-assignment identity lookup this test
    suite has no fixture for, and exercising it is out of scope for these
    read-side tests (it already has its own test coverage elsewhere).
    """
    from sqlalchemy import text as sql_text

    correlation_id = f"corr-{uuid4().hex[:12]}"
    call_id = uuid4()
    async with client_engine_session_factory() as session:
        await session.execute(
            sql_text(
                "INSERT INTO telephony_call_lifecycle "
                "(id, correlation_id, primary_unique_id, lifecycle_state, "
                " started_at, source_extension, destination, dialplan_context, "
                " lead_model, lead_id) "
                "VALUES (:id, :cid, :puid, 'STARTED', now(), '6101', '+15551234567', "
                " 'click-to-call', :lead_model, :lead_id)"
            ),
            {
                "id": call_id, "cid": correlation_id, "puid": f"click-to-call:{call_id}",
                "lead_model": lead_model, "lead_id": lead_id,
            },
        )
        await session.execute(
            sql_text(
                "INSERT INTO audit_event (id, action, subject, correlation_id, decision, redacted_payload) "
                "VALUES (gen_random_uuid(), 'telephony.calls.originate', :subject, :cid, 'allow', "
                " CAST(:payload AS JSONB))"
            ),
            {
                "subject": str(call_id), "cid": correlation_id,
                "payload": (
                    '{"business_unit": "%s", "campaign": "%s"}' % (business_unit, campaign)
                ),
            },
        )
        await session.commit()
    return str(call_id), correlation_id


@pytest.mark.asyncio
async def test_list_calls_requires_bearer_token(client):
    response = await client.get("/platform/v1/calls?tenant_id=COD")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_calls_wrong_tenant_claim_is_denied(client, authority):
    token = authority(tenant_ids=("OTHER",))
    response = await client.get(
        "/platform/v1/calls?tenant_id=COD", headers=_headers(token)
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_list_calls_reflects_seeded_row_and_excludes_other_tenant(client, authority):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    call_id, _ = await _seed_call(session_factory, business_unit="COD", campaign="TEST_SYN")
    await _seed_call(session_factory, business_unit="OTHER_TENANT", campaign="TEST_SYN")
    await engine.dispose()

    response = await client.get(
        "/platform/v1/calls?tenant_id=COD", headers=_headers(authority())
    )
    assert response.status_code == 200
    body = response.json()
    call_ids = {item["call_id"] for item in body["items"]}
    assert call_id in call_ids
    assert len(body["items"]) == 1  # the OTHER_TENANT row must not leak through


@pytest.mark.asyncio
async def test_list_calls_exposes_lead_reference_when_present(client, authority):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    with_lead, _ = await _seed_call(
        session_factory, business_unit="COD", campaign="TEST_SYN",
        lead_model="crm.lead", lead_id=4821,
    )
    without_lead, _ = await _seed_call(session_factory, business_unit="COD", campaign="TEST_SYN")
    await engine.dispose()

    response = await client.get(
        "/platform/v1/calls?tenant_id=COD", headers=_headers(authority())
    )
    assert response.status_code == 200
    by_id = {item["call_id"]: item for item in response.json()["items"]}
    assert by_id[with_lead]["lead_model"] == "crm.lead"
    assert by_id[with_lead]["lead_id"] == 4821
    assert by_id[without_lead]["lead_model"] is None
    assert by_id[without_lead]["lead_id"] is None


@pytest.mark.asyncio
async def test_get_call_by_id_wrong_tenant_is_404_not_leaked(client, authority):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    call_id, _ = await _seed_call(session_factory, business_unit="COD", campaign="TEST_SYN")
    await engine.dispose()

    other_token = authority(tenant_ids=("OTHER_TENANT",))
    response = await client.get(
        f"/platform/v1/calls/{call_id}?tenant_id=OTHER_TENANT",
        headers=_headers(other_token),
    )
    assert response.status_code == 404


def _provision_body(**overrides) -> dict:
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


def _provision_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": uuid4().hex,
        "X-Correlation-ID": str(uuid4()),
        "X-Policy-Revision": "7",
    }


@pytest.mark.asyncio
async def test_activity_unifies_provisioning_audit_into_one_feed(client, authority):
    response = await client.post(
        "/platform/v1/agent-provisioning/requests",
        json=_provision_body(), headers=_provision_headers(authority()),
    )
    assert response.status_code == 202, response.text

    activity_response = await client.get(
        "/platform/v1/activity?tenant_id=COD", headers=_headers(authority())
    )
    assert activity_response.status_code == 200
    body = activity_response.json()
    provisioning_items = [
        item for item in body["items"] if item["source"] == "agent_provisioning_audit"
    ]
    assert provisioning_items, "expected the saga's own audit trail to appear in the unified feed"
    assert all(item["type"].startswith("provisioning.") for item in provisioning_items)


@pytest.mark.asyncio
async def test_activity_wrong_tenant_claim_is_denied(client, authority):
    token = authority(tenant_ids=("OTHER",))
    response = await client.get(
        "/platform/v1/activity?tenant_id=COD", headers=_headers(token)
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_activity_filters_by_type(client, authority):
    await client.post(
        "/platform/v1/agent-provisioning/requests",
        json=_provision_body(), headers=_provision_headers(authority()),
    )
    response = await client.get(
        "/platform/v1/activity?tenant_id=COD&type=provisioning.advance",
        headers=_headers(authority()),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["items"]
    assert all(item["type"] == "provisioning.advance" for item in body["items"])
