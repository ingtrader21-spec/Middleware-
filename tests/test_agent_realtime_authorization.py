"""Real-database regressions for POST /api/v1/agent/events authorization.

Proves the hardcoded single-extension/single-campaign staging gate that
used to be the *only* check has been replaced with a real per-caller check
for any non-staging campaign/extension, while leaving the staging fixture
path (exact webphone_staging_campaign/webphone_staging_endpoint match)
unchanged. Same disposable-PostgreSQL convention as
tests/test_agent_provisioning_reads.py / tests/test_session_context.py.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
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

from app.api.v1 import agent_realtime
from app.core.config import settings

ISSUER = "https://identity.example.invalid/realms/agent-realtime-test"
AUDIENCE = "middleware-api-test"

pytestmark = pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)


def envelope(**changes):
    value = {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "event_type": "call.ringing",
        "timestamp": datetime.now(UTC).isoformat(),
        "correlation_id": str(uuid4()),
        "idempotency_key": str(uuid4()),
        "tenant_id": "TEN1",
        "business_unit_id": "TEN1",
        "campaign_id": "REAL_CAMPAIGN",
        "call_id": str(uuid4()),
        "asterisk_uniqueid": "asterisk-0001",
        "linkedid": "linked-0001",
        "agent_id": "employee-real-1",
        "extension": "7001",
        "sequence": 1,
        "payload": {},
    }
    value.update(changes)
    return value


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
        "agent_websocket_enabled": True,
        "webphone_staging_campaign": "TEST_SYN",
        "webphone_staging_endpoint": "6101",
    }.items():
        monkeypatch.setattr(settings, key, value)

    def token(
        tenant_ids=("TEN1",),
        scope="identity.request",
        subject="provisioning-service-subject",
        azp="provisioning-service",
    ):
        current = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "azp": azp,
            "sub": subject,
            "iat": current,
            "exp": current + 300,
            "jti": str(uuid4()),
            "scope": scope,
            "tenant_ids": list(tenant_ids),
        }
        return jwt.encode(claims, private, algorithm="RS256")

    return token


@pytest_asyncio.fixture
async def client(monkeypatch):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def isolated_session():
        async with session_factory() as session:
            yield session

    app = FastAPI()
    app.include_router(agent_realtime.router)
    app.dependency_overrides[agent_realtime.get_session] = isolated_session

    async with engine.begin() as connection:
        await connection.execute(text("DELETE FROM agent_call_event"))
        await connection.execute(text("DELETE FROM agent_call_state"))
        await connection.execute(text("DELETE FROM telephony_extension_reservation"))
        await connection.execute(text("DELETE FROM telephony_extension_pool"))
        await connection.execute(text("DELETE FROM agent_provisioning_audit"))
        await connection.execute(text("DELETE FROM agent_provisioning_step"))
        await connection.execute(text("DELETE FROM agent_provisioning_request"))
        await connection.execute(
            text(
                """INSERT INTO telephony_extension_pool
                   (id, code, business_unit, role_class, range_start, range_end, active)
                   VALUES (gen_random_uuid(), :code, 'TEN1', 'agent', 7000, 7099, true)"""
            ),
            {"code": f"test-pool-{uuid4().hex[:8]}"},
        )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client, session_factory


async def _seed_campaign_membership(
    session_factory,
    *,
    employee_id,
    tenant_id,
    campaign_id,
    vicidial_user_id=None,
    state="EFFECTIVE",
):
    async with session_factory() as session:
        campaigns = [{"campaign_id": campaign_id, "role": "agent"}]
        if vicidial_user_id is not None:
            campaigns[0]["vicidial_user_id"] = vicidial_user_id
        request_id = (
            await session.execute(
                text(
                    """INSERT INTO agent_provisioning_request
                       (id, request_id, tenant_id, employee_id, primary_email, state,
                        campaigns_json, channels_json, telephony_json, policy_revision,
                        idempotency_hash, request_hash, correlation_id, requested_by,
                        version, created_at, updated_at)
                       VALUES (gen_random_uuid(), :request_id, :tenant_id, :employee_id,
                               :email, :state, CAST(:campaigns AS jsonb), '{}'::jsonb,
                               '{}'::jsonb, 'test-policy-1', :idem_hash, :req_hash,
                               :correlation_id, 'test-fixture', 1, now(), now())
                       RETURNING id"""
                ),
                {
                    "request_id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "employee_id": employee_id,
                    "email": f"{employee_id}@example.invalid",
                    "campaigns": json.dumps(campaigns),
                    "state": state,
                    "idem_hash": uuid4().hex + uuid4().hex,
                    "req_hash": uuid4().hex + uuid4().hex,
                    "correlation_id": str(uuid4()),
                },
            )
        ).scalar_one()
        await session.commit()
        return request_id


async def _seed_extension_reservation(
    session_factory, *, employee_id, extension, state="ACTIVE"
):
    async with session_factory() as session:
        pool_id = (
            await session.execute(
                text("SELECT id FROM telephony_extension_pool LIMIT 1")
            )
        ).scalar_one()
        await session.execute(
            text(
                """INSERT INTO telephony_extension_reservation
                   (id, extension, employee_id, request_id, pool_id, state,
                    idempotency_hash, evidence_hash, reserved_at, expires_at)
                   VALUES (gen_random_uuid(), :extension, :employee_id, :request_id, :pool_id,
                           :state, :idem_hash, :evidence_hash, now(), now() + interval '1 day')"""
            ),
            {
                "extension": extension,
                "employee_id": employee_id,
                "request_id": str(uuid4()),
                "pool_id": pool_id,
                "state": state,
                "idem_hash": uuid4().hex + uuid4().hex,
                "evidence_hash": uuid4().hex + uuid4().hex,
            },
        )
        await session.commit()


async def _seed_provisioning_extension_step(
    session_factory, *, request_id, extension, operation="reserve_extension"
):
    async with session_factory() as session:
        await session.execute(
            text(
                """INSERT INTO agent_provisioning_step
                   (id, request_id, tenant_id, system, operation, attempt, state,
                    external_reference, created_at)
                   SELECT gen_random_uuid(), id, tenant_id, 'vicidial', :operation,
                          1, 'succeeded', :extension, now()
                   FROM agent_provisioning_request WHERE id=:request_id"""
            ),
            {
                "request_id": request_id,
                "operation": operation,
                "extension": str(extension),
            },
        )
        await session.commit()


@pytest.mark.asyncio
async def test_real_campaign_and_extension_membership_is_authorized(authority, client):
    http_client, session_factory = client
    await _seed_campaign_membership(
        session_factory,
        employee_id="employee-real-1",
        tenant_id="TEN1",
        campaign_id="REAL_CAMPAIGN",
    )
    await _seed_extension_reservation(
        session_factory, employee_id="employee-real-1", extension=7001
    )
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(),
        headers={"Authorization": "Bearer " + authority()},
    )
    assert response.status_code == 202, response.text


@pytest.mark.asyncio
async def test_primary_provisioning_saga_extension_step_is_authorized(
    authority, client
):
    """The normal agent-provisioning path does not create a local reservation."""
    http_client, session_factory = client
    request_id = await _seed_campaign_membership(
        session_factory,
        employee_id="employee-real-1",
        tenant_id="TEN1",
        campaign_id="REAL_CAMPAIGN",
    )
    await _seed_provisioning_extension_step(
        session_factory, request_id=request_id, extension=7001
    )
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(),
        headers={"Authorization": "Bearer " + authority()},
    )
    assert response.status_code == 202, response.text


@pytest.mark.asyncio
async def test_vicidial_agent_id_resolves_to_canonical_employee(authority, client):
    http_client, session_factory = client
    await _seed_campaign_membership(
        session_factory,
        employee_id="odoo-employee-42",
        tenant_id="TEN1",
        campaign_id="REAL_CAMPAIGN",
        vicidial_user_id="cod00042",
    )
    await _seed_extension_reservation(
        session_factory, employee_id="odoo-employee-42", extension=7001
    )
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(agent_id="cod00042"),
        headers={"Authorization": "Bearer " + authority()},
    )
    assert response.status_code == 202, response.text


@pytest.mark.asyncio
async def test_campaign_not_in_membership_is_rejected(authority, client):
    http_client, session_factory = client
    await _seed_campaign_membership(
        session_factory,
        employee_id="employee-real-1",
        tenant_id="TEN1",
        campaign_id="OTHER_CAMPAIGN",
    )
    await _seed_extension_reservation(
        session_factory, employee_id="employee-real-1", extension=7001
    )
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(campaign_id="REAL_CAMPAIGN"),
        headers={"Authorization": "Bearer " + authority()},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "campaign denied"


@pytest.mark.asyncio
async def test_extension_not_owned_by_agent_is_rejected(authority, client):
    http_client, session_factory = client
    await _seed_campaign_membership(
        session_factory,
        employee_id="employee-real-1",
        tenant_id="TEN1",
        campaign_id="REAL_CAMPAIGN",
    )
    # Extension reserved for a DIFFERENT employee - the caller's own agent_id
    # must not be able to claim someone else's extension.
    await _seed_extension_reservation(
        session_factory, employee_id="someone-else", extension=7001
    )
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(),
        headers={"Authorization": "Bearer " + authority()},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "extension denied"


@pytest.mark.asyncio
async def test_tenant_outside_token_scope_is_rejected(authority, client):
    http_client, session_factory = client
    await _seed_campaign_membership(
        session_factory,
        employee_id="employee-real-1",
        tenant_id="TEN1",
        campaign_id="REAL_CAMPAIGN",
    )
    await _seed_extension_reservation(
        session_factory, employee_id="employee-real-1", extension=7001
    )
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(),
        headers={"Authorization": "Bearer " + authority(tenant_ids=("OTHER_TENANT",))},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_revoked_provisioning_request_is_rejected(authority, client):
    http_client, session_factory = client
    request_id = await _seed_campaign_membership(
        session_factory,
        employee_id="employee-real-1",
        tenant_id="TEN1",
        campaign_id="REAL_CAMPAIGN",
        state="REVOKED",
    )
    await _seed_provisioning_extension_step(
        session_factory, request_id=request_id, extension=7001
    )
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(),
        headers={"Authorization": "Bearer " + authority()},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "campaign denied"


@pytest.mark.asyncio
async def test_staging_fixture_pair_still_bypasses_the_real_check(authority, client):
    http_client, _session_factory = client
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(campaign_id="TEST_SYN", extension="6101", agent_id="whoever"),
        headers={"Authorization": "Bearer " + authority()},
    )
    assert response.status_code == 202, response.text


@pytest.mark.asyncio
async def test_staging_fixture_still_requires_tenant_binding(authority, client):
    http_client, _session_factory = client
    response = await http_client.post(
        "/api/v1/agent/events",
        json=envelope(campaign_id="TEST_SYN", extension="6101", agent_id="whoever"),
        headers={"Authorization": "Bearer " + authority(tenant_ids=("OTHER_TENANT",))},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_missing_bearer_is_rejected(client):
    http_client, _session_factory = client
    response = await http_client.post("/api/v1/agent/events", json=envelope())
    assert response.status_code == 401
