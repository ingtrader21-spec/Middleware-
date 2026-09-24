"""Real-database regressions for GET /api/v1/integrations/odoo/sync-status
and /odoo/sync-errors.

Same convention as tests/test_calls_and_activity.py: skipped unless a
disposable PostgreSQL is available. Seeds real rows directly into
vicidial_campaign_registry (the same reviewed, migration-controlled table
tests/../app/api/v1/mappings.py already reads) rather than going through a
mutation path - none exists for this table, by design (see the note in
app/api/v1/integrations.py).
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
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

from app.api.v1 import integrations as integrations_module
from app.core.config import settings

ISSUER = "https://identity.example.invalid/realms/odoo-sync-test"
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
    }.items():
        monkeypatch.setattr(settings, key, value)

    def token(tenant_ids=("MOY",), **overrides):
        current = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "azp": "provisioning-service",
            "sub": "provisioning-service-subject",
            "iat": current,
            "exp": current + 300,
            "jti": str(uuid4()),
            "scope": "identity.request",
            "tenant_ids": list(tenant_ids),
            **overrides,
        }
        return jwt.encode(claims, private, algorithm="RS256")

    return token


@pytest_asyncio.fixture
async def client(authority):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def isolated_session():
        async with session_factory() as session:
            yield session

    app = FastAPI()
    app.include_router(integrations_module.router)
    app.dependency_overrides[integrations_module.get_session] = isolated_session

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()
    await engine.dispose()


async def _seed_mapping(
    session_factory, *, unit: str, code: str, drift_status: str
) -> None:
    # ck_vicidial_registry_reconciled_readback requires last_read_back_at and
    # observed_state_hash whenever drift_status='reconciled' - a real
    # production guard, not incidental to work around.
    reconciled = drift_status == "reconciled"
    async with session_factory() as session:
        await session.execute(
            text(
                "INSERT INTO vicidial_campaign_registry "
                "(mapping_uuid, environment, business_unit_code, canonical_campaign_code, "
                " direction, vicidial_campaign_id, desired_state_hash, drift_status, "
                " last_read_back_at, observed_state_hash) "
                "VALUES (:uuid, 'staging', :unit, :code, 'OUT', :vcid, :hash, :drift, "
                " :read_back_at, :observed_hash)"
            ),
            {
                "uuid": uuid4(),
                "unit": unit,
                "code": code,
                "vcid": str(uuid4().int)[:8],
                "hash": uuid4().hex,
                "drift": drift_status,
                "read_back_at": datetime.now(timezone.utc) if reconciled else None,
                "observed_hash": uuid4().hex if reconciled else None,
            },
        )
        await session.commit()


@pytest.mark.asyncio
async def test_sync_status_groups_by_drift_status(client, authority):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    unit = "MOY"
    suffix = uuid4().hex[:8]
    code_a, code_b = f"{unit}-A-{suffix}", f"{unit}-B-{suffix}"
    await _seed_mapping(
        session_factory, unit=unit, code=code_a, drift_status="reconciled"
    )
    await _seed_mapping(session_factory, unit=unit, code=code_b, drift_status="drifted")

    response = await client.get(
        "/api/v1/integrations/odoo/sync-status",
        params={"business_unit": unit},
        headers={"Authorization": f"Bearer {authority((unit,))}"},
    )
    assert response.status_code == 200
    body = response.json()
    # This endpoint returns aggregate counts, not individual codes, and
    # business_unit_code is shared across tests (not unique per row like
    # campaign_registry's campaign_code) - assert at-least-one rather than
    # an exact count, which would be brittle against other tests/runs also
    # seeding "MOY".
    assert body["total_mappings"] >= 2
    assert body["mapping_count_by_drift_status"].get("reconciled", 0) >= 1
    assert body["mapping_count_by_drift_status"].get("drifted", 0) >= 1


@pytest.mark.asyncio
async def test_sync_errors_excludes_reconciled_and_not_observed(client, authority):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    unit = "MOY"
    suffix = uuid4().hex[:8]
    code_ok, code_new, code_bad = (
        f"{unit}-OK-{suffix}",
        f"{unit}-NEW-{suffix}",
        f"{unit}-BAD-{suffix}",
    )
    await _seed_mapping(
        session_factory, unit=unit, code=code_ok, drift_status="reconciled"
    )
    await _seed_mapping(
        session_factory, unit=unit, code=code_new, drift_status="not_observed"
    )
    await _seed_mapping(
        session_factory, unit=unit, code=code_bad, drift_status="drifted"
    )

    response = await client.get(
        "/api/v1/integrations/odoo/sync-errors",
        params={"business_unit": unit},
        headers={"Authorization": f"Bearer {authority((unit,))}"},
    )
    assert response.status_code == 200
    # business_unit_code is not unique per row (unlike campaign_registry's
    # campaign_code) - other tests in this same run may have already seeded
    # rows for "MOY", so assert inclusion/exclusion of THIS test's own codes
    # rather than an exact set, which would be brittle against that sharing.
    body = response.json()
    codes = {item["canonical_campaign_code"] for item in body["items"]}
    assert code_bad in codes
    assert code_ok not in codes
    assert code_new not in codes
    assert body["pagination"]["offset"] == 0
    assert body["pagination"]["returned"] == len(body["items"])
    assert isinstance(body["pagination"]["has_more"], bool)


@pytest.mark.asyncio
async def test_sync_status_requires_authentication(client):
    response = await client.get(
        "/api/v1/integrations/odoo/sync-status",
        params={"business_unit": "MOY"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_odoo_status_requires_authentication(client):
    response = await client.get("/api/v1/integrations/odoo/status")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_odoo_status_aggregates_health_and_readiness(client, authority):
    response = await client.get(
        "/api/v1/integrations/odoo/status",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["health"]["status"] == "ok"
    assert "automation_writes_enabled" in body


@pytest.mark.asyncio
async def test_sync_status_rejects_unknown_environment(client, authority):
    response = await client.get(
        "/api/v1/integrations/odoo/sync-status",
        params={"business_unit": "MOY", "environment": "sandbox"},
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 422
