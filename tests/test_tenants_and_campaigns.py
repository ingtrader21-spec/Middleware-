"""Real-database regressions for GET /platform/v1/tenants/* and
/platform/v1/campaigns/*.

Same convention as tests/test_calls_and_activity.py and
tests/test_presence_and_queues.py: skipped unless a disposable PostgreSQL is
available. Reuses tests/test_presence_and_queues.py's `_seed_queue` helper
to create a real, constraint-valid campaign_registry row rather than
re-deriving the retry-safe extension-allocation seeding logic it already
solved.

Tenant-resolution tests stub FoundationClient at the module level rather
than requiring a live codestra-foundation instance in CI - these tests are
proving tenants.py's own routing/aggregation logic, not re-testing
FoundationClient's HTTP behavior (which is that adapter's own concern).
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
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

from app.adapters.foundation.client import (
    FoundationTenantNotFound,
    FoundationUnavailable,
)
from app.api.v1 import campaigns as campaigns_module
from app.api.v1 import tenants as tenants_module
from app.core.config import settings
from tests.test_presence_and_queues import _seed_queue

ISSUER = "https://identity.example.invalid/realms/tenants-campaigns-test"
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
            "iss": ISSUER,
            "aud": AUDIENCE,
            "azp": azp,
            "sub": subject,
            "iat": current,
            "exp": current + 300,
            "jti": str(uuid4()),
            "scope": scope,
            "tenant_ids": list(tenant_ids),
            **overrides,
        }
        return jwt.encode(claims, private, algorithm="RS256")

    return token


class _StubFoundation:
    """Replaces FoundationClient.get_tenant with an in-memory answer.

    Resolves any tenant_id EXCEPT "ZZZ" (reserved by
    test_get_tenant_unknown_in_foundation_is_404) - campaign_registry's
    campaign_code has a hard, permanent unique constraint shared across this
    whole test session, so each test seeds its own randomly-generated code
    via _seed_queue rather than reusing a fixed literal.
    """

    async def get_tenant(self, http, tenant_id):
        if tenant_id == "ZZZ":
            raise FoundationTenantNotFound(tenant_id)
        return SimpleNamespace(
            id=tenant_id, slug=tenant_id.lower(), name="Codestra", status="ACTIVE"
        )


class _UnavailableFoundation:
    async def get_tenant(self, http, tenant_id):
        raise FoundationUnavailable("test outage")


@pytest_asyncio.fixture
async def client(monkeypatch):
    monkeypatch.setattr(
        tenants_module, "FoundationClient", lambda settings: _StubFoundation()
    )

    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def isolated_session():
        async with session_factory() as session:
            yield session

    app = FastAPI()
    app.include_router(tenants_module.router)
    app.include_router(campaigns_module.router)
    app.dependency_overrides[tenants_module.get_session] = isolated_session
    app.dependency_overrides[campaigns_module.get_session] = isolated_session

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()
    await engine.dispose()


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _seed_provisioning_request(
    session_factory,
    *,
    tenant_id: str,
    employee_id: str,
    campaign_id: str,
    channels: dict[str, bool],
    state: str = "EFFECTIVE",
    created_at: datetime,
) -> None:
    async with session_factory() as session:
        await session.execute(
            text(
                """INSERT INTO agent_provisioning_request
                   (id, request_id, tenant_id, employee_id, primary_email, state,
                    campaigns_json, channels_json, telephony_json, policy_revision,
                    idempotency_hash, request_hash, correlation_id, requested_by,
                    version, created_at, updated_at)
                   VALUES (gen_random_uuid(), :request_id, :tenant_id, :employee_id,
                           :email, :state, CAST(:campaigns AS jsonb),
                           CAST(:channels AS jsonb), '{}'::jsonb, 'test-policy-1',
                           :idempotency_hash, :request_hash, :correlation_id,
                           'test-fixture', 1, :created_at, :created_at)"""
            ),
            {
                "request_id": str(uuid4()),
                "tenant_id": tenant_id,
                "employee_id": employee_id,
                "email": f"{employee_id}@example.invalid",
                "state": state,
                "campaigns": json.dumps([{"campaign_id": campaign_id}]),
                "channels": json.dumps(channels),
                "idempotency_hash": uuid4().hex + uuid4().hex,
                "request_hash": uuid4().hex + uuid4().hex,
                "correlation_id": str(uuid4()),
                "created_at": created_at,
            },
        )
        await session.commit()


@pytest.mark.asyncio
async def test_list_tenants_requires_bearer_token(client):
    response = await client.get("/platform/v1/tenants/authorized")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_tenant_wrong_tenant_claim_is_denied(client, authority):
    token = authority(tenant_ids=("OTHER",))
    response = await client.get("/platform/v1/tenants/COD", headers=_headers(token))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_tenant_reflects_foundation_record(client, authority):
    response = await client.get(
        "/platform/v1/tenants/COD", headers=_headers(authority())
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Codestra"


@pytest.mark.asyncio
async def test_get_tenant_unknown_in_foundation_is_404(client, authority):
    token = authority(tenant_ids=("ZZZ",))
    response = await client.get("/platform/v1/tenants/ZZZ", headers=_headers(token))
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_authorized_directory_fails_closed_when_foundation_is_unavailable(
    client, authority, monkeypatch
):
    monkeypatch.setattr(
        tenants_module, "FoundationClient", lambda settings: _UnavailableFoundation()
    )
    response = await client.get(
        "/platform/v1/tenants/authorized", headers=_headers(authority())
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_tenant_campaigns_reflects_seeded_registry_row(client, authority):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    vicidial_campaign_id, campaign_code = await _seed_queue(session_factory)

    response = await client.get(
        f"/platform/v1/tenants/{campaign_code}/campaigns",
        headers=_headers(authority(tenant_ids=(campaign_code,))),
    )
    assert response.status_code == 200
    body = response.json()
    ids = {item["campaign_id"] for item in body["items"]}
    assert vicidial_campaign_id in ids
    assert body["pagination"] == {
        "limit": 100,
        "offset": 0,
        "returned": 1,
        "total": 1,
    }


@pytest.mark.asyncio
async def test_get_campaign_requires_bearer_token(client):
    response = await client.get("/platform/v1/campaigns/6101?tenant_id=COD")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_campaign_wrong_tenant_is_404_not_leaked(client, authority):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    vicidial_campaign_id, campaign_code = await _seed_queue(session_factory)

    other_token = authority(tenant_ids=("OTHER_TENANT",))
    response = await client.get(
        f"/platform/v1/campaigns/{vicidial_campaign_id}?tenant_id=OTHER_TENANT",
        headers=_headers(other_token),
    )
    # The token's own tenant claim matches its query param (so
    # require_tenant_match passes), but the campaign actually belongs to a
    # different tenant - fail-closed 404, not a 403, matching calls.py's
    # established test_get_call_by_id_wrong_tenant_is_404_not_leaked.
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_campaign_reflects_seeded_registry_row(client, authority):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    vicidial_campaign_id, campaign_code = await _seed_queue(session_factory)

    response = await client.get(
        f"/platform/v1/campaigns/{vicidial_campaign_id}?tenant_id={campaign_code}",
        headers=_headers(authority(tenant_ids=(campaign_code,))),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["campaign_id"] == vicidial_campaign_id
    assert body["campaign_code"] == campaign_code


@pytest.mark.asyncio
async def test_list_campaigns_is_tenant_scoped_and_paginated(client, authority):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    vicidial_campaign_id, campaign_code = await _seed_queue(session_factory)

    response = await client.get(
        "/platform/v1/campaigns",
        params={"tenant_id": campaign_code, "limit": 1, "offset": 0},
        headers=_headers(authority(tenant_ids=(campaign_code,))),
    )
    assert response.status_code == 200
    assert [item["campaign_id"] for item in response.json()["items"]] == [
        vicidial_campaign_id
    ]
    assert response.json()["pagination"] == {
        "limit": 1,
        "offset": 0,
        "returned": 1,
        "total": 1,
    }


@pytest.mark.asyncio
async def test_campaign_channels_reports_zero_when_no_requests_reference_it(
    client, authority
):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    vicidial_campaign_id, campaign_code = await _seed_queue(session_factory)

    response = await client.get(
        f"/platform/v1/campaigns/{vicidial_campaign_id}/channels?tenant_id={campaign_code}",
        headers=_headers(authority(tenant_ids=(campaign_code,))),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["provisioning_requests_referencing_campaign"] == 0
    assert body["desired_channel_counts"] == {}


@pytest.mark.asyncio
async def test_campaign_channels_uses_only_each_agents_latest_desired_state(
    client, authority
):
    session_factory = async_sessionmaker(
        create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool),
        expire_on_commit=False,
    )
    vicidial_campaign_id, campaign_code = await _seed_queue(session_factory)
    now = datetime.now(timezone.utc)

    # A retry for the same employee replaces, rather than adds to, the old
    # desired channels.
    await _seed_provisioning_request(
        session_factory,
        tenant_id=campaign_code,
        employee_id=f"{campaign_code}.agent-1",
        campaign_id=vicidial_campaign_id,
        channels={"phone": True, "sms": True},
        created_at=now - timedelta(minutes=3),
    )
    await _seed_provisioning_request(
        session_factory,
        tenant_id=campaign_code,
        employee_id=f"{campaign_code}.agent-1",
        campaign_id=vicidial_campaign_id,
        channels={"phone": True, "email": True},
        created_at=now - timedelta(minutes=2),
    )
    # A revoked latest request is not presented as active desired intent.
    await _seed_provisioning_request(
        session_factory,
        tenant_id=campaign_code,
        employee_id=f"{campaign_code}.agent-2",
        campaign_id=vicidial_campaign_id,
        channels={"phone": True},
        state="REVOKED",
        created_at=now - timedelta(minutes=1),
    )

    response = await client.get(
        f"/platform/v1/campaigns/{vicidial_campaign_id}/channels"
        f"?tenant_id={campaign_code}",
        headers=_headers(authority(tenant_ids=(campaign_code,))),
    )
    assert response.status_code == 200
    assert response.json() == {
        "campaign_id": vicidial_campaign_id,
        "provisioning_requests_referencing_campaign": 1,
        "desired_channel_counts": {"email": 1, "phone": 1},
        "projection": "latest_desired_request_per_agent",
    }


@pytest.mark.asyncio
async def test_authorized_directory_resolves_only_verified_token_grants(
    client, authority
):
    response = await client.get(
        "/platform/v1/tenants/authorized",
        headers=_headers(authority(tenant_ids=("SMT", "ZZZ", "COD"))),
    )
    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == ["COD", "SMT"]
    assert response.json()["pagination"] == {
        "limit": 100,
        "offset": 0,
        "returned": 2,
        "granted": 3,
    }


@pytest.mark.asyncio
async def test_authorized_directory_pages_before_resolving_foundation(
    client, authority
):
    response = await client.get(
        "/platform/v1/tenants/authorized?limit=1&offset=1",
        headers=_headers(authority(tenant_ids=("SMT", "ZZZ", "COD"))),
    )
    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == ["SMT"]
    assert response.json()["pagination"] == {
        "limit": 1,
        "offset": 1,
        "returned": 1,
        "granted": 3,
    }
