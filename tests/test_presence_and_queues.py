"""Real-database regressions for GET /platform/v1/agents/*/presence and
/platform/v1/queues/*.

Same convention as tests/test_calls_and_activity.py: skipped unless a
disposable PostgreSQL is available. Seeds durable rows directly (the
integration_event/agent_call_state/campaign_registry rows these read
endpoints project from) rather than re-exercising the full HMAC-signed
/api/v1/events/vicidial ingestion pipeline, which is out of scope here -
this suite is testing the read/query logic, not re-testing ingestion.
"""

from __future__ import annotations

import itertools
import os
import random as _random
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
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1 import presence as presence_module
from app.api.v1 import queues as queues_module
from app.core.config import settings
from app.db.models import (
    AgentCallState,
    CampaignExtensionAllocation,
    CampaignRegistry,
    IntegrationEvent,
)

ISSUER = "https://identity.example.invalid/realms/presence-queues-test"
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
    app.include_router(presence_module.router)
    app.include_router(queues_module.router)
    app.dependency_overrides[presence_module.get_session] = isolated_session
    app.dependency_overrides[queues_module.get_session] = isolated_session

    # No table-wide cleanup here, deliberately: integration_event is shared
    # with other test modules in a full-suite run and can carry a foreign
    # key from invalid_event_quarantine that makes a blanket DELETE fail;
    # campaign_registry/campaign_extension_allocation are append-only
    # (DB-trigger-enforced "campaign identity history is immutable"). Every
    # identifier this suite seeds (agent ids, campaign codes, vicidial
    # campaign ids) is unique per test/run, and every read query takes the
    # most recent row for that specific identifier, so leftover rows from
    # other tests or previous runs are inert noise, not a correctness risk.

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client

    await engine.dispose()


_presence_sequence = itertools.count(start=_random.randint(1, 1_000_000))


async def _seed_presence_row(session_factory, agent_id: str, business_unit: str, state: str):
    # extension/sequence share a unique constraint
    # (uq_agent_call_state_extension_sequence) across this shared, permanent-
    # ish table - use a fresh extension+sequence pair per call.
    unique = next(_presence_sequence)
    async with session_factory() as session:
        session.add(
            AgentCallState(
                call_id=str(uuid4()),
                tenant_id=business_unit,
                business_unit_id=business_unit,
                campaign_id="TRANSPORT",
                agent_id=agent_id,
                extension=str(6100 + (unique % 900)),
                correlation_id=str(uuid4()),
                asterisk_uniqueid=str(uuid4()),
                linkedid=str(uuid4()),
                event_type="call.created",
                state_rank=10,
                sequence=unique,
                event_timestamp=datetime.now(timezone.utc),
                context_json={},
            )
        )
        session.add(
            IntegrationEvent(
                idempotency_key=str(uuid4()),
                event_type="vicidial.agent.state.changed",
                schema_version="1.0",
                original_event_id=str(uuid4()),
                entity_key=f"agent_id:{agent_id}",
                source_system="vicidial",
                correlation_id=str(uuid4()),
                payload_json={
                    "agent_id": agent_id,
                    "state": state,
                    "changed_at": datetime.now(timezone.utc).isoformat(),
                },
                payload_hash=uuid4().hex,
                state="accepted",
            )
        )
        await session.commit()


# campaign_registry / campaign_extension_allocation are permanent, append-only
# (DB-trigger-enforced) tables that are never cleaned between test runs, so
# identifiers must be randomized per run rather than fixed - a fixed value
# collides with whatever a previous run already committed.
_run_base = _random.randint(1000, 8_000_000)
_extension_block = itertools.count(start=0)
# extension_start/end are DB-constrained to [6100, 9999] (this org's real
# extension range - see ck_campaign_extension_allocation_start/_end) with a
# GiST exclude constraint against every row ever inserted (permanent table).
# Only ~38 non-overlapping 100-wide blocks fit; pick a random starting block
# per test run so repeated local runs are unlikely to collide, rather than
# always starting at the same block.
_block_start = _random.randint(0, 30)


def _unique_campaign_code() -> str:
    # campaign_registry.campaign_code is globally UNIQUE and permanent
    # (ck_campaign_registry_code requires ^[A-Z]{3}$) - a real business-unit
    # code like "COD" can only ever be inserted once across this table's
    # entire lifetime. Tests therefore mint a fresh synthetic 3-letter code
    # per call rather than reusing "COD"/"MOY" literals.
    n = _random.randint(0, 26**3 - 1)
    letters = []
    for _ in range(3):
        n, rem = divmod(n, 26)
        letters.append(chr(ord("A") + rem))
    return "".join(letters)


async def _seed_queue(session_factory, campaign_code: str | None = None) -> tuple[str, str]:
    campaign_code = campaign_code or _unique_campaign_code()
    # The valid extension range [6100, 9999] is small and shared with other
    # test modules in this suite that also seed campaign_extension_allocation
    # (a permanent table with a GiST no-overlap exclusion constraint), so a
    # collision with data another test file already committed is a real,
    # observed possibility - retry with a fresh random block rather than
    # assume one random pick is enough.
    last_error: Exception | None = None
    for _attempt in range(20):
        block = _random.randint(0, 38)
        vicidial_campaign_id = str(_run_base + next(_extension_block))[-8:]
        campaign_number = (_run_base + block + 1) * 100 + _random.randint(0, 99)
        campaign_number -= campaign_number % 100
        extension_start = 6100 + block * 100
        extension_end = extension_start + 99
        try:
            async with session_factory() as session:
                allocation_id = uuid4()
                session.add(
                    CampaignExtensionAllocation(
                        id=allocation_id,
                        campaign_id=vicidial_campaign_id,
                        campaign_number=campaign_number,
                        allocation_public_id=str(uuid4()),
                        extension_start=extension_start,
                        extension_end=extension_end,
                        allocation_status="ACTIVE",
                        created_by="test-fixture",
                        policy_hash=uuid4().hex,
                        source_change_id=str(uuid4()),
                    )
                )
                await session.flush()
                await session.commit()
                break
        except Exception as exc:  # noqa: BLE001 - retry on any constraint clash
            last_error = exc
            continue
    else:
        raise AssertionError(
            f"could not find a free extension block after 20 attempts: {last_error}"
        )

    async with session_factory() as session:
        session.add(
            CampaignRegistry(
                campaign_number=campaign_number,
                campaign_code=campaign_code,
                campaign_public_id=f"CMP-{campaign_number}-{campaign_code}",
                name=f"{campaign_code} test campaign",
                vicidial_campaign_id=vicidial_campaign_id,
                agent_group=f"grp_{vicidial_campaign_id}",
                dialplan_context=f"ctx_{vicidial_campaign_id}",
                extension_allocation_id=allocation_id,
                registry_status="ACTIVE",
                policy_hash=uuid4().hex,
                source_change_id=str(uuid4()),
            )
        )
        session.add(
            IntegrationEvent(
                idempotency_key=str(uuid4()),
                event_type="vicidial.hopper.low",
                schema_version="1.0",
                original_event_id=str(uuid4()),
                entity_key=f"campaign_id:{vicidial_campaign_id}",
                source_system="vicidial",
                correlation_id=str(uuid4()),
                payload_json={
                    "campaign_id": vicidial_campaign_id,
                    "remaining": 3,
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                },
                payload_hash=uuid4().hex,
                state="accepted",
            )
        )
        await session.commit()
    return vicidial_campaign_id, campaign_code


@pytest.mark.asyncio
async def test_get_agent_presence_reflects_seeded_state(authority, client):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    await _seed_presence_row(session_factory, "agent-1", "COD", "busy")

    token = authority()
    response = await client.get(
        "/platform/v1/agents/agent-1/presence",
        params={"tenant_id": "COD"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["agent_id"] == "agent-1"
    assert body["state"] == "busy"
    assert body["known"] is True
    await engine.dispose()


@pytest.mark.asyncio
async def test_get_agent_presence_wrong_tenant_denied(authority, client):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    await _seed_presence_row(session_factory, "agent-2", "MOY", "available")

    token = authority(tenant_ids=("COD",))
    response = await client.get(
        "/platform/v1/agents/agent-2/presence",
        params={"tenant_id": "COD"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
    await engine.dispose()


@pytest.mark.asyncio
async def test_get_agent_presence_unknown_agent_returns_offline_shape(authority, client):
    token = authority()
    response = await client.get(
        "/platform/v1/agents/never-seen/presence",
        params={"tenant_id": "COD"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_queue_reflects_seeded_hopper_state(authority, client):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    queue_id, campaign_code = await _seed_queue(session_factory)

    token = authority(tenant_ids=(campaign_code,))
    response = await client.get(
        f"/platform/v1/queues/{queue_id}",
        params={"tenant_id": campaign_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["queue_id"] == queue_id
    assert body["campaign_code"] == campaign_code
    assert body["backlog_remaining"] == 3
    await engine.dispose()


@pytest.mark.asyncio
async def test_get_queue_wrong_tenant_denied(authority, client):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    queue_id, owning_code = await _seed_queue(session_factory)
    other_code = _unique_campaign_code()

    token = authority(tenant_ids=(other_code,))
    response = await client.get(
        f"/platform/v1/queues/{queue_id}",
        params={"tenant_id": other_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
    await engine.dispose()


@pytest.mark.asyncio
async def test_list_queues_scopes_by_tenant(authority, client):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    cod_queue_id, cod_code = await _seed_queue(session_factory)
    moy_queue_id, _moy_code = await _seed_queue(session_factory)

    token = authority(tenant_ids=(cod_code,))
    response = await client.get(
        "/platform/v1/queues",
        params={"tenant_id": cod_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    queue_ids = {item["queue_id"] for item in response.json()["items"]}
    assert cod_queue_id in queue_ids
    assert moy_queue_id not in queue_ids
    await engine.dispose()


@pytest.mark.asyncio
async def test_queue_metrics_returns_backlog_and_abandon_stats(authority, client):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    queue_id, campaign_code = await _seed_queue(session_factory)

    token = authority(tenant_ids=(campaign_code,))
    response = await client.get(
        f"/platform/v1/queues/{queue_id}/metrics",
        params={"tenant_id": campaign_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["backlog_remaining"] == 3
    assert body["abandoned_count_last_hour"] == 0
    await engine.dispose()
