from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.core.campaign_recycling import (
    CampaignRecyclingConflict,
    CampaignRecyclingEngine,
    CampaignRecyclingIdempotencyConflict,
    Candidate,
    ChannelHealth,
    LeadSnapshot,
    PolicyProfile,
    PostgresCampaignRecyclingStore,
    canonical_digest,
    next_action_document,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
TENANT = "TENANT_C2"
LEAD = "100-L-00000042"
SENDER = "00000000-0000-4000-8000-000000000111"


class _Txn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeConn:
    def __init__(self, fetchrow_results=()):
        self.fetchrow_results = list(fetchrow_results)
        self.executed = []

    def transaction(self):
        return _Txn()

    async def fetchrow(self, sql, *args):
        self.executed.append(("fetchrow", sql, args))
        return self.fetchrow_results.pop(0) if self.fetchrow_results else None

    async def execute(self, sql, *args):
        self.executed.append(("execute", sql, args))
        return "INSERT 0 1"


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _Acquire(self.conn)


def decision_document(*, tenant_id: str = TENANT, lead_id: str = LEAD) -> dict:
    snapshot = LeadSnapshot(
        tenant_id=tenant_id,
        lead_id=lead_id,
        lifecycle_state="ELIGIBLE",
        lifecycle_version=3,
        channel_health={"email": ChannelHealth("valid", NOW)},
    )
    candidate = Candidate(
        campaign_id="klyrow:c2",
        campaign_version=1,
        channel="email",
        priority=1,
        touch_index=1,
        sender_identity_id=SENDER,
    )
    decision = CampaignRecyclingEngine(PolicyProfile.load("test")).evaluate(
        snapshot, [candidate], now=NOW
    )
    return next_action_document(
        decision,
        snapshot,
        mode="plan",
        evaluated_at=NOW,
        correlation_id="corr-c2-decision-0001",
    )


@pytest.mark.asyncio
async def test_record_decision_is_tenant_bound_and_append_only() -> None:
    conn = FakeConn([None])
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    document = decision_document()
    request_hash = canonical_digest({"tenant_id": TENANT, "lead_id": LEAD, "request": 1})

    stored, duplicate = await store.record_decision(
        tenant_id=TENANT,
        lead_id=LEAD,
        idempotency_key="idem-c2-decision-0001",
        request_hash=request_hash,
        document=document,
    )

    assert duplicate is False
    assert stored == document
    insert = next(item for item in conn.executed if item[0] == "execute")
    assert "INSERT INTO mcr_decisions" in insert[1]
    assert insert[2][1] == TENANT
    assert insert[2][3] == LEAD
    assert insert[2][5] == request_hash


@pytest.mark.asyncio
async def test_exact_decision_replay_returns_original_without_new_insert() -> None:
    document = decision_document()
    request_hash = canonical_digest({"request": "same"})
    conn = FakeConn([{"request_hash": request_hash, "decision_json": document}])
    store = PostgresCampaignRecyclingStore(FakePool(conn))

    stored, duplicate = await store.record_decision(
        tenant_id=TENANT,
        lead_id=LEAD,
        idempotency_key="idem-c2-decision-replay",
        request_hash=request_hash,
        document={**document, "evaluated_at": "2026-09-25T10:01:00+00:00"},
    )

    assert duplicate is True
    assert stored == document
    assert not any(item[0] == "execute" for item in conn.executed)


@pytest.mark.asyncio
async def test_decision_idempotency_key_reuse_with_changed_request_conflicts() -> None:
    document = decision_document()
    original_hash = canonical_digest({"request": 1})
    changed_hash = canonical_digest({"request": 2})
    conn = FakeConn([{"request_hash": original_hash, "decision_json": document}])
    store = PostgresCampaignRecyclingStore(FakePool(conn))

    with pytest.raises(CampaignRecyclingIdempotencyConflict):
        await store.record_decision(
            tenant_id=TENANT,
            lead_id=LEAD,
            idempotency_key="idem-c2-decision-conflict",
            request_hash=changed_hash,
            document=document,
        )
    assert not any(item[0] == "execute" for item in conn.executed)


@pytest.mark.asyncio
async def test_decision_tenant_and_lead_binding_fails_before_database() -> None:
    conn = FakeConn()
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    document = decision_document()

    with pytest.raises(CampaignRecyclingConflict, match="tenant/lead binding"):
        await store.record_decision(
            tenant_id="OTHER_TENANT",
            lead_id=LEAD,
            idempotency_key="idem-c2-wrong-tenant",
            request_hash=canonical_digest({"request": 1}),
            document=document,
        )
    assert conn.executed == []


@pytest.mark.asyncio
async def test_invalid_frozen_decision_document_fails_before_database() -> None:
    conn = FakeConn()
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    document = decision_document()
    document["provider_effects"] = "provider-call"

    with pytest.raises(CampaignRecyclingConflict, match="frozen next-action contract"):
        await store.record_decision(
            tenant_id=TENANT,
            lead_id=LEAD,
            idempotency_key="idem-c2-invalid",
            request_hash=canonical_digest({"request": 1}),
            document=document,
        )
    assert conn.executed == []


@pytest.mark.asyncio
async def test_latest_decision_readback_is_tenant_and_lead_scoped() -> None:
    document = decision_document()
    conn = FakeConn([{"decision_json": document}])
    store = PostgresCampaignRecyclingStore(FakePool(conn))

    result = await store.latest_decision(tenant_id=TENANT, lead_id=LEAD)

    assert result == document
    query = conn.executed[0]
    assert "WHERE tenant_id=$1 AND lead_id=$2" in query[1]
    assert query[2] == (TENANT, LEAD)


def test_decision_migration_is_additive_append_only_and_non_destructive() -> None:
    text = (
        ROOT / "migrations/versions/0070_campaign_recycling_decision_ledger.py"
    ).read_text(encoding="utf-8")
    assert "down_revision = \"0069_campaign_recycling_delivery_events\"" in text
    assert "CREATE TABLE mcr_decisions" in text
    assert "UNIQUE (tenant_id, idempotency_key)" in text
    assert "mcr_decisions_append_only" in text
    assert "mcr_reject_append_only_mutation" in text
    assert "downgrade refused" in text
    assert "provider" not in text.lower()
