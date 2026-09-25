from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.core.mcr_odoo_handoff import (
    McrOdooHandoffConflict,
    McrOdooHandoffNotFound,
    PostgresMcrOdooHandoffStore,
    command_payload_hash,
    expected_idempotency_key,
)

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
COMMAND_ID = UUID("00000000-0000-4000-8000-000000000101")


class Tx:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeConn:
    def __init__(self):
        self.fetchrow_results = []
        self.fetchval_results = []
        self.calls = []

    def transaction(self):
        self.calls.append(("transaction",))
        return Tx()

    async def fetchrow(self, sql, *args):
        self.calls.append(("fetchrow", " ".join(sql.split()), args))
        return self.fetchrow_results.pop(0) if self.fetchrow_results else None

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", " ".join(sql.split()), args))
        return self.fetchval_results.pop(0) if self.fetchval_results else None


class FakePool:
    def __init__(self, conn):
        self.conn = conn
        self.acquire_count = 0

    def acquire(self):
        self.acquire_count += 1
        return Acquire(self.conn)


def command(**payload_overrides):
    payload = {
        "schema_version": "1.0",
        "lead_id": "100-L-00000001",
        "campaign_id": "klyrow:test-syn-mcr",
        "campaign_version": 1,
        "lifecycle_version": 3,
        "policy_version": "mcr-policy-1.0.0",
        "handoff": "engaged",
        "lifecycle_state": "ENGAGED",
        "signal": "reply",
        "evidence_source": "middleware",
        "evidence_id": "evt-123",
        "evidence_hash": "a" * 64,
        "occurred_at": NOW.isoformat(),
        "dry_run": True,
        "allow_external_contact": False,
    }
    payload.update(payload_overrides)
    value = {
        "command_id": str(COMMAND_ID),
        "command_type": "crm.lifecycle.handoff",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "TEST_SYN_TENANT",
        "requested_by": "svc-mcr",
        "correlation_id": "corr-odoo-1",
        "idempotency_key": "",
        "capability": "ODOO_WRITE",
        "payload": payload,
    }
    value["idempotency_key"] = expected_idempotency_key(value)
    return value


def readback_row(value):
    p = value["payload"]
    return {
        "tenant_id": value["tenant_id"],
        "command_id": UUID(value["command_id"]),
        "lead_id": p["lead_id"],
        "campaign_id": p["campaign_id"],
        "campaign_version": p["campaign_version"],
        "lifecycle_version": p["lifecycle_version"],
        "policy_version": p["policy_version"],
        "handoff": p["handoff"],
        "idempotency_key": value["idempotency_key"],
        "correlation_id": value["correlation_id"],
        "payload_hash": command_payload_hash(value),
        "status": "accepted",
        "odoo_record_id": None,
        "observed_lifecycle_version": None,
        "observed_at": NOW,
    }


def test_idempotency_key_is_deterministic_and_natural_key_bound():
    first = command()
    second = command()
    assert first["idempotency_key"] == second["idempotency_key"]
    changed = command(lifecycle_version=4)
    assert changed["idempotency_key"] != first["idempotency_key"]
    assert first["idempotency_key"].startswith("mcrodoo1:")


@pytest.mark.asyncio
async def test_accept_persists_no_effect_handoff_once():
    value = command()
    conn = FakeConn()
    conn.fetchrow_results = [{"command_id": COMMAND_ID}]
    pool = FakePool(conn)
    result = await PostgresMcrOdooHandoffStore(pool).accept(
        value, causation_id="cause-1", accepted_at=NOW
    )
    assert result.duplicate is False
    assert result.command_id == COMMAND_ID
    insert = next(call for call in conn.calls if call[0] == "fetchrow")
    assert "INSERT INTO mcr_odoo_handoffs" in insert[1]
    assert insert[2][0] == "TEST_SYN_TENANT"
    assert insert[2][1] == COMMAND_ID
    assert not any("middleware_outbox" in str(call) for call in conn.calls)
    assert not any("odoo" in str(call).lower() and "mcr_odoo" not in str(call).lower()
                   for call in conn.calls if len(call) > 1)


@pytest.mark.asyncio
async def test_exact_replay_returns_duplicate_without_second_effect():
    value = command()
    conn = FakeConn()
    conn.fetchrow_results = [
        None,
        {
            "command_id": COMMAND_ID,
            "idempotency_key": value["idempotency_key"],
            "correlation_id": value["correlation_id"],
            "payload_hash": command_payload_hash(value),
            "lead_id": value["payload"]["lead_id"],
            "campaign_id": value["payload"]["campaign_id"],
            "campaign_version": 1,
            "lifecycle_version": 3,
            "policy_version": value["payload"]["policy_version"],
            "handoff": "engaged",
        },
    ]
    result = await PostgresMcrOdooHandoffStore(FakePool(conn)).accept(
        value, causation_id="cause-1", accepted_at=NOW
    )
    assert result.duplicate is True


@pytest.mark.asyncio
async def test_replay_conflict_fails_closed():
    value = command()
    conn = FakeConn()
    conn.fetchrow_results = [
        None,
        {
            "command_id": COMMAND_ID,
            "idempotency_key": value["idempotency_key"],
            "correlation_id": "different-correlation",
            "payload_hash": command_payload_hash(value),
            "lead_id": value["payload"]["lead_id"],
            "campaign_id": value["payload"]["campaign_id"],
            "campaign_version": 1,
            "lifecycle_version": 3,
            "policy_version": value["payload"]["policy_version"],
            "handoff": "engaged",
        },
    ]
    with pytest.raises(McrOdooHandoffConflict, match="different evidence"):
        await PostgresMcrOdooHandoffStore(FakePool(conn)).accept(
            value, causation_id="cause-1", accepted_at=NOW
        )


@pytest.mark.asyncio
async def test_no_effect_guard_rejects_before_database():
    value = command()
    value["payload"]["dry_run"] = False
    value["idempotency_key"] = expected_idempotency_key(value)
    pool = FakePool(FakeConn())
    with pytest.raises(McrOdooHandoffConflict, match="no-effect"):
        await PostgresMcrOdooHandoffStore(pool).accept(
            value, causation_id="cause-1", accepted_at=NOW
        )
    assert pool.acquire_count == 0


@pytest.mark.asyncio
async def test_readback_is_tenant_scoped():
    value = command()
    conn = FakeConn()
    conn.fetchrow_results = [readback_row(value)]
    result = await PostgresMcrOdooHandoffStore(FakePool(conn)).readback(
        "TEST_SYN_TENANT", COMMAND_ID
    )
    assert result["tenant_id"] == "TEST_SYN_TENANT"
    assert result["command_id"] == str(COMMAND_ID)
    assert result["status"] == "accepted"
    assert result["odoo_record_id"] is None


@pytest.mark.asyncio
async def test_unknown_readback_is_not_found():
    conn = FakeConn()
    conn.fetchrow_results = [None]
    with pytest.raises(McrOdooHandoffNotFound):
        await PostgresMcrOdooHandoffStore(FakePool(conn)).readback(
            "TEST_SYN_TENANT", COMMAND_ID
        )


@pytest.mark.asyncio
async def test_reconcile_records_intent_but_never_calls_provider():
    value = command()
    conn = FakeConn()
    conn.fetchval_results = [1]
    conn.fetchrow_results = [
        {"reconciliation_id": UUID("00000000-0000-4000-8000-000000000202")},
        readback_row(value),
    ]
    result = await PostgresMcrOdooHandoffStore(FakePool(conn)).request_reconciliation(
        "TEST_SYN_TENANT",
        COMMAND_ID,
        idempotency_key="reconcile-1",
        correlation_id="corr-reconcile-1",
        causation_id="cause-reconcile-1",
        requested_at=NOW,
    )
    assert result["status"] == "accepted"
    assert any("INSERT INTO mcr_odoo_handoff_reconciliations" in str(call)
               for call in conn.calls)
    assert not any("http" in str(call).lower() for call in conn.calls)
