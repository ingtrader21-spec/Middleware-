"""Middleware-side assertions for the joint TEST_SYN certification (outbox intake).

Proves, against a stateful fake Odoo outbox and a fake session with the
integration_event unique constraint:

- lease expiry before acknowledgement returns the same outbox event;
- persist_intake reports a duplicate for the same event id + payload hash;
- a conflicting payload hash for the same event id is rejected;
- exactly one integration_event row exists afterwards;
- after durable-intake acknowledgement, Odoo no longer returns the event.

Execution completion is deliberately NOT asserted here: it is proven only by
the actual-state readback (see tests/test_odoo_campaign_saga.py).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from app.adapters.odoo import sync
from app.db.models import IntegrationEvent


def _record(payload: dict[str, Any], event_id: str = "TEST_SYN_EVENT_1") -> dict[str, Any]:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {
        "event_id": event_id,
        "event_type": "campaign.provision.requested.v1",
        "schema_version": "1.0",
        "payload": payload,
        "payload_hash": f"sha256:{hashlib.sha256(encoded).hexdigest()}",
        "correlation_id": "TEST_SYN_CORRELATION",
        "aggregate_type": "campaign",
        "aggregate_public_id": "TEST_SYN",
    }


def _claimed(record: dict[str, Any]) -> dict[str, Any]:
    return {**record, "lease_token": "lease-direct", "lease_generation": 1}


PAYLOAD = {
    "command_id": "cmd-1",
    "organization_public_id": "TEST_SYN_TENANT",
    "business_unit_public_id": "TEST_SYN",
    "campaign_public_id": "TEST_SYN",
    "configuration_version": 1,
    "manifest_ref": "manifest://TEST_SYN/1",
    "manifest_hash": "sha256:" + "a" * 64,
}


class FakeOdooOutbox:
    """Minimal lease semantics: a claimed record is invisible until its lease expires."""

    def __init__(self, records: list[dict[str, Any]]):
        self.records = {r["event_id"]: dict(r) for r in records}
        self.leased: set[str] = set()
        self.acknowledged: set[str] = set()
        self.generation = 0
        self.fail_next_ack = False
        self.calls: list[tuple[str, str]] = []

    def expire_leases(self) -> None:
        self.leased.clear()

    async def request(self, method: str, path: str, body: Any, **_: Any) -> dict[str, Any]:
        self.calls.append((method, path))
        if path.endswith("/capabilities"):
            return {"capabilities": ["outbox.claim", "outbox.acknowledge"]}
        if path.endswith("/outbox/claims"):
            out = []
            for event_id, record in self.records.items():
                if event_id in self.acknowledged or event_id in self.leased:
                    continue
                self.generation += 1
                self.leased.add(event_id)
                out.append({**record, "lease_token": f"lease-{self.generation}", "lease_generation": self.generation})
            return {"records": out}
        if path.endswith("/acknowledgements"):
            if self.fail_next_ack:
                self.fail_next_ack = False
                raise httpx.ConnectError("synthetic outage before acknowledgement")
            event_id = path.split("/outbox/")[1].split("/")[0]
            assert body["lease_token"].startswith("lease-")
            self.acknowledged.add(event_id)
            self.leased.discard(event_id)
            return {"delivery_state": "acknowledged"}
        raise AssertionError(f"unexpected Odoo call {method} {path}")

    async def aclose(self) -> None:
        return None


class FakeIntegrationEventStore:
    """integration_event with its unique original_event_id, shared across sessions."""

    def __init__(self) -> None:
        self.rows: dict[str, IntegrationEvent] = {}
        self.audit: list[Any] = []
        self.next_id = 1
        self.race_once = False

    def factory(self):
        store = self

        class Session:
            def __init__(self) -> None:
                self.pending: list[Any] = []

            async def scalar(self, _statement):
                if store.race_once:
                    # Another worker has not committed yet: the pre-check sees nothing.
                    return None
                return store.rows.get(_statement.whereclause.right.value)

            def add(self, value: Any) -> None:
                self.pending.append(value)

            async def commit(self) -> None:
                for value in self.pending:
                    if isinstance(value, IntegrationEvent):
                        if value.original_event_id in store.rows:
                            store.race_once = False
                            raise IntegrityError("INSERT", {}, Exception("uq_integration_event_original_event_id"))
                        value.id = store.next_id
                        store.next_id += 1
                        store.rows[value.original_event_id] = value
                    else:
                        store.audit.append(value)
                self.pending = []

            async def rollback(self) -> None:
                self.pending = []

        @asynccontextmanager
        async def _factory():
            yield Session()

        return _factory


@pytest.fixture
def store(monkeypatch):
    fake = FakeIntegrationEventStore()
    monkeypatch.setattr(sync, "SessionFactory", fake.factory())
    return fake


def _bind(monkeypatch, odoo: FakeOdooOutbox) -> None:
    async def create():
        return odoo

    monkeypatch.setattr(sync.OdooRuntimeClient, "create", create)


def test_lease_expiry_before_ack_returns_same_event_and_intake_is_idempotent(monkeypatch, store):
    odoo = FakeOdooOutbox([_record(PAYLOAD)])
    _bind(monkeypatch, odoo)

    # Cycle 1: durable intake succeeds, acknowledgement fails -> event stays leased.
    odoo.fail_next_ack = True
    with pytest.raises(httpx.ConnectError):
        asyncio.run(sync.run_sync_cycle())
    assert set(store.rows) == {"TEST_SYN_EVENT_1"}
    assert odoo.acknowledged == set()

    # While leased, Odoo does not hand the event out again.
    assert asyncio.run(sync.run_sync_cycle())["claimed"] == 0

    # Lease expiry before acknowledgement: the same event comes back and
    # intake reports a duplicate for the same hash; still exactly one row.
    odoo.expire_leases()
    result = asyncio.run(sync.run_sync_cycle())
    assert result == {"status": "processed", "claimed": 1, "accepted": 0, "duplicates": 1}
    assert len(store.rows) == 1
    assert "TEST_SYN_EVENT_1" in odoo.acknowledged

    # After durable-intake acknowledgement Odoo never returns the event again.
    odoo.expire_leases()
    assert asyncio.run(sync.run_sync_cycle())["claimed"] == 0
    assert len(store.rows) == 1


def test_conflicting_payload_hash_for_same_event_id_is_rejected(monkeypatch, store):
    asyncio.run(sync.persist_intake(_claimed(_record(PAYLOAD))))
    changed = _record({**PAYLOAD, "configuration_version": 2})
    with pytest.raises(sync.OdooSyncError, match="idempotency conflict"):
        asyncio.run(sync.persist_intake(_claimed(changed)))
    assert len(store.rows) == 1
    assert store.rows["TEST_SYN_EVENT_1"].payload_json["configuration_version"] == 1


def test_concurrent_intake_race_resolves_on_the_unique_constraint(monkeypatch, store):
    """Two workers pass the pre-check; the second loses on the unique index."""
    asyncio.run(sync.persist_intake(_claimed(_record(PAYLOAD))))
    store.race_once = True
    duplicate, event_id = asyncio.run(sync.persist_intake(_claimed(_record(PAYLOAD))))
    assert duplicate is True
    assert event_id == store.rows["TEST_SYN_EVENT_1"].id
    assert len(store.rows) == 1


def test_intake_row_is_shaped_for_saga_enrollment(monkeypatch, store):
    asyncio.run(sync.persist_intake(_claimed(_record(PAYLOAD))))
    row = store.rows["TEST_SYN_EVENT_1"]
    assert row.source_system == "odoo"
    assert row.state == "accepted"
    assert row.event_type == "campaign.provision.requested.v1"
    assert row.entity_key == "odoo:campaign:TEST_SYN"
    assert row.payload_json == PAYLOAD
    # Acknowledgement proves durable intake only; nothing here marks completion.
    assert not hasattr(row, "completed_at") or row.__dict__.get("completed_at") is None
