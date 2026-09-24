from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.models import EventEnvelope
from app.storage import (
    EventLedgerIntegrityError,
    EventLedgerRecord,
    MemoryInboxStore,
    PostgresInboxStore,
    ReplayConflict,
    ZERO_LEDGER_HASH,
    canonical_payload_sha256,
    event_ledger_hash,
    verify_event_ledger_records,
)


def envelope(*, event_id: str, idempotency_key: str, value: int = 1) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        event_type="codestra.test.event",
        event_version="1.0",
        occurred_at=datetime.now(timezone.utc),
        received_at=datetime.now(timezone.utc),
        source="test-source",
        tenant_id="tenant-test",
        correlation_id="corr-1",
        causation_id="cause-1",
        idempotency_key=idempotency_key,
        payload={"value": value},
        metadata={},
    )


def semantic_digest(item: EventEnvelope) -> str:
    return canonical_payload_sha256(item.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_memory_store_enforces_tenant_idempotency_uniqueness() -> None:
    store = MemoryInboxStore()
    first = envelope(event_id="evt-1", idempotency_key="idem-shared")
    second = envelope(event_id="evt-2", idempotency_key="idem-shared")

    accepted = await store.accept(
        first,
        producer_client_id="test-source",
        body_sha256="a" * 64,
        semantic_sha256=semantic_digest(first),
    )
    assert accepted.status == "accepted"

    with pytest.raises(ReplayConflict):
        await store.accept(
            second,
            producer_client_id="test-source",
            body_sha256="b" * 64,
            semantic_sha256=semantic_digest(second),
        )


@pytest.mark.asyncio
async def test_memory_store_same_idempotency_same_semantics_is_duplicate() -> None:
    store = MemoryInboxStore()
    first = envelope(event_id="evt-1", idempotency_key="idem-shared")

    accepted = await store.accept(
        first,
        producer_client_id="test-source",
        body_sha256="a" * 64,
        semantic_sha256=semantic_digest(first),
    )
    duplicate = await store.accept(
        first,
        producer_client_id="test-source",
        body_sha256="b" * 64,
        semantic_sha256=semantic_digest(first),
    )

    assert accepted.status == "accepted"
    assert duplicate.status == "duplicate"
    assert duplicate.duplicate is True
    assert len(store.ledger_records) == 1
    assert verify_event_ledger_records(store.ledger_records) == {"tenant-test": 1}


def test_event_ledger_hash_chain_detects_payload_and_link_tampering() -> None:
    payload_one = envelope(
        event_id="evt-ledger-1",
        idempotency_key="idem-ledger-1",
    ).model_dump(mode="json")
    semantic_one = canonical_payload_sha256(payload_one)
    hash_one = event_ledger_hash(
        tenant_id="tenant-test",
        tenant_sequence=1,
        event_id="evt-ledger-1",
        semantic_sha256=semantic_one,
        previous_entry_hash=ZERO_LEDGER_HASH,
    )
    payload_two = envelope(
        event_id="evt-ledger-2",
        idempotency_key="idem-ledger-2",
    ).model_dump(mode="json")
    semantic_two = canonical_payload_sha256(payload_two)
    hash_two = event_ledger_hash(
        tenant_id="tenant-test",
        tenant_sequence=2,
        event_id="evt-ledger-2",
        semantic_sha256=semantic_two,
        previous_entry_hash=hash_one,
    )
    records = [
        EventLedgerRecord(
            "tenant-test",
            1,
            "evt-ledger-1",
            semantic_one,
            ZERO_LEDGER_HASH,
            hash_one,
            payload_one,
        ),
        EventLedgerRecord(
            "tenant-test",
            2,
            "evt-ledger-2",
            semantic_two,
            hash_one,
            hash_two,
            payload_two,
        ),
    ]
    assert verify_event_ledger_records(records) == {"tenant-test": 2}

    tampered = [
        records[0],
        replace(
            records[1],
            payload={**payload_two, "payload": {"value": 999}},
        ),
    ]
    with pytest.raises(EventLedgerIntegrityError, match="payload hash mismatch"):
        verify_event_ledger_records(tampered)

    broken_link = [
        records[0],
        replace(
            records[1],
            previous_entry_hash=ZERO_LEDGER_HASH,
        ),
    ]
    with pytest.raises(EventLedgerIntegrityError, match="previous hash mismatch"):
        verify_event_ledger_records(broken_link)


def test_readiness_declares_type_for_every_required_column() -> None:
    required = {
        (table, column)
        for table, columns in PostgresInboxStore.REQUIRED_COLUMNS.items()
        for column in columns
    }
    assert set(PostgresInboxStore.REQUIRED_UDT_TYPES) == required
