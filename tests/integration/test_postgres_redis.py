from __future__ import annotations

from collections.abc import AsyncIterator

import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.commands import (
    CommandConflict,
    CommandEnvelope,
    PostgresCommandStore,
    command_digest,
)
from app.models import EventEnvelope
from app.replay import RedisReplayGuard, ReplayBusy
from app.storage import (
    KLYROW_ODOO_PROJECTION_DESTINATION,
    PostgresInboxStore,
    PostgresOutboxStore,
    ReconciliationError,
    ReplayConflict,
)


DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL = os.getenv("REDIS_URL", "")
RUN = os.getenv("RUNTIME_INTEGRATION_TESTS") == "1"

pytestmark = pytest.mark.skipif(
    not RUN,
    reason="set RUNTIME_INTEGRATION_TESTS=1 against disposable PostgreSQL/Redis",
)


def envelope(
    *,
    event_id: str = "evt-1",
    idempotency_key: str = "idem-0001",
    value: int = 1,
) -> EventEnvelope:
    now = datetime.now(timezone.utc)
    return EventEnvelope(
        event_id=event_id,
        event_type="codestra.odoo.contact_updated",
        event_version="1.0",
        occurred_at=now,
        received_at=now,
        source="odoo-integration",
        tenant_id="tenant-test",
        correlation_id="corr-1",
        causation_id="cause-1",
        idempotency_key=idempotency_key,
        payload={"value": value},
        metadata={},
    )


def semantic_digest(item: EventEnvelope) -> str:
    payload = item.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@pytest_asyncio.fixture
async def pool() -> asyncpg.Pool:
    assert DATABASE_URL, "DATABASE_URL is required"
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=8)
    migrations = [
        path.read_text(encoding="utf-8")
        for path in sorted(Path("migrations").glob("[0-9][0-9][0-9][0-9]_*.sql"))
    ]
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS middleware_outbox_attempt_events CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_control_mutations CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_control_audit CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_operation_mutations CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_event_ledger CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_reconciliation_audit CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_outbox CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_inbox CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_schema_migrations CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_command_audit CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_command_attempts CASCADE")
        await conn.execute("DROP TABLE IF EXISTS middleware_commands CASCADE")
        for migration in migrations:
            await conn.execute(migration)
    try:
        yield pool
    finally:
        await pool.close()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[Redis]:
    assert REDIS_URL, "REDIS_URL is required"
    client = Redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


@pytest.mark.asyncio
async def test_postgres_schema_and_duplicate_reconciliation(pool: asyncpg.Pool) -> None:
    store = PostgresInboxStore(pool)
    await store.verify_schema()

    item = envelope()
    digest = semantic_digest(item)
    first = await store.accept(
        item,
        producer_client_id="odoo-integration",
        body_sha256="a" * 64,
        semantic_sha256=digest,
    )
    second = await store.accept(
        item,
        producer_client_id="odoo-integration",
        body_sha256="b" * 64,
        semantic_sha256=digest,
    )

    assert first.status == "accepted"
    assert second.status == "duplicate"
    assert second.duplicate is True
    async with pool.acquire() as conn:
        outbox = await conn.fetchrow(
            """
            SELECT destination, event_type, idempotency_key, payload
              FROM middleware_outbox
             WHERE tenant_id=$1 AND idempotency_key=$2
            """,
            item.tenant_id,
            item.idempotency_key,
        )
    assert outbox is not None
    assert outbox["destination"] == "nats-jetstream"
    assert outbox["event_type"] == item.event_type
    raw_payload = outbox["payload"]
    payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
    assert payload["event_id"] == item.event_id
    assert await store.verify_event_ledger(item.tenant_id) == {
        item.tenant_id: 1
    }
    async with pool.acquire() as conn:
        ledger = await conn.fetchrow(
            """
            SELECT tenant_sequence, event_id, previous_entry_hash, entry_hash
            FROM middleware_event_ledger
            WHERE tenant_id=$1
            """,
            item.tenant_id,
        )
    assert ledger["tenant_sequence"] == 1
    assert ledger["event_id"] == item.event_id
    assert ledger["previous_entry_hash"] == "0" * 64
    assert len(ledger["entry_hash"]) == 64


@pytest.mark.asyncio
async def test_event_ledger_is_hash_chained_and_database_immutable(
    pool: asyncpg.Pool,
) -> None:
    store = PostgresInboxStore(pool)
    first = envelope(
        event_id="evt-ledger-db-1",
        idempotency_key="idem-ledger-db-1",
    )
    second = envelope(
        event_id="evt-ledger-db-2",
        idempotency_key="idem-ledger-db-2",
        value=2,
    )
    for item in (first, second):
        await store.accept(
            item,
            producer_client_id="odoo-integration",
            body_sha256="a" * 64,
            semantic_sha256=semantic_digest(item),
        )

    assert await store.verify_event_ledger("tenant-test") == {"tenant-test": 2}
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT tenant_sequence, previous_entry_hash, entry_hash
            FROM middleware_event_ledger
            WHERE tenant_id='tenant-test'
            ORDER BY tenant_sequence
            """
        )
        assert rows[1]["previous_entry_hash"] == rows[0]["entry_hash"]
        with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError):
            await conn.execute(
                "UPDATE middleware_event_ledger SET event_type='tampered'"
            )
        with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError):
            await conn.execute(
                "DELETE FROM middleware_event_ledger WHERE tenant_id='tenant-test'"
            )
        with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError):
            await conn.execute("TRUNCATE middleware_event_ledger")
        remaining = await conn.fetchval(
            "SELECT count(*) FROM middleware_event_ledger"
        )
    assert remaining == 2


@pytest.mark.asyncio
async def test_postgres_concurrent_same_event_is_single_accept(pool: asyncpg.Pool) -> None:
    store = PostgresInboxStore(pool)
    item = envelope(event_id="evt-concurrent", idempotency_key="idem-concurrent")
    digest = semantic_digest(item)

    async def accept_once() -> str:
        result = await store.accept(
            item,
            producer_client_id="odoo-integration",
            body_sha256="c" * 64,
            semantic_sha256=digest,
        )
        return result.status

    statuses = await asyncio.gather(accept_once(), accept_once())
    assert sorted(statuses) == ["accepted", "duplicate"]

    async with pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT count(*) FROM middleware_inbox WHERE tenant_id=$1 AND event_id=$2",
            item.tenant_id,
            item.event_id,
        )
    assert count == 1


@pytest.mark.asyncio
async def test_postgres_concurrent_klyrow_raw_replay_records_one_projection(
    pool: asyncpg.Pool,
) -> None:
    store = PostgresInboxStore(pool)
    first = envelope(
        event_id="evt-klyrow-race",
        idempotency_key="evt-klyrow-race",
    ).model_copy(
        update={
            "event_type": "codestra.klyrow.usage.daily",
            "source": "klyrow-gateway",
        }
    )
    second = first.model_copy(
        update={"received_at": first.received_at + timedelta(seconds=1)}
    )
    body_hash = "a" * 64

    async def accept_once(item: EventEnvelope) -> str:
        result = await store.accept(
            item,
            producer_client_id="klyrow-gateway",
            body_sha256=body_hash,
            semantic_sha256=semantic_digest(item),
            deduplication_sha256=body_hash,
            destination=KLYROW_ODOO_PROJECTION_DESTINATION,
        )
        return result.status

    statuses = await asyncio.gather(accept_once(first), accept_once(second))
    assert sorted(statuses) == ["accepted", "duplicate"]

    async with pool.acquire() as conn:
        inbox_count = await conn.fetchval(
            "SELECT count(*) FROM middleware_inbox WHERE tenant_id=$1 AND event_id=$2",
            first.tenant_id,
            first.event_id,
        )
        projection_count = await conn.fetchval(
            "SELECT count(*) FROM middleware_outbox "
            "WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3",
            first.tenant_id,
            KLYROW_ODOO_PROJECTION_DESTINATION,
            first.idempotency_key,
        )
    assert inbox_count == 1
    assert projection_count == 1


@pytest.mark.asyncio
async def test_postgres_klyrow_replay_repairs_deliberately_missing_projection(
    pool: asyncpg.Pool,
) -> None:
    store = PostgresInboxStore(pool)
    first = envelope(
        event_id="evt-klyrow-repair",
        idempotency_key="evt-klyrow-repair",
    ).model_copy(
        update={
            "event_type": "codestra.klyrow.usage.daily",
            "source": "klyrow-gateway",
        }
    )
    body_hash = "b" * 64
    accepted = await store.accept(
        first,
        producer_client_id="klyrow-gateway",
        body_sha256=body_hash,
        semantic_sha256=semantic_digest(first),
        deduplication_sha256=body_hash,
        destination=KLYROW_ODOO_PROJECTION_DESTINATION,
    )
    assert accepted.status == "accepted"

    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM middleware_outbox "
            "WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3",
            first.tenant_id,
            KLYROW_ODOO_PROJECTION_DESTINATION,
            first.idempotency_key,
        )

    replay = first.model_copy(
        update={"received_at": first.received_at + timedelta(seconds=1)}
    )
    duplicate = await store.accept(
        replay,
        producer_client_id="klyrow-gateway",
        body_sha256=body_hash,
        semantic_sha256=semantic_digest(replay),
        deduplication_sha256=body_hash,
        destination=KLYROW_ODOO_PROJECTION_DESTINATION,
    )
    assert duplicate.status == "duplicate"

    async with pool.acquire() as conn:
        repaired = await conn.fetchrow(
            "SELECT event_type,payload FROM middleware_outbox "
            "WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3",
            first.tenant_id,
            KLYROW_ODOO_PROJECTION_DESTINATION,
            first.idempotency_key,
        )
    assert repaired is not None
    assert repaired["event_type"] == first.event_type
    repaired_payload = (
        json.loads(repaired["payload"])
        if isinstance(repaired["payload"], str)
        else dict(repaired["payload"])
    )
    assert repaired_payload["received_at"] == first.model_dump(
        mode="json"
    )["received_at"]


@pytest.mark.asyncio
async def test_concurrent_distinct_events_form_one_gapless_tenant_chain(
    pool: asyncpg.Pool,
) -> None:
    store = PostgresInboxStore(pool)
    items = [
        envelope(
            event_id=f"evt-chain-{index}",
            idempotency_key=f"idem-chain-{index}",
            value=index,
        )
        for index in range(1, 9)
    ]

    async def accept_once(item: EventEnvelope) -> None:
        await store.accept(
            item,
            producer_client_id="odoo-integration",
            body_sha256="c" * 64,
            semantic_sha256=semantic_digest(item),
        )

    await asyncio.gather(*(accept_once(item) for item in items))
    assert await store.verify_event_ledger("tenant-test") == {"tenant-test": 8}
    async with pool.acquire() as conn:
        sequences = await conn.fetch(
            """
            SELECT tenant_sequence FROM middleware_event_ledger
            WHERE tenant_id='tenant-test' ORDER BY tenant_sequence
            """
        )
    assert [row["tenant_sequence"] for row in sequences] == list(range(1, 9))


@pytest.mark.asyncio
async def test_postgres_semantic_collision_fails_closed(pool: asyncpg.Pool) -> None:
    store = PostgresInboxStore(pool)
    first = envelope(event_id="evt-semantic", idempotency_key="idem-semantic", value=1)
    second = envelope(event_id="evt-semantic", idempotency_key="idem-semantic", value=2)

    await store.accept(
        first,
        producer_client_id="odoo-integration",
        body_sha256="d" * 64,
        semantic_sha256=semantic_digest(first),
    )
    with pytest.raises(ReplayConflict):
        await store.accept(
            second,
            producer_client_id="odoo-integration",
            body_sha256="e" * 64,
            semantic_sha256=semantic_digest(second),
        )


@pytest.mark.asyncio
async def test_postgres_idempotency_key_collision_fails_closed(pool: asyncpg.Pool) -> None:
    store = PostgresInboxStore(pool)
    first = envelope(event_id="evt-idem-1", idempotency_key="idem-shared", value=1)
    second = envelope(event_id="evt-idem-2", idempotency_key="idem-shared", value=2)

    await store.accept(
        first,
        producer_client_id="odoo-integration",
        body_sha256="f" * 64,
        semantic_sha256=semantic_digest(first),
    )
    with pytest.raises(ReplayConflict):
        await store.accept(
            second,
            producer_client_id="odoo-integration",
            body_sha256="0" * 64,
            semantic_sha256=semantic_digest(second),
        )


@pytest.mark.asyncio
async def test_command_intent_outbox_and_audit_are_one_durable_transaction(
    pool: asyncpg.Pool,
) -> None:
    store = PostgresCommandStore(pool)
    assert await store.ready() is True
    command = CommandEnvelope.model_validate(
        {
            "command_id": "00000000-0000-4000-8000-000000000001",
            "command_type": "crm.contact.create.v1",
            "command_version": "1.0",
            "target": "odoo-19",
            "tenant_id": "tenant-test",
            "requested_by": "user-1",
            "correlation_id": "correlation-command-1",
            "idempotency_key": "idempotency-command-1",
            "capability": "ODOO_WRITE",
            "payload": {"contact_id": "contact-1"},
        }
    )

    accepted = await store.submit(command, authenticated_client_id="test-client")
    duplicate = await store.submit(command, authenticated_client_id="test-client")
    assert accepted.state == "persisted"
    assert duplicate.duplicate is True

    with pytest.raises(CommandConflict):
        await store.submit(
            command.model_copy(update={"payload": {"contact_id": "changed"}}),
            authenticated_client_id="test-client",
        )

    for new_state in (
        "queued",
        "dispatching",
        "accepted",
        "readback_pending",
        "completed",
    ):
        await store.transition(
            command.tenant_id,
            command.command_id,
            new_state=new_state,
            actor_id="temporal:test",
            reason=f"verified transition to {new_state}",
            provider_operation_id=(
                "provider-operation-1" if new_state == "accepted" else None
            ),
        )

    operation = await store.get(command.tenant_id, command.command_id)
    assert operation.state == "completed"
    assert operation.provider_operation_id == "provider-operation-1"

    async with pool.acquire() as conn:
        outbox_count = await conn.fetchval(
            """
            SELECT count(*) FROM middleware_outbox
            WHERE tenant_id=$1 AND destination='temporal-command'
              AND idempotency_key=$2
            """,
            command.tenant_id,
            command.idempotency_key,
        )
        audit_states = await conn.fetch(
            """
            SELECT new_state FROM middleware_command_audit
            WHERE tenant_id=$1 AND command_id=$2 ORDER BY id
            """,
            command.tenant_id,
            str(command.command_id),
        )
        authenticated_client_id = await conn.fetchval(
            """
            SELECT payload->>'_authenticated_client_id'
            FROM middleware_outbox
            WHERE tenant_id=$1 AND command_id=$2
              AND destination='temporal-command'
            """,
            command.tenant_id,
            str(command.command_id),
        )
        audit_client_id = await conn.fetchval(
            """
            SELECT metadata->>'authenticated_client_id'
            FROM middleware_command_audit
            WHERE tenant_id=$1 AND command_id=$2 AND new_state='persisted'
            """,
            command.tenant_id,
            str(command.command_id),
        )
        attempts = await conn.fetchval(
            """
            SELECT count(*) FROM middleware_command_attempts
            WHERE tenant_id=$1 AND command_id=$2
            """,
            command.tenant_id,
            str(command.command_id),
        )
    assert outbox_count == 1
    assert authenticated_client_id == "test-client"
    assert audit_client_id == "test-client"
    assert [row["new_state"] for row in audit_states] == [
        "persisted",
        "queued",
        "dispatching",
        "accepted",
        "readback_pending",
        "completed",
    ]
    assert attempts == 1


@pytest.mark.asyncio
async def test_postgres_command_retry_accepts_pre_provenance_digest(
    pool: asyncpg.Pool,
) -> None:
    store = PostgresCommandStore(pool)
    command = CommandEnvelope.model_validate(
        {
            "command_id": "00000000-0000-4000-8000-000000000091",
            "command_type": "crm.contact.create.v1",
            "command_version": "1.0",
            "target": "odoo-19",
            "tenant_id": "tenant-legacy-command",
            "requested_by": "user-legacy",
            "correlation_id": "correlation-legacy-command",
            "idempotency_key": "idempotency-legacy-command",
            "capability": "ODOO_WRITE",
            "payload": {"contact_id": "contact-legacy"},
        }
    )
    public_payload = command.model_dump(mode="json")
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO middleware_commands (
                command_id, tenant_id, command_type, command_version,
                target, requested_by, correlation_id, idempotency_key,
                capability, payload, payload_sha256, state
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,'persisted')
            """,
            str(command.command_id),
            command.tenant_id,
            command.command_type,
            command.command_version,
            command.target,
            command.requested_by,
            command.correlation_id,
            command.idempotency_key,
            command.capability,
            json.dumps(public_payload, separators=(",", ":"), sort_keys=True),
            command_digest(command),
        )

    duplicate = await store.submit(
        command,
        authenticated_client_id="post-upgrade-client",
    )

    assert duplicate.duplicate is True
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            """
            SELECT payload ? '_authenticated_client_id'
            FROM middleware_commands
            WHERE tenant_id=$1 AND command_id=$2
            """,
            command.tenant_id,
            str(command.command_id),
        ) is False


@pytest.mark.asyncio
async def test_postgres_operation_reads_and_cancel_are_tenant_isolated_and_atomic(pool: asyncpg.Pool) -> None:
    store = PostgresCommandStore(pool)
    command = CommandEnvelope.model_validate({
        "command_id": "00000000-0000-4000-8000-000000000002",
        "command_type": "crm.contact.create.v1", "command_version": "1.0",
        "target": "odoo-19", "tenant_id": "tenant-operation", "requested_by": "user-1",
        "correlation_id": "correlation-operation-2", "idempotency_key": "test-idem-2",
        "capability": "ODOO_WRITE", "payload": {"contact_id": "contact-2"},
    })
    await store.submit(command, authenticated_client_id="test-client")
    assert len(await store.list_operations("tenant-operation", limit=2)) == 1
    assert await store.list_operations("another-tenant", limit=2) == []
    events = await store.list_events("tenant-operation", command.command_id, limit=2)
    assert [event.new_state for event in events] == ["persisted"]
    cancelled = await store.mutate_operation("tenant-operation", command.command_id, action="cancel", actor_id="user-1", idempotency_key="cancel-mutation-2", expected_version=1, reason="operator_requested")
    assert cancelled.state == "cancelled" and cancelled.resource_version == 2
    replay = await store.mutate_operation("tenant-operation", command.command_id, action="cancel", actor_id="user-1", idempotency_key="cancel-mutation-2", expected_version=1, reason="operator_requested")
    assert replay.duplicate is True
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT cancelled_at IS NOT NULL FROM middleware_outbox WHERE tenant_id=$1 AND command_id=$2", "tenant-operation", str(command.command_id)) is True
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("DELETE FROM middleware_operation_mutations WHERE tenant_id=$1", "tenant-operation")


@pytest.mark.asyncio
async def test_postgres_operation_retry_enqueues_dispatchable_command_envelope(pool: asyncpg.Pool) -> None:
    store = PostgresCommandStore(pool)
    command = CommandEnvelope.model_validate({
        "command_id": "00000000-0000-4000-8000-000000000003",
        "command_type": "crm.contact.create.v1", "command_version": "1.0",
        "target": "odoo-19", "tenant_id": "tenant-operation-retry", "requested_by": "user-1",
        "correlation_id": "correlation-operation-3", "idempotency_key": "test-idem-3",
        "capability": "ODOO_WRITE", "payload": {"contact_id": "contact-3"},
    })
    await store.submit(command, authenticated_client_id="test-client")
    for state in ("queued", "dispatching", "failed"):
        await store.transition(
            command.tenant_id,
            command.command_id,
            new_state=state,
            actor_id="temporal:test",
            reason=f"verified transition to {state}",
        )

    retried = await store.mutate_operation(
        command.tenant_id,
        command.command_id,
        action="retry",
        actor_id="user-1",
        idempotency_key="retry-mutation-3",
        expected_version=1,
        reason="known_safe_failure",
    )
    assert retried.state == "queued" and retried.resource_version == 2
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT event_type,payload,idempotency_key FROM middleware_outbox
               WHERE tenant_id=$1 AND command_id=$2 AND idempotency_key LIKE 'operation-retry:%'""",
            command.tenant_id,
            str(command.command_id),
        )
    assert row is not None and row["event_type"] == command.command_type
    retry_payload = json.loads(row["payload"])
    assert retry_payload.pop("_authenticated_client_id") == "test-client"
    retry_envelope = CommandEnvelope.model_validate(retry_payload)
    assert retry_envelope.command_id == command.command_id
    assert retry_envelope.idempotency_key == row["idempotency_key"]
    assert retry_envelope.payload == command.payload


async def insert_outbox(pool: asyncpg.Pool, idempotency_key: str) -> int:
    async with pool.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO middleware_outbox
              (tenant_id, destination, event_type, payload, idempotency_key)
            VALUES ($1,$2,$3,$4::jsonb,$5)
            RETURNING id
            """,
            "tenant-test",
            "sandbox-provider",
            "codestra.test.delivery",
            json.dumps({"hello": "world"}),
            idempotency_key,
        )


async def quarantine_record(
    pool: asyncpg.Pool,
    *,
    idempotency_key: str,
    worker_id: str,
    expire_lease: bool = False,
) -> tuple[PostgresOutboxStore, int]:
    row_id = await insert_outbox(pool, idempotency_key)
    store = PostgresOutboxStore(pool)
    claimed = await store.claim(worker_id=worker_id, lease_seconds=30, max_attempts=3)
    assert claimed is not None and claimed.id == row_id
    await store.quarantine_unknown_outcome(
        row_id,
        worker_id=worker_id,
        error="provider dispatch reserved; outcome unknown until handler resolves",
    )
    if expire_lease:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE middleware_outbox SET lease_until=now() - interval '1 second' WHERE id=$1",
                row_id,
            )
    return store, row_id


@pytest.mark.asyncio
async def test_outbox_claim_carries_idempotency_and_skip_locked(pool: asyncpg.Pool) -> None:
    await insert_outbox(pool, "delivery-idem-1")

    store = PostgresOutboxStore(pool)
    one, two = await asyncio.gather(
        store.claim(worker_id="worker-a", lease_seconds=30, max_attempts=3),
        store.claim(worker_id="worker-b", lease_seconds=30, max_attempts=3),
    )
    claimed = [record for record in (one, two) if record is not None]
    assert len(claimed) == 1
    assert claimed[0].idempotency_key == "delivery-idem-1"
    assert claimed[0].attempt_count == 1
    owner="worker-a" if one is not None else "worker-b"
    await store.complete(claimed[0].id,worker_id=owner)
    async with pool.acquire() as conn:
        events=await conn.fetch("SELECT event_type,attempt_number FROM middleware_outbox_attempt_events WHERE outbox_id=$1 ORDER BY id",claimed[0].id)
        assert [(row["event_type"],row["attempt_number"]) for row in events]==[("claimed",1),("completed",1)]
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("DELETE FROM middleware_outbox_attempt_events WHERE outbox_id=$1",claimed[0].id)


@pytest.mark.asyncio
async def test_outbox_expired_max_attempts_moves_to_dlq(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        row_id = await conn.fetchval(
            """
            INSERT INTO middleware_outbox
              (tenant_id, destination, event_type, payload, idempotency_key,
               attempt_count, lease_owner, lease_until)
            VALUES ($1,$2,$3,$4::jsonb,$5,3,'dead-worker',now() - interval '1 second')
            RETURNING id
            """,
            "tenant-test",
            "sandbox-provider",
            "codestra.test.delivery",
            json.dumps({"hello": "world"}),
            "delivery-idem-exhausted",
        )

    store = PostgresOutboxStore(pool)
    record = await store.claim(worker_id="worker-new", lease_seconds=30, max_attempts=3)
    assert record is None

    async with pool.acquire() as conn:
        dead_lettered = await conn.fetchval(
            "SELECT dead_lettered_at IS NOT NULL FROM middleware_outbox WHERE id=$1",
            row_id,
        )
    assert dead_lettered is True


@pytest.mark.asyncio
async def test_reconciliation_required_row_keeps_live_lease_and_is_never_claimed(
    pool: asyncpg.Pool,
) -> None:
    store, row_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-unknown",
        worker_id="worker-timeout",
    )

    assert await store.claim(worker_id="worker-retry", lease_seconds=30, max_attempts=3) is None
    async with pool.acquire() as conn:
        state = await conn.fetchrow(
            """
            SELECT reconciliation_required_at IS NOT NULL AS reconciliation_required,
                   lease_owner, lease_until > now() AS lease_active,
                   completed_at, dead_lettered_at
            FROM middleware_outbox WHERE id=$1
            """,
            row_id,
        )
    assert state["reconciliation_required"] is True
    assert state["lease_owner"] == "worker-timeout"
    assert state["lease_active"] is True
    assert state["completed_at"] is None
    assert state["dead_lettered_at"] is None


@pytest.mark.asyncio
async def test_active_dispatch_blocks_manual_and_wrong_worker_reconciliation(
    pool: asyncpg.Pool,
) -> None:
    store, row_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-active-block",
        worker_id="worker-owner",
    )

    with pytest.raises(ReconciliationError, match="cannot be manually reconciled"):
        await store.resolve_reconciliation(
            row_id,
            operator_id="ops:test",
            action="retry",
            reason="operator must wait for active dispatch lease to expire",
            max_attempts=3,
        )

    with pytest.raises(ReconciliationError, match="owned by another worker"):
        await store.resolve_reconciliation(
            row_id,
            operator_id="worker:worker-other",
            action="complete",
            reason="wrong worker must not resolve active dispatch",
            max_attempts=3,
            worker_id="worker-other",
        )


@pytest.mark.asyncio
async def test_active_dispatch_owner_can_resolve_complete_and_retry(pool: asyncpg.Pool) -> None:
    complete_store, complete_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-active-complete",
        worker_id="worker-complete",
    )
    await complete_store.resolve_reconciliation(
        complete_id,
        operator_id="worker:worker-complete",
        action="complete",
        reason="provider handler returned success",
        max_attempts=3,
        worker_id="worker-complete",
    )

    retry_store, retry_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-active-retry",
        worker_id="worker-safe-retry",
    )
    await retry_store.resolve_reconciliation(
        retry_id,
        operator_id="worker:worker-safe-retry",
        action="retry",
        reason="provider rejected before any external write",
        max_attempts=3,
        worker_id="worker-safe-retry",
    )

    reclaimed = await retry_store.claim(
        worker_id="worker-after-safe-retry",
        lease_seconds=30,
        max_attempts=3,
    )
    assert reclaimed is not None and reclaimed.id == retry_id

    async with pool.acquire() as conn:
        completed = await conn.fetchval(
            "SELECT completed_at IS NOT NULL FROM middleware_outbox WHERE id=$1",
            complete_id,
        )
        actions = await conn.fetch(
            "SELECT outbox_id, action FROM middleware_reconciliation_audit WHERE outbox_id=ANY($1::bigint[])",
            [complete_id, retry_id],
        )
    assert completed is True
    assert {(row["outbox_id"], row["action"]) for row in actions} == {
        (complete_id, "complete"),
        (retry_id, "retry"),
    }


@pytest.mark.asyncio
async def test_expired_active_dispatch_becomes_manually_reconcilable(pool: asyncpg.Pool) -> None:
    store, row_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-expired-manual",
        worker_id="worker-crashed",
        expire_lease=True,
    )
    await store.resolve_reconciliation(
        row_id,
        operator_id="ops:test",
        action="complete",
        reason="operator verified provider delivery after worker lease expired",
        max_attempts=3,
    )

    async with pool.acquire() as conn:
        state = await conn.fetchrow(
            "SELECT completed_at IS NOT NULL AS completed, lease_owner, lease_until FROM middleware_outbox WHERE id=$1",
            row_id,
        )
    assert state["completed"] is True
    assert state["lease_owner"] is None
    assert state["lease_until"] is None


@pytest.mark.asyncio
async def test_reconciliation_retry_is_audited_and_releases_record(pool: asyncpg.Pool) -> None:
    store, row_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-reconcile-retry",
        worker_id="worker-timeout-retry",
        expire_lease=True,
    )
    await store.resolve_reconciliation(
        row_id,
        operator_id="ops:test",
        action="retry",
        reason="sandbox provider confirmed no external delivery",
        max_attempts=3,
    )

    claimed = await store.claim(worker_id="worker-after-review", lease_seconds=30, max_attempts=3)
    assert claimed is not None and claimed.id == row_id
    async with pool.acquire() as conn:
        audit = await conn.fetchrow(
            "SELECT action, operator_id, reason FROM middleware_reconciliation_audit WHERE outbox_id=$1",
            row_id,
        )
    assert audit["action"] == "retry"
    assert audit["operator_id"] == "ops:test"
    assert "confirmed no external delivery" in audit["reason"]


@pytest.mark.asyncio
async def test_reconciliation_complete_and_dead_letter_are_terminal_and_audited(
    pool: asyncpg.Pool,
) -> None:
    complete_store, complete_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-reconcile-complete",
        worker_id="worker-timeout-complete",
        expire_lease=True,
    )
    await complete_store.resolve_reconciliation(
        complete_id,
        operator_id="ops:test",
        action="complete",
        reason="provider reconciliation confirmed the original delivery succeeded",
    )

    dead_store, dead_id = await quarantine_record(
        pool,
        idempotency_key="delivery-idem-reconcile-dlq",
        worker_id="worker-timeout-dlq",
        expire_lease=True,
    )
    await dead_store.resolve_reconciliation(
        dead_id,
        operator_id="ops:test",
        action="dead_letter",
        reason="outcome cannot be proven safe for automatic retry",
    )

    async with pool.acquire() as conn:
        completed = await conn.fetchval(
            "SELECT completed_at IS NOT NULL FROM middleware_outbox WHERE id=$1",
            complete_id,
        )
        dead = await conn.fetchval(
            "SELECT dead_lettered_at IS NOT NULL FROM middleware_outbox WHERE id=$1",
            dead_id,
        )
        actions = await conn.fetch(
            "SELECT outbox_id, action FROM middleware_reconciliation_audit WHERE outbox_id=ANY($1::bigint[]) ORDER BY outbox_id",
            [complete_id, dead_id],
        )
    assert completed is True
    assert dead is True
    assert {(row["outbox_id"], row["action"]) for row in actions} == {
        (complete_id, "complete"),
        (dead_id, "dead_letter"),
    }


@pytest.mark.asyncio
async def test_reconciliation_retry_refuses_exhausted_attempt_limit(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        row_id = await conn.fetchval(
            """
            INSERT INTO middleware_outbox
              (tenant_id, destination, event_type, payload, idempotency_key,
               attempt_count, reconciliation_required_at)
            VALUES ($1,$2,$3,$4::jsonb,$5,3,now())
            RETURNING id
            """,
            "tenant-test",
            "sandbox-provider",
            "codestra.test.delivery",
            json.dumps({"hello": "world"}),
            "delivery-idem-reconcile-exhausted",
        )
    store = PostgresOutboxStore(pool)
    with pytest.raises(ReconciliationError):
        await store.resolve_reconciliation(
            row_id,
            operator_id="ops:test",
            action="retry",
            reason="should not bypass the attempt ceiling",
            max_attempts=3,
        )


@pytest.mark.asyncio
async def test_redis_replay_lock_owner_and_tuple_isolation(redis_client: Redis) -> None:
    guard = RedisReplayGuard(redis_client, lock_seconds=30)

    token = await guard.acquire("tenant:a", "event:b")
    with pytest.raises(ReplayBusy):
        await guard.acquire("tenant:a", "event:b")

    await guard.release("tenant:a", "event:b", "wrong-token")
    with pytest.raises(ReplayBusy):
        await guard.acquire("tenant:a", "event:b")

    other = await guard.acquire("tenant", "a:event:b")
    await guard.release("tenant", "a:event:b", other)

    await guard.release("tenant:a", "event:b", token)
    token2 = await guard.acquire("tenant:a", "event:b")
    await guard.release("tenant:a", "event:b", token2)
