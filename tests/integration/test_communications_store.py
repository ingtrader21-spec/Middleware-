from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

from app.communications import (
    CommunicationMessage,
    CommunicationsConflict,
    PostgresCommunicationsStore,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUNTIME_INTEGRATION_TESTS") != "1",
    reason="requires disposable PostgreSQL",
)


@pytest_asyncio.fixture(autouse=True)
async def migrated_schema() -> None:
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"], min_size=1, max_size=2)
    try:
        async with pool.acquire() as conn:
            for path in sorted(Path("migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")):
                await conn.execute(path.read_text(encoding="utf-8"))
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_communication_projection_survives_restart() -> None:
    database_url = os.environ["DATABASE_URL"]
    tenant_id = f"tenant-communications-{uuid.uuid4()}"
    message_id = uuid.uuid4()
    now = datetime.now(UTC)
    store = await PostgresCommunicationsStore.connect(database_url)
    store.messages[(tenant_id, message_id)] = CommunicationMessage(
        messageId=message_id,
        tenantId=tenant_id,
        channel="email",
        direction="outbound",
        status="queued",
        correlationId="correlation-restart",
        idempotencyKey="idempotency-restart",
        provider="klyrow",
        createdAt=now,
        updatedAt=now,
    )
    store.add_event(
        tenant_id,
        message_id,
        event_type="queued",
        status="queued",
        provider="klyrow",
    )
    await store.persist()
    await store.close()

    reopened = await PostgresCommunicationsStore.connect(database_url)
    try:
        await reopened.load_tenant(tenant_id)
        assert reopened.messages[(tenant_id, message_id)].status == "queued"
        assert [event.type for event in reopened.events[(tenant_id, message_id)]] == [
            "queued"
        ]
    finally:
        await reopened.close()


@pytest.mark.asyncio
async def test_stale_worker_cannot_overwrite_newer_projection() -> None:
    database_url = os.environ["DATABASE_URL"]
    tenant_id = f"tenant-concurrency-{uuid.uuid4()}"
    message_id = uuid.uuid4()
    now = datetime.now(UTC)
    writer = await PostgresCommunicationsStore.connect(database_url)
    stale: PostgresCommunicationsStore | None = None
    try:
        writer.messages[(tenant_id, message_id)] = CommunicationMessage(
            messageId=message_id,
            tenantId=tenant_id,
            channel="sms",
            direction="outbound",
            status="queued",
            correlationId="correlation-concurrency",
            idempotencyKey="idempotency-concurrency",
            provider="telnexa",
            createdAt=now,
            updatedAt=now,
        )
        await writer.persist()
        stale = await PostgresCommunicationsStore.connect(database_url)
        await stale.load_tenant(tenant_id)

        writer.messages[(tenant_id, message_id)] = writer.messages[
            (tenant_id, message_id)
        ].model_copy(
            update={
                "status": "delivered",
                "completedAt": now + timedelta(seconds=1),
                "updatedAt": now + timedelta(seconds=1),
            }
        )
        await writer.persist()

        unrelated_id = uuid.uuid4()
        stale.messages[(tenant_id, unrelated_id)] = CommunicationMessage(
            messageId=unrelated_id,
            tenantId=tenant_id,
            channel="email",
            direction="outbound",
            status="queued",
            correlationId="correlation-unrelated",
            idempotencyKey="idempotency-unrelated",
            provider="klyrow",
            createdAt=now,
            updatedAt=now,
        )
        await stale.persist()

        async with stale.pool.acquire() as connection:
            durable_payload = await connection.fetchval(
                "SELECT payload FROM middleware_communication_messages "
                "WHERE tenant_id=$1 AND message_id=$2",
                tenant_id,
                message_id,
            )
        durable = (
            CommunicationMessage.model_validate_json(durable_payload)
            if isinstance(durable_payload, str)
            else CommunicationMessage.model_validate(durable_payload)
        )
        assert durable.status == "delivered"

        stale.messages[(tenant_id, message_id)] = stale.messages[
            (tenant_id, message_id)
        ].model_copy(
            update={
                "status": "dispatched",
                "updatedAt": now + timedelta(seconds=2),
            }
        )
        with pytest.raises(CommunicationsConflict):
            await stale.persist()
        assert stale.messages[(tenant_id, message_id)].status == "delivered"
    finally:
        await writer.close()
        if stale is not None:
            await stale.close()


@pytest.mark.asyncio
async def test_inflight_local_mutation_keeps_its_pre_callback_version() -> None:
    database_url = os.environ["DATABASE_URL"]
    tenant_id = f"tenant-local-race-{uuid.uuid4()}"
    message_id = uuid.uuid4()
    now = datetime.now(UTC)
    store = await PostgresCommunicationsStore.connect(database_url)
    try:
        store.messages[(tenant_id, message_id)] = CommunicationMessage(
            messageId=message_id,
            tenantId=tenant_id,
            channel="sms",
            direction="outbound",
            status="queued",
            correlationId="correlation-local-race",
            idempotencyKey="idempotency-local-race",
            provider="telnexa",
            createdAt=now,
            updatedAt=now,
        )
        await store.persist()

        # A request captures the queued value before an awaited command
        # operation.  While it is suspended, the callback commits delivery
        # and refreshes this process's cache.
        captured = store.messages[(tenant_id, message_id)]
        stale_cancel = captured.model_copy(
            update={
                "status": "cancelled",
                "completedAt": now + timedelta(seconds=2),
                "updatedAt": now + timedelta(seconds=2),
            }
        )
        delivered = captured.model_copy(
            update={
                "status": "delivered",
                "completedAt": now + timedelta(seconds=1),
                "updatedAt": now + timedelta(seconds=1),
            }
        )
        async with store.pool.acquire() as connection:
            await connection.execute(
                "UPDATE middleware_communication_messages "
                "SET payload=$3::jsonb,updated_at=$4 "
                "WHERE tenant_id=$1 AND message_id=$2",
                tenant_id,
                message_id,
                delivered.model_dump_json(),
                delivered.updatedAt,
            )
        store.synchronize_durable_message(delivered)

        # The suspended request resumes with its old-derived value.  Its
        # object-bound durable version must still be the queued version even
        # though the process cache has observed delivery.
        store.messages[(tenant_id, message_id)] = stale_cancel
        with pytest.raises(CommunicationsConflict):
            await store.persist()

        assert store.messages[(tenant_id, message_id)].status == "delivered"
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_communication_event_ledger_is_immutable() -> None:
    store = await PostgresCommunicationsStore.connect(os.environ["DATABASE_URL"])
    try:
        with pytest.raises(Exception, match="append-only"):
            await store.pool.execute("DELETE FROM middleware_communication_events")
    finally:
        await store.close()
