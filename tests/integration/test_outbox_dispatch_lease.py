from __future__ import annotations

import os
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

from app.storage import PostgresOutboxStore, ReconciliationError


DATABASE_URL = os.getenv("DATABASE_URL", "")
RUN = os.getenv("RUNTIME_INTEGRATION_TESTS") == "1"

pytestmark = pytest.mark.skipif(
    not RUN,
    reason="set RUNTIME_INTEGRATION_TESTS=1 against disposable PostgreSQL/Redis",
)


@pytest_asyncio.fixture
async def pool() -> asyncpg.Pool:
    assert DATABASE_URL, "DATABASE_URL is required"
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=4)
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


async def insert_and_quarantine(pool: asyncpg.Pool, *, key: str, worker_id: str) -> tuple[PostgresOutboxStore, int]:
    async with pool.acquire() as conn:
        row_id = await conn.fetchval(
            """
            INSERT INTO middleware_outbox
              (tenant_id, destination, event_type, payload, idempotency_key)
            VALUES ('tenant-test','sandbox-provider','codestra.test.delivery','{}'::jsonb,$1)
            RETURNING id
            """,
            key,
        )

    store = PostgresOutboxStore(pool)
    claimed = await store.claim(
        worker_id=worker_id,
        lease_seconds=1,
        max_attempts=3,
    )
    assert claimed is not None and claimed.id == row_id
    await store.quarantine_unknown_outcome(
        row_id,
        worker_id=worker_id,
        error="dispatch reserved immediately before provider invocation",
        lease_seconds=30,
    )
    return store, row_id


@pytest.mark.asyncio
async def test_pre_dispatch_quarantine_refreshes_full_lease_atomically(
    pool: asyncpg.Pool,
) -> None:
    store, row_id = await insert_and_quarantine(
        pool,
        key="delivery-refresh-lease",
        worker_id="worker-refresh",
    )

    async with pool.acquire() as conn:
        state = await conn.fetchrow(
            """
            SELECT reconciliation_required_at IS NOT NULL AS reconciliation_required,
                   lease_owner,
                   extract(epoch FROM (lease_until - now())) AS remaining_seconds
            FROM middleware_outbox
            WHERE id=$1
            """,
            row_id,
        )

    assert state["reconciliation_required"] is True
    assert state["lease_owner"] == "worker-refresh"
    assert float(state["remaining_seconds"]) > 20.0

    with pytest.raises(ReconciliationError, match="cannot be manually reconciled"):
        await store.resolve_reconciliation(
            row_id,
            operator_id="ops:test",
            action="retry",
            reason="manual retry must be blocked during refreshed active dispatch",
            max_attempts=3,
        )

    assert await store.claim(
        worker_id="worker-other",
        lease_seconds=30,
        max_attempts=3,
    ) is None


@pytest.mark.asyncio
async def test_active_dispatch_heartbeat_renews_same_owner_from_database_time(
    pool: asyncpg.Pool,
) -> None:
    store, row_id = await insert_and_quarantine(
        pool,
        key="delivery-heartbeat-lease",
        worker_id="worker-heartbeat",
    )

    # Simulate a handler that has remained alive long enough for its prior lease
    # to be near expiry, then verify the heartbeat restores a full lease window.
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE middleware_outbox SET lease_until=now() + interval '100 milliseconds' WHERE id=$1",
            row_id,
        )

    await store.renew_active_dispatch(
        row_id,
        worker_id="worker-heartbeat",
        lease_seconds=30,
    )

    async with pool.acquire() as conn:
        state = await conn.fetchrow(
            """
            SELECT lease_owner,
                   reconciliation_required_at IS NOT NULL AS reconciliation_required,
                   extract(epoch FROM (lease_until - now())) AS remaining_seconds
            FROM middleware_outbox
            WHERE id=$1
            """,
            row_id,
        )

    assert state["lease_owner"] == "worker-heartbeat"
    assert state["reconciliation_required"] is True
    assert float(state["remaining_seconds"]) > 20.0

    assert await store.claim(
        worker_id="worker-other",
        lease_seconds=30,
        max_attempts=3,
    ) is None
