import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.reliability import RetryPolicy
from app.workers.dead_letter import list_dead_letters
from app.workers.outbox import (
    acknowledge,
    claim_batch,
    queue_metrics,
    record_failure,
    recover_expired_leases,
    replay_dead_letter,
)
from app.workers.reconciliation import reconcile_internal_outbox


def test_durable_outbox_database_lifecycle():
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    asyncio.run(_scenario(database_url))


async def _scenario(database_url: str):
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    item_id = uuid4()
    recovery_id = uuid4()
    event_id = f"diag-{uuid4()}"
    correlation_id = f"corr-{uuid4()}"
    now = datetime.now(timezone.utc)
    try:
        async with factory() as session:
            # The deployed compatibility bridge intentionally RESTRICTs inbox
            # deletion. Clean the disposable CI database in dependency order;
            # do not require TRUNCATE authority from an application role.
            await session.execute(text("DELETE FROM event_model_bridge"))
            await session.execute(text("DELETE FROM outbox_event"))
            await session.execute(text("DELETE FROM event_inbox"))
            await session.execute(text("DELETE FROM reconciliation_checkpoint"))
            await session.execute(
                text("""INSERT INTO outbox_event
                    (id, topic, payload, correlation_id, status, attempts, replay_count, created_at)
                    VALUES (:id, 'test.synthetic', CAST(:payload AS jsonb), :correlation, 'pending', 0, 0, :now)"""),
                {
                    "id": item_id,
                    "payload": '{"event_id":"%s"}' % event_id,
                    "correlation": correlation_id,
                    "now": now,
                },
            )
            await session.commit()

            claimed = await claim_batch(session, limit=10, lease_seconds=30)
            assert [row["id"] for row in claimed] == [item_id]
            policy = RetryPolicy(max_attempts=2, base_seconds=1, max_seconds=2)
            assert (
                await record_failure(session, item_id, 0, "token=do-not-store", policy)
                == "retry"
            )
            await session.execute(
                text("UPDATE outbox_event SET next_attempt_at=:now WHERE id=:id"),
                {"now": now, "id": item_id},
            )
            await session.commit()
            claimed = await claim_batch(session, limit=10, lease_seconds=30)
            assert (
                await record_failure(
                    session,
                    item_id,
                    claimed[0]["attempts"],
                    "dependency unavailable",
                    policy,
                )
                == "dead_letter"
            )
            dead = await list_dead_letters(session)
            assert dead[0]["id"] == item_id and "do-not-store" not in (
                dead[0]["last_error"] or ""
            )
            assert await replay_dead_letter(session, item_id)
            claimed = await claim_batch(session, limit=10, lease_seconds=30)
            assert claimed[0]["id"] == item_id
            assert await acknowledge(session, item_id)

            await session.execute(
                text("""INSERT INTO outbox_event
                    (id, topic, payload, correlation_id, status, attempts, next_attempt_at, locked_at, replay_count, created_at)
                    VALUES (:id, 'test.recovery', '{}'::jsonb, :correlation, 'processing', 0, :expired, :expired, 0, :now)"""),
                {
                    "id": recovery_id,
                    "correlation": correlation_id,
                    "expired": now - timedelta(seconds=120),
                    "now": now,
                },
            )
            await session.execute(
                text("""INSERT INTO event_inbox
                    (id, event_id, source, event_type, payload, correlation_id, status, created_at)
                    VALUES (:id, :event_id, 'test', 'test.synthetic', '{}'::jsonb, :correlation, 'accepted', :now)"""),
                {
                    "id": uuid4(),
                    "event_id": event_id + "-missing",
                    "correlation": correlation_id,
                    "now": now,
                },
            )
            await session.commit()
            assert await recover_expired_leases(session) == 1
            reconciliation = await reconcile_internal_outbox(session)
            missing_ids = reconciliation["missing_outbox_event_ids"]
            assert isinstance(missing_ids, list)
            assert event_id + "-missing" in missing_ids
            metrics = await queue_metrics(session)
            assert metrics["delivered"]["count"] == 1
            assert metrics["retry"]["count"] == 1
    finally:
        await engine.dispose()
