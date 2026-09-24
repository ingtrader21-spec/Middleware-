"""Durable outbox state machine. This module performs no external delivery."""

from datetime import datetime, timedelta, timezone
from typing import Any, cast
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.reliability import RetryPolicy, redact


CLAIM_SQL = text("""
WITH claimable AS (
    SELECT id FROM outbox_event
    WHERE status IN ('pending', 'retry')
      AND (next_attempt_at IS NULL OR next_attempt_at <= :now)
    ORDER BY created_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT :limit
)
UPDATE outbox_event AS item
SET status = 'processing', locked_at = :now, next_attempt_at = :lease_until
FROM claimable
WHERE item.id = claimable.id
RETURNING item.id, item.topic, item.payload, item.correlation_id,
          item.attempts, item.status, item.locked_at
""")

ACK_SQL = text("""
UPDATE outbox_event SET status='delivered', locked_at=NULL, next_attempt_at=NULL,
last_error=NULL WHERE id=:item_id AND status='processing'
""")

FAIL_SQL = text("""
UPDATE outbox_event
SET attempts=:attempts, status=:status, last_error=:last_error,
    next_attempt_at=:next_attempt_at, locked_at=NULL,
    dead_lettered_at=:dead_lettered_at
WHERE id=:item_id AND status='processing'
""")

RECOVER_SQL = text("""
UPDATE outbox_event SET status='retry', locked_at=NULL, next_attempt_at=:now,
last_error=COALESCE(last_error, 'worker lease expired')
WHERE status='processing' AND next_attempt_at <= :now
RETURNING id
""")

REPLAY_SQL = text("""
UPDATE outbox_event SET status='pending', attempts=0, next_attempt_at=NULL,
locked_at=NULL, last_error=NULL, dead_lettered_at=NULL,
replay_count=replay_count + 1
WHERE id=:item_id AND status='dead_letter'
""")

METRICS_SQL = text("""
SELECT status, count(*) AS count,
       EXTRACT(EPOCH FROM (:now - min(created_at)))::bigint AS oldest_age_seconds
FROM outbox_event GROUP BY status ORDER BY status
""")


async def claim_batch(
    session: AsyncSession, *, limit: int, lease_seconds: int
) -> list[dict[str, Any]]:
    if limit < 1 or limit > 100:
        raise ValueError("claim limit must be between 1 and 100")
    now = datetime.now(timezone.utc)
    rows = await session.execute(
        CLAIM_SQL,
        {
            "limit": limit,
            "now": now,
            "lease_until": now + timedelta(seconds=lease_seconds),
        },
    )
    await session.commit()
    return [dict(row) for row in rows.mappings()]


async def acknowledge(session: AsyncSession, item_id: UUID) -> bool:
    result = cast(
        CursorResult[Any], await session.execute(ACK_SQL, {"item_id": item_id})
    )
    await session.commit()
    return result.rowcount == 1


async def record_failure(
    session: AsyncSession,
    item_id: UUID,
    current_attempts: int,
    error: str,
    policy: RetryPolicy,
    *,
    permanent: bool = False,
) -> str:
    attempts = current_attempts + 1
    now = datetime.now(timezone.utc)
    dead = permanent or attempts >= policy.max_attempts
    status = "dead_letter" if dead else "retry"
    next_attempt_at = None if dead else now + timedelta(seconds=policy.delay(attempts))
    sanitized_error = str(redact({"last_error": error})["last_error"])
    result = cast(
        CursorResult[Any],
        await session.execute(
            FAIL_SQL,
            {
                "item_id": item_id,
                "attempts": attempts,
                "status": status,
                "last_error": sanitized_error,
                "next_attempt_at": next_attempt_at,
                "dead_lettered_at": now if dead else None,
            },
        ),
    )
    await session.commit()
    if result.rowcount != 1:
        raise RuntimeError("outbox item was not processing")
    return status


async def recover_expired_leases(session: AsyncSession) -> int:
    result = await session.execute(RECOVER_SQL, {"now": datetime.now(timezone.utc)})
    recovered = len(result.fetchall())
    await session.commit()
    return recovered


async def replay_dead_letter(session: AsyncSession, item_id: UUID) -> bool:
    result = cast(
        CursorResult[Any], await session.execute(REPLAY_SQL, {"item_id": item_id})
    )
    await session.commit()
    return result.rowcount == 1


async def queue_metrics(session: AsyncSession) -> dict[str, dict[str, int]]:
    rows = (
        await session.execute(METRICS_SQL, {"now": datetime.now(timezone.utc)})
    ).mappings()
    return {
        str(row["status"]): {
            "count": int(row["count"]),
            "oldest_age_seconds": int(row["oldest_age_seconds"] or 0),
        }
        for row in rows
    }
