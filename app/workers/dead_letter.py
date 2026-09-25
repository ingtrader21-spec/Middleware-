"""Tenant-scoped dead-letter inspection and explicit redrive primitives."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.workers.outbox import replay_dead_letter


LIST_SQL = text("""
SELECT id, topic, correlation_id, attempts, last_error, dead_lettered_at,
       replay_count
FROM outbox_event
WHERE status='dead_letter'
  AND payload->>'tenant_id' = :tenant_id
ORDER BY dead_lettered_at, id
LIMIT :limit
""")

LEGACY_LIST_SQL = text("""
SELECT id, topic, correlation_id, attempts, last_error, dead_lettered_at,
       replay_count
FROM outbox_event
WHERE status='dead_letter'
ORDER BY dead_lettered_at, id
LIMIT :limit
""")

DETAIL_SQL = text("""
SELECT id, topic, correlation_id, attempts, last_error, dead_lettered_at,
       replay_count, created_at
FROM outbox_event
WHERE status='dead_letter'
  AND id=:item_id
  AND payload->>'tenant_id' = :tenant_id
""")

REDRIVE_SQL = text("""
UPDATE outbox_event
SET status='pending', attempts=0, next_attempt_at=NULL,
    locked_at=NULL, last_error=NULL, dead_lettered_at=NULL,
    replay_count=replay_count + 1
WHERE id=:item_id
  AND status='dead_letter'
  AND payload->>'tenant_id' = :tenant_id
RETURNING id, replay_count
""")


async def list_dead_letters(
    session: AsyncSession,
    limit: int = 100,
    *,
    tenant_id: str | None = None,
) -> list[dict]:
    if limit < 1 or limit > 100:
        raise ValueError("dead-letter limit must be between 1 and 100")
    if tenant_id is None:
        rows = await session.execute(LEGACY_LIST_SQL, {"limit": limit})
    else:
        rows = await session.execute(LIST_SQL, {"limit": limit, "tenant_id": tenant_id})
    return [dict(row) for row in rows.mappings()]


async def get_dead_letter(
    session: AsyncSession,
    item_id: UUID,
    *,
    tenant_id: str,
) -> dict | None:
    row = (
        await session.execute(
            DETAIL_SQL,
            {"item_id": item_id, "tenant_id": tenant_id},
        )
    ).mappings().one_or_none()
    return dict(row) if row is not None else None


async def redrive_dead_letter(
    session: AsyncSession,
    item_id: UUID,
    *,
    tenant_id: str,
) -> dict | None:
    row = (
        await session.execute(
            REDRIVE_SQL,
            {"item_id": item_id, "tenant_id": tenant_id},
        )
    ).mappings().one_or_none()
    if row is None:
        await session.rollback()
        return None
    await session.commit()
    return {"id": str(row["id"]), "replay_count": int(row["replay_count"])}


async def replay(session: AsyncSession, item_id: UUID) -> bool:
    """Legacy internal redrive primitive; canonical APIs use tenant-scoped redrive."""
    return await replay_dead_letter(session, item_id)
