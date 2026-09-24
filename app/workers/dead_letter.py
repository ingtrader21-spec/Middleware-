"""Dead-letter inspection and explicit replay primitives."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.workers.outbox import replay_dead_letter


LIST_SQL = text("""
SELECT id, topic, correlation_id, attempts, last_error, dead_lettered_at,
       replay_count
FROM outbox_event WHERE status='dead_letter'
ORDER BY dead_lettered_at, id LIMIT :limit
""")


async def list_dead_letters(session: AsyncSession, limit: int = 100) -> list[dict]:
    if limit < 1 or limit > 100:
        raise ValueError("dead-letter limit must be between 1 and 100")
    rows = await session.execute(LIST_SQL, {"limit": limit})
    return [dict(row) for row in rows.mappings()]


async def replay(session: AsyncSession, item_id: UUID) -> bool:
    return await replay_dead_letter(session, item_id)
