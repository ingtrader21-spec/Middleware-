"""Internal outbox reconciliation; no external system is queried."""

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


MISSING_SQL = text("""
SELECT inbox.event_id
FROM event_inbox AS inbox
WHERE NOT EXISTS (
    SELECT 1 FROM outbox_event AS outbox
    WHERE outbox.payload->>'event_id' = inbox.event_id
)
ORDER BY inbox.created_at, inbox.event_id
LIMIT :limit
""")

CHECKPOINT_SQL = text("""
INSERT INTO reconciliation_checkpoint (id, source, cursor, status, updated_at)
VALUES (gen_random_uuid(), 'middleware_outbox', :cursor, :status, :now)
ON CONFLICT (source) DO UPDATE
SET cursor=EXCLUDED.cursor, status=EXCLUDED.status, updated_at=EXCLUDED.updated_at
""")


async def reconcile_internal_outbox(
    session: AsyncSession, limit: int = 100
) -> dict[str, object]:
    if limit < 1 or limit > 1000:
        raise ValueError("reconciliation limit must be between 1 and 1000")
    rows = await session.execute(MISSING_SQL, {"limit": limit})
    missing = [row.event_id for row in rows]
    now = datetime.now(timezone.utc)
    await session.execute(
        CHECKPOINT_SQL,
        {
            "cursor": now.isoformat(),
            "status": "drift" if missing else "healthy",
            "now": now,
        },
    )
    await session.commit()
    return {
        "missing_outbox_event_ids": missing,
        "status": "drift" if missing else "healthy",
    }
