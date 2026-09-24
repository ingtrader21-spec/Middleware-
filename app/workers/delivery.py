"""Authoritative integration_delivery lease operations; no transport calls."""

from datetime import datetime, timedelta, timezone
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

CLAIM = text("""
WITH eligible AS (
 SELECT d.id FROM integration_delivery d
 JOIN integration_event e ON e.id=d.event_id
 WHERE d.target=:target AND d.status IN ('pending','retry_wait')
   AND (d.available_at IS NULL OR d.available_at<=:now)
   AND NOT EXISTS (
     SELECT 1 FROM integration_delivery older
     JOIN integration_event oe ON oe.id=older.event_id
     WHERE oe.entity_key=e.entity_key AND oe.id<e.id
       AND older.target=d.target
       AND older.status NOT IN ('delivered','canceled','dead_letter')
   )
 ORDER BY e.id FOR UPDATE OF d SKIP LOCKED LIMIT :limit
)
UPDATE integration_delivery d SET status='leased', lease_owner=:owner,
 lease_expires_at=:expires, locked_at=:now
FROM eligible WHERE d.id=eligible.id
RETURNING d.id,d.event_id,d.target,d.attempts,d.max_attempts
""")

RECOVER = text("""
UPDATE integration_delivery SET status='retry_wait',lease_owner=NULL,
 lease_expires_at=NULL,available_at=:now
WHERE status='leased' AND lease_expires_at<=:now RETURNING id
""")


async def claim(
    session: AsyncSession, target: str, owner: str, limit: int, lease_seconds: int
):
    now = datetime.now(timezone.utc)
    rows = await session.execute(
        CLAIM,
        {
            "target": target,
            "owner": owner,
            "limit": limit,
            "now": now,
            "expires": now + timedelta(seconds=lease_seconds),
        },
    )
    await session.commit()
    return [dict(row) for row in rows.mappings()]


async def recover(session: AsyncSession) -> int:
    rows = await session.execute(RECOVER, {"now": datetime.now(timezone.utc)})
    values = rows.fetchall()
    await session.commit()
    return len(values)
