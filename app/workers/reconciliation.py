"""Bounded internal-outbox reconciliation with tenant-scoped canonical readback.

This module never queries an external provider and never performs provider effects.
"""

from datetime import datetime, timezone
from uuid import UUID

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

MISSING_TENANT_SQL = text("""
SELECT inbox.event_id
FROM event_inbox AS inbox
WHERE inbox.payload->>'tenant_id' = :tenant_id
  AND NOT EXISTS (
    SELECT 1 FROM outbox_event AS outbox
    WHERE outbox.payload->>'event_id' = inbox.event_id
      AND outbox.payload->>'tenant_id' = :tenant_id
)
ORDER BY inbox.created_at, inbox.event_id
LIMIT :limit
""")

CHECKPOINT_SQL = text("""
INSERT INTO reconciliation_checkpoint (id, source, cursor, status, updated_at)
VALUES (gen_random_uuid(), :source, :cursor, :status, :now)
ON CONFLICT (source) DO UPDATE
SET cursor=EXCLUDED.cursor, status=EXCLUDED.status, updated_at=EXCLUDED.updated_at
RETURNING id, source, cursor, status, updated_at
""")

CHECKPOINT_BY_ID_SQL = text("""
SELECT id, source, cursor, status, updated_at
FROM reconciliation_checkpoint
WHERE id=:run_id
""")

CHECKPOINT_BY_SOURCE_SQL = text("""
SELECT id, source, cursor, status, updated_at
FROM reconciliation_checkpoint
WHERE source=:source
""")


async def reconcile_internal_outbox(
    session: AsyncSession,
    limit: int = 100,
    *,
    tenant_id: str | None = None,
) -> dict[str, object]:
    if limit < 1 or limit > 1000:
        raise ValueError("reconciliation limit must be between 1 and 1000")
    if tenant_id is None:
        rows = await session.execute(MISSING_SQL, {"limit": limit})
        source = "middleware_outbox"
    else:
        rows = await session.execute(
            MISSING_TENANT_SQL,
            {"limit": limit, "tenant_id": tenant_id},
        )
        source = f"middleware_outbox:{tenant_id}"
    missing = [row.event_id for row in rows]
    now = datetime.now(timezone.utc)
    checkpoint = (
        await session.execute(
            CHECKPOINT_SQL,
            {
                "source": source,
                "cursor": now.isoformat(),
                "status": "drift" if missing else "healthy",
                "now": now,
            },
        )
    ).mappings().one()
    await session.commit()
    return {
        "reconciliation_id": str(checkpoint["id"]),
        "source": source,
        "tenant_id": tenant_id,
        "missing_outbox_event_ids": missing,
        "checked": len(missing),
        "status": "drift" if missing else "healthy",
        "dry_run": True,
        "updated_at": checkpoint["updated_at"],
    }


async def get_reconciliation_status(
    session: AsyncSession,
    run_id: UUID,
    *,
    tenant_id: str,
) -> dict[str, object] | None:
    row = (
        await session.execute(
            CHECKPOINT_BY_ID_SQL,
            {"run_id": run_id},
        )
    ).mappings().one_or_none()
    if row is None or row["source"] != f"middleware_outbox:{tenant_id}":
        return None
    return {
        "reconciliation_id": str(row["id"]),
        "source": row["source"],
        "tenant_id": tenant_id,
        "cursor": row["cursor"],
        "status": row["status"],
        "updated_at": row["updated_at"],
        "dry_run": True,
    }


async def get_latest_reconciliation_status(
    session: AsyncSession,
    *,
    tenant_id: str,
) -> dict[str, object] | None:
    row = (
        await session.execute(
            CHECKPOINT_BY_SOURCE_SQL,
            {"source": f"middleware_outbox:{tenant_id}"},
        )
    ).mappings().one_or_none()
    if row is None:
        return None
    return {
        "reconciliation_id": str(row["id"]),
        "source": row["source"],
        "tenant_id": tenant_id,
        "cursor": row["cursor"],
        "status": row["status"],
        "updated_at": row["updated_at"],
        "dry_run": True,
    }
