"""Retention cleanup that preserves legal holds and auditable metadata."""

from datetime import datetime, timezone

from prometheus_client import Counter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditEvent, InvalidEventQuarantine


CLEANUP = Counter(
    "quarantine_cleanup_total", "Quarantine retention cleanup", ["result"]
)


async def cleanup_expired(session: AsyncSession, limit: int = 100) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    records = (
        await session.scalars(
            select(InvalidEventQuarantine)
            .where(
                InvalidEventQuarantine.legal_hold.is_(False),
                InvalidEventQuarantine.retention_deadline <= now,
                InvalidEventQuarantine.status.in_(
                    ("PENDING_REVIEW", "RESOLVED_NO_REPLAY", "REJECTED")
                ),
            )
            .order_by(InvalidEventQuarantine.retention_deadline)
            .with_for_update(skip_locked=True)
            .limit(limit)
        )
    ).all()
    for record in records:
        record.encrypted_payload = None
        record.encryption_nonce = None
        record.encryption_key_version = None
        if record.status == "PENDING_REVIEW":
            record.status = "EXPIRED"
        record.record_version += 1
        db_audit = AuditEvent(
            action="quarantine.encrypted_payload_destroyed",
            subject=str(record.id),
            correlation_id=record.server_correlation_id,
            decision="EXPIRED",
            redacted_payload={
                "retention_policy_version": record.retention_policy_version
            },
        )
        session.add(db_audit)
    await session.commit()
    CLEANUP.labels("success").inc(len(records))
    return {"expired": len(records)}
