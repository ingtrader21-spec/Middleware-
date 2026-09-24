"""Bridge canonical social outbox deliveries into the governed n8n runtime."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.n8n_runtime import ExecutionStatus, canonical_bytes, sha256
from app.db.models import IntegrationEvent, N8nRuntimeExecution, N8nWorkflowRegistry
from app.social.metrics import (
    n8n_delivery_attempts,
    n8n_delivery_deadletter,
    n8n_delivery_failure,
    n8n_delivery_success,
)
from app.workers.delivery import claim


SOCIAL_ROUTER_CODE = "CDST_SOCIAL_EVENT_ROUTER"
SOCIAL_ROUTER_VERSION = "1"


def _tenant(payload: dict[str, Any]) -> str:
    value = str(payload.get("tenant_id", ""))
    if not value or len(value) > 64:
        raise ValueError("social event tenant is invalid")
    return value


async def stage_claimed_delivery(
    session: AsyncSession, row: dict[str, Any]
) -> UUID | None:
    """Create exactly one governed execution before any n8n network action."""
    delivery_id = UUID(str(row["id"]))
    mapped = await session.scalar(
        text(
            "SELECT execution_id FROM social_n8n_delivery_execution "
            "WHERE delivery_id=:delivery"
        ),
        {"delivery": delivery_id},
    )
    if mapped is not None:
        await session.execute(
            text(
                "UPDATE integration_delivery SET status='delivering',"
                "lease_owner=NULL,lease_expires_at=NULL WHERE id=:delivery"
            ),
            {"delivery": delivery_id},
        )
        await session.commit()
        n8n_delivery_attempts.labels(result="duplicate_bridge").inc()
        return UUID(str(mapped))

    event = await session.get(IntegrationEvent, int(row["event_id"]), with_for_update=True)
    if event is None or event.source_system != "social":
        await _terminal_failure(session, delivery_id, "INVALID_SOCIAL_EVENT")
        return None
    envelope = dict(event.payload_json)
    try:
        tenant_id = _tenant(envelope)
    except ValueError:
        await _terminal_failure(session, delivery_id, "INVALID_TENANT")
        return None
    registry = await session.scalar(
        select(N8nWorkflowRegistry).where(
            N8nWorkflowRegistry.workflow_code == SOCIAL_ROUTER_CODE,
            N8nWorkflowRegistry.workflow_version == SOCIAL_ROUTER_VERSION,
            N8nWorkflowRegistry.enabled.is_(True),
            N8nWorkflowRegistry.event_types.contains([event.event_type]),
            N8nWorkflowRegistry.tenant_scope.contains([tenant_id]),
        )
    )
    if registry is None:
        await _terminal_failure(session, delivery_id, "SOCIAL_ROUTER_NOT_REGISTERED")
        return None
    execution_id = uuid4()
    now = datetime.now(UTC)
    execution = N8nRuntimeExecution(
        execution_id=execution_id,
        tenant_id=tenant_id,
        event_id=event.original_event_id,
        event_type=event.event_type,
        source_event_id=event.original_event_id,
        workflow_code=registry.workflow_code,
        workflow_version=registry.workflow_version,
        correlation_id=event.correlation_id,
        causation_id=event.original_event_id,
        trace_id=hashlib.sha256(event.correlation_id.encode()).hexdigest()[:32],
        idempotency_key_hash=hashlib.sha256(event.idempotency_key.encode()).hexdigest(),
        payload_hash=sha256(canonical_bytes(envelope)),
        payload_json=envelope,
        status=ExecutionStatus.PENDING,
        timeout_at=now + timedelta(seconds=registry.timeout_seconds),
    )
    session.add(execution)
    await session.flush()
    attempt = int(row["attempts"]) + 1
    await session.execute(
        text(
            """INSERT INTO social_n8n_delivery_execution(delivery_id,execution_id)
            VALUES (:delivery,:execution)"""
        ),
        {"delivery": delivery_id, "execution": execution_id},
    )
    await session.execute(
        text(
            """INSERT INTO social_n8n_delivery_attempts
            (id,delivery_id,attempt_number,result)
            VALUES (:id,:delivery,:attempt,'STAGED')"""
        ),
        {"id": uuid4(), "delivery": delivery_id, "attempt": attempt},
    )
    await session.execute(
        text(
            """UPDATE integration_delivery SET status='delivering',attempts=:attempt,
            lease_owner=NULL,lease_expires_at=NULL,last_error=NULL
            WHERE id=:delivery"""
        ),
        {"delivery": delivery_id, "attempt": attempt},
    )
    await session.commit()
    n8n_delivery_attempts.labels(result="staged").inc()
    return execution_id


async def stage_pending(session: AsyncSession) -> int:
    rows = await claim(
        session,
        "n8n",
        settings.social_n8n_delivery_worker_id,
        settings.social_n8n_delivery_batch_size,
        settings.social_n8n_delivery_lease_seconds,
    )
    count = 0
    for row in rows:
        if await stage_claimed_delivery(session, row) is not None:
            count += 1
    return count


async def reconcile_terminal(session: AsyncSession) -> int:
    rows = (
        await session.execute(
            text(
                """SELECT d.id,e.status FROM integration_delivery d
                JOIN social_n8n_delivery_execution m ON m.delivery_id=d.id
                JOIN n8n_runtime_execution e ON e.execution_id=m.execution_id
                WHERE d.status='delivering' AND e.status IN
                ('COMPLETED','FAILED','DEAD_LETTER','TIMED_OUT','CANCELLED')
                FOR UPDATE OF d SKIP LOCKED"""
            )
        )
    ).mappings().all()
    for row in rows:
        status = "delivered" if row["status"] == "COMPLETED" else "dead_letter"
        error = None if status == "delivered" else f"N8N_{row['status']}"
        await session.execute(
            text(
                """UPDATE integration_delivery SET status=:status,last_error=:error,
                lease_owner=NULL,lease_expires_at=NULL WHERE id=:delivery"""
            ),
            {"status": status, "error": error, "delivery": row["id"]},
        )
        if status == "delivered":
            n8n_delivery_success.inc()
        else:
            n8n_delivery_deadletter.labels(reason=error).inc()
    await session.commit()
    return len(rows)


async def _terminal_failure(
    session: AsyncSession, delivery_id: UUID, error_code: str
) -> None:
    await session.execute(
        text(
            """UPDATE integration_delivery SET status='dead_letter',last_error=:error,
            attempts=attempts+1,lease_owner=NULL,lease_expires_at=NULL
            WHERE id=:delivery"""
        ),
        {"delivery": delivery_id, "error": error_code},
    )
    await session.commit()
    n8n_delivery_failure.labels(reason=error_code).inc()
    n8n_delivery_deadletter.labels(reason=error_code).inc()
