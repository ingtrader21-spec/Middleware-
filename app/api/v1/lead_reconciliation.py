"""Durable orchestration endpoints; production execution stays disabled by policy."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session


router = APIRouter(
    prefix="/api/v1/crm-vicidial/reconciliation", tags=["crm-vicidial-reconciliation"]
)


class StartRequest(BaseModel):
    company_id: str = Field(min_length=1, max_length=64)
    connector_id: str = Field(min_length=1, max_length=64)
    source_cursor: datetime | None = None
    environment_id: str = Field(pattern="^(test|staging)$")


class FinishRequest(BaseModel):
    status: str = Field(pattern="^(succeeded|failed|partial)$")
    next_cursor: datetime | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    error_summary: str | None = Field(default=None, max_length=2000)


def require_integration_admin(role: str) -> None:
    if role != "integration_admin":
        raise HTTPException(403, "integration administrator role required")


@router.post("/start", status_code=202)
async def start_run(
    body: StartRequest,
    db: AsyncSession = Depends(get_session),
    x_codestra_role: str = Header("", alias="X-Codestra-Role"),
):
    require_integration_admin(x_codestra_role)
    lock_name = f"crm-vicidial:{body.company_id}:{body.connector_id}"
    locked = await db.scalar(
        text("SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": lock_name},
    )
    if not locked:
        return {"status": "skipped", "reason": "PREVIOUS_RUN_ACTIVE"}
    run_id = uuid4()
    try:
        await db.execute(
            text("""
                INSERT INTO vicidial_sync_run
                    (id, company_id, connector_id, status, source_cursor, counts)
                VALUES (:id, :company_id, :connector_id, 'running', :source_cursor, '{}'::jsonb)
            """),
            {
                "id": run_id,
                "company_id": body.company_id,
                "connector_id": body.connector_id,
                "source_cursor": body.source_cursor,
            },
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return {"status": "skipped", "reason": "PREVIOUS_RUN_ACTIVE"}
    return {
        "sync_run_id": str(run_id),
        "status": "running",
        "overlap_window_seconds": 300,
    }


@router.post("/{run_id}/finish")
async def finish_run(
    run_id: UUID,
    body: FinishRequest,
    db: AsyncSession = Depends(get_session),
    x_codestra_role: str = Header("", alias="X-Codestra-Role"),
):
    require_integration_admin(x_codestra_role)
    if any(value < 0 for value in body.counts.values()):
        raise HTTPException(422, "counts must be non-negative")
    row = await db.execute(
        text("""
            UPDATE vicidial_sync_run
            SET completed_at=:completed_at, status=:status, next_cursor=:next_cursor,
                counts=CAST(:counts AS jsonb), error_summary=:error_summary
            WHERE id=:id AND status='running'
            RETURNING id
        """),
        {
            "id": run_id,
            "completed_at": datetime.now(timezone.utc),
            "status": body.status,
            "next_cursor": body.next_cursor,
            "counts": __import__("json").dumps(body.counts),
            "error_summary": body.error_summary,
        },
    )
    if row.scalar_one_or_none() is None:
        await db.rollback()
        raise HTTPException(409, "run is not active")
    await db.commit()
    return {
        "sync_run_id": str(run_id),
        "status": body.status,
        "cursor_advanced": body.status == "succeeded",
    }


@router.get("/metrics")
async def metrics(db: AsyncSession = Depends(get_session)):
    rows = (
        await db.execute(
            text(
                "SELECT status, count(*) AS total FROM vicidial_sync_run GROUP BY status"
            )
        )
    ).mappings()
    return {"sync_run_total": {row["status"]: row["total"] for row in rows}}
