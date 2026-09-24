from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.workers.dead_letter import list_dead_letters, replay
from app.workers.outbox import queue_metrics, recover_expired_leases
from app.workers.reconciliation import reconcile_internal_outbox


router = APIRouter(prefix="/api/v1/operations", tags=["operations"])


def require_integration_admin(role: str) -> None:
    if role != "integration_admin":
        raise HTTPException(403, "integration administrator role required")


@router.get("/reliability")
async def reliability(db: AsyncSession = Depends(get_session)):
    return {"outbox": await queue_metrics(db)}


@router.get("/dead-letters")
async def dead_letters(limit: int = 100, db: AsyncSession = Depends(get_session)):
    return {"items": await list_dead_letters(db, limit)}


@router.post("/dead-letters/{item_id}/replay", status_code=202)
async def replay_item(
    item_id: UUID,
    db: AsyncSession = Depends(get_session),
    x_codestra_role: str = Header("", alias="X-Codestra-Role"),
):
    require_integration_admin(x_codestra_role)
    if not await replay(db, item_id):
        raise HTTPException(409, "item is not eligible for replay")
    return {"id": str(item_id), "status": "pending"}


@router.post("/maintenance/recover", status_code=202)
async def recover(
    db: AsyncSession = Depends(get_session),
    x_codestra_role: str = Header("", alias="X-Codestra-Role"),
):
    require_integration_admin(x_codestra_role)
    return {"recovered": await recover_expired_leases(db)}


@router.post("/reconciliation", status_code=202)
async def reconcile(
    db: AsyncSession = Depends(get_session),
    x_codestra_role: str = Header("", alias="X-Codestra-Role"),
):
    require_integration_admin(x_codestra_role)
    return await reconcile_internal_outbox(db)
