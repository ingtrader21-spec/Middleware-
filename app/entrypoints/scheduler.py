"""Lease recovery and maintenance scheduler."""

from app.core.config import settings
from app.entrypoints.runtime import run_worker
from app.workers.scheduler import maintenance_once
from app.callback_scheduler import claim_due, escalate_missed, mark_missed, reconcile
from app.db.session import SessionFactory


SERVICE = "middleware-scheduler"
QUEUE = "middleware.scheduler.v1"


async def cycle() -> dict[str, object]:
    if settings.callback_scheduler_enabled:
        if not settings.callback_test_syn_enabled:
            return {"status": "callback-disabled"}
        if (
            settings.callback_allowed_tenant != "COD"
            or settings.callback_allowed_campaign != "TEST_SYN"
        ):
            return {"status": "callback-allowlist-denied"}
        async with SessionFactory() as session:
            due = await claim_due(
                session, SERVICE, tenant_id="COD", campaign_id="TEST_SYN"
            )
        async with SessionFactory() as session:
            missed = await mark_missed(
                session, SERVICE, tenant_id="COD", campaign_id="TEST_SYN"
            )
        async with SessionFactory() as session:
            escalated = await escalate_missed(
                session, SERVICE, tenant_id="COD", campaign_id="TEST_SYN"
            )
        async with SessionFactory() as session:
            repaired = await reconcile(session, tenant_id="COD", campaign_id="TEST_SYN")
        return {"due": len(due), "missed": missed, "escalated": escalated, **repaired}
    if not settings.outbox_worker_enabled:
        return {"status": "disabled"}
    return await maintenance_once()


if __name__ == "__main__":
    run_worker(SERVICE, QUEUE, cycle)
