"""Odoo campaign-control saga worker."""

from app.core.config import settings
from app.db.session import SessionFactory
from app.entrypoints.runtime import run_worker
from app.odoo_campaign_saga import (
    adapter_for,
    claim_saga,
    enroll_pending_sagas,
    process_saga,
    recover_expired_leases,
    validate_worker_settings,
)

SERVICE = "middleware-odoo-campaign-saga-worker"
QUEUE = "odoo-campaign-saga"


async def cycle() -> dict[str, object]:
    if not settings.odoo_campaign_saga_enabled:
        return {"claimed": 0, "disabled": True}
    # Fail closed before touching the database: lease must cover both Odoo
    # calls and only the synthetic adapter exists.
    validate_worker_settings(settings)
    adapter = adapter_for(settings)
    async with SessionFactory() as session:
        recovered = await recover_expired_leases(
            session, retry_limit=settings.odoo_campaign_saga_retry_limit
        )
        enrolled = await enroll_pending_sagas(session)
        saga = await claim_saga(
            session, lease_seconds=settings.odoo_campaign_saga_lease_seconds
        )
        counts: dict[str, object] = {"recovered": recovered, "enrolled": enrolled}
        if saga is None:
            return {"claimed": 0, **counts}
        outcome = await process_saga(session, saga.saga_id, adapter=adapter)
        return {"claimed": 1, **counts, **outcome}


def main() -> None:
    run_worker(SERVICE, QUEUE, cycle)


if __name__ == "__main__":
    main()
