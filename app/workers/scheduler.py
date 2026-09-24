"""Disabled-by-default internal recovery and reconciliation scheduler."""

import asyncio
import logging
from typing import Any

from app.core.config import settings
from app.db.session import SessionFactory
from app.workers.outbox import recover_expired_leases
from app.workers.reconciliation import reconcile_internal_outbox


logger = logging.getLogger(__name__)


async def maintenance_once() -> dict[str, Any]:
    async with SessionFactory() as session:
        recovered = await recover_expired_leases(session)
        reconciliation = await reconcile_internal_outbox(session)
    return {"recovered": recovered, "reconciliation": reconciliation}


async def run_forever() -> None:
    if not settings.outbox_worker_enabled:
        raise RuntimeError("OUTBOX_WORKER_ENABLED is false")
    while True:
        try:
            result = await maintenance_once()
            logger.info(
                "maintenance completed recovered=%s reconciliation_status=%s",
                result["recovered"],
                result["reconciliation"]["status"],
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("maintenance cycle failed")
        await asyncio.sleep(settings.maintenance_interval_seconds)


if __name__ == "__main__":
    asyncio.run(run_forever())
