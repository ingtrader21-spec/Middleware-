"""Durable Odoo transactional-outbox synchronization worker."""

from app.adapters.odoo.sync import run_sync_cycle
from app.core.config import settings
from app.entrypoints.runtime import run_worker


SERVICE = "middleware-sync-worker"
QUEUE = "middleware.sync.odoo.v1"


async def cycle() -> dict[str, object]:
    if not settings.odoo_read_enabled or not settings.odoo_sync_worker_enabled:
        return {"status": "disabled"}
    return await run_sync_cycle()


if __name__ == "__main__":
    run_worker(SERVICE, QUEUE, cycle)
