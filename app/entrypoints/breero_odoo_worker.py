"""Disabled-by-default BREERO Odoo delivery worker."""

from app.core.config import settings
from app.db.session import SessionFactory
from app.entrypoints.runtime import run_worker
from app.workers.breero_odoo import (
    RestrictedOdooTransport,
    claim,
    process,
    recover_stale,
)

SERVICE = "middleware-breero-odoo-worker"
QUEUE = "breero-odoo"


async def cycle() -> dict[str, object]:
    if not settings.breero_odoo_delivery_enabled:
        return {"claimed": 0, "delivered": 0}
    async with SessionFactory() as session:
        await recover_stale(session)
        items = await claim(
            session,
            settings.breero_worker_batch_size,
            settings.breero_worker_lease_seconds,
        )
    delivered = 0
    for item in items:
        async with SessionFactory() as session:
            delivered += int(
                await process(session, item, RestrictedOdooTransport()) == "delivered"
            )
    return {"claimed": len(items), "delivered": delivered}


def main() -> None:
    run_worker(SERVICE, QUEUE, cycle)


if __name__ == "__main__":
    main()
