"""Disabled-by-default Klyrow inbound-mail Odoo delivery worker."""

from app.core.config import settings
from app.db.session import SessionFactory
from app.entrypoints.runtime import run_worker
from app.workers.klyrow_mail_odoo import (
    RestrictedOdooTransport,
    claim,
    process,
    recover_stale,
)

SERVICE = "middleware-klyrow-mail-odoo-worker"
QUEUE = "klyrow-mail-odoo"


async def cycle() -> dict[str, object]:
    if not settings.klyrow_mail_odoo_delivery_enabled:
        return {"claimed": 0, "delivered": 0}
    async with SessionFactory() as session:
        await recover_stale(session)
        items = await claim(session)
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
