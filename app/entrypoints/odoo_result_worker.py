"""Durable Odoo result delivery worker."""

from app.adapters.odoo.results import (
    claim_result_delivery,
    deliver_result,
    recover_stale_result_deliveries,
)
from app.db.session import SessionFactory
from app.entrypoints.runtime import run_worker

SERVICE = "middleware-odoo-result-worker"
QUEUE = "odoo-results"


async def cycle() -> dict[str, object]:
    async with SessionFactory() as session:
        await recover_stale_result_deliveries(session)
        item = await claim_result_delivery(session)
        if item is None:
            return {"claimed": 0}
        await deliver_result(session, item.result_delivery_id)
        return {"claimed": 1, "delivered": 1}


def main() -> None:
    run_worker(SERVICE, QUEUE, cycle)


if __name__ == "__main__":
    main()
