"""Staging-only scraper to Odoo delivery worker."""

import asyncio

from prometheus_client import start_http_server

from app.entrypoints.runtime import configure_logging, validate_runtime
from app.workers.scraper_odoo_delivery import run_forever

METRICS_PORT = 8095


def main() -> None:
    configure_logging()
    validate_runtime("middleware-scraper-odoo-delivery")
    start_http_server(METRICS_PORT, addr="0.0.0.0")
    asyncio.run(run_forever())


if __name__ == "__main__":
    main()
