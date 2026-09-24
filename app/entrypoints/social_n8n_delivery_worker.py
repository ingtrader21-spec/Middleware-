"""Entrypoint for the PostgreSQL-authoritative social n8n bridge."""

from __future__ import annotations

import asyncio
import signal

from app.core.config import settings
from app.db.session import SessionFactory
from app.workers.delivery import recover
from app.workers.social_n8n_delivery import reconcile_terminal, stage_pending


async def run() -> None:
    if not settings.social_n8n_delivery_worker_enabled:
        raise RuntimeError("social n8n delivery worker is disabled")
    if not settings.social_n8n_events_enabled or not settings.n8n_runtime_enabled:
        raise RuntimeError("social n8n delivery gates are incomplete")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    while not stop.is_set():
        async with SessionFactory() as session:
            await recover(session)
            await reconcile_terminal(session)
            staged = await stage_pending(session)
        try:
            await asyncio.wait_for(stop.wait(), timeout=1.0 if staged else 2.0)
        except TimeoutError:
            pass


if __name__ == "__main__":
    asyncio.run(run())
