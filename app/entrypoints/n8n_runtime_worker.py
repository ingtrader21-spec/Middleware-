"""Durable governed n8n dispatch worker."""

from __future__ import annotations

import asyncio
import signal

import httpx

from app.core.config import settings
from app.db.session import SessionFactory
from app.workers.n8n_runtime import (
    claim,
    dispatch_one,
    expire_running,
    recover_stale_dispatches,
)


async def run() -> None:
    if not settings.n8n_runtime_enabled:
        raise RuntimeError("governed n8n runtime is disabled")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    timeout = httpx.Timeout(settings.n8n_runtime_dispatch_timeout_seconds)
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False
    ) as client:
        while not stop.is_set():
            async with SessionFactory() as session:
                await recover_stale_dispatches(session)
                await expire_running(session)
                rows = await claim(session, min(settings.n8n_concurrency, 25))
            for row in rows:
                async with SessionFactory() as session:
                    await dispatch_one(session, row, client)
            try:
                await asyncio.wait_for(stop.wait(), timeout=1.0 if rows else 2.0)
            except TimeoutError:
                pass


if __name__ == "__main__":
    asyncio.run(run())
