"""Read-only Postly polling worker entrypoint."""

from __future__ import annotations

import asyncio
import signal

from app.core.config import settings
from app.db.session import SessionFactory
from app.integrations.postiz.client import PostizClient
from app.workers.postly_polling import poll_cycle


async def run() -> None:
    if not settings.postly_polling_enabled:
        raise RuntimeError("Postly polling is disabled")
    if settings.social_publish_enabled or settings.postiz_publish_enabled:
        raise RuntimeError("polling worker refuses to start while publishing is enabled")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    client = PostizClient()
    while not stop.is_set():
        async with SessionFactory() as session:
            await poll_cycle(session, client)
        try:
            await asyncio.wait_for(
                stop.wait(), timeout=float(settings.postly_poll_interval_seconds)
            )
        except TimeoutError:
            pass


if __name__ == "__main__":
    asyncio.run(run())
