#!/usr/bin/env python3
"""One bounded pass of durable Telnexa callback reconciliation.

Re-projects ``retry`` inbox rows whose communication message now exists and
dead-letters rows that exhaust ``TELNEXA_EVENT_RECONCILE_MAX_ATTEMPTS``.  The
pass only touches Middleware's own PostgreSQL tables; it never calls Telnexa,
never sends SMS and is a no-op unless Telnexa event ingress is enabled.
Schedule it externally (systemd timer / cron); it exits after one batch.
"""

from __future__ import annotations

import asyncio
import json

from app.api.internal.telnexa_events import reconcile_telnexa_inbox
from app.core.config import Settings
from app.db import session as db_session


async def main() -> int:
    settings = Settings.from_env()
    if not settings.telnexa_event_ingress_enabled:
        print(json.dumps({"status": "disabled", "scanned": 0}))
        return 0
    settings.validate_telnexa_callback_trust()
    db_session.configure(settings)
    try:
        async with db_session.SessionFactory() as db:
            summary = await reconcile_telnexa_inbox(
                db,
                max_attempts=settings.telnexa_event_reconcile_max_attempts,
                batch_size=settings.telnexa_event_reconcile_batch_size,
            )
    finally:
        await db_session.dispose()
    print(json.dumps({"status": "complete", **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
