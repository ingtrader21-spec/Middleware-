from __future__ import annotations

import os
import socket
import time

from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, select

from .api import build_app
from .models import Notification, Outbox, Status
from .metrics import dead_letter_count, oldest_outbox_age, outbox_depth, retry_count
from .schema import Sessions
from .security import TokenValidator
from .worker import Worker
validator = TokenValidator(os.environ["BEYVRA_EMAIL_ISSUER"], os.getenv("BEYVRA_EMAIL_AUDIENCE", "codestra-email"), os.environ["BEYVRA_EMAIL_JWKS_URL"])
app = build_app(Sessions, validator)


@app.get("/metrics")
def metrics() -> Response:
    with Sessions() as db:
        rows = db.scalars(select(Outbox).where(Outbox.status == "QUEUED")).all()
        outbox_depth.set(len(rows))
        oldest_outbox_age.set(max((time.time() - row.created_at.timestamp() for row in rows), default=0))
        retry_count.set(sum(row.attempt_count for row in rows))
        dead_letter_count.set(db.scalar(select(func.count()).select_from(Notification).where(Notification.status == Status.DEAD_LETTER)) or 0)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def worker_main() -> None:
    if os.getenv("LIVE_EMAIL_DELIVERY", "false").lower() != "true":
        raise RuntimeError("live_email_delivery_disabled")
    worker = Worker(Sessions, os.getenv("HOSTNAME", socket.gethostname()))
    while True:
        claimed = worker.claim()
        for notification_id in claimed:
            worker.deliver(notification_id)
        time.sleep(1 if claimed else 5)
