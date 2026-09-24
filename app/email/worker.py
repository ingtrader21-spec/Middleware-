from __future__ import annotations

import os
import time
from datetime import timedelta

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from .models import Notification, Outbox, Status, TemplateVersion, utcnow
from .metrics import klyrow_latency, sent
from .service import record_failure
from .templates import render


class Worker:
    def __init__(self, sessions: sessionmaker[Session], worker_id: str, batch_size: int = 25):
        self.sessions, self.worker_id, self.batch_size = sessions, worker_id, min(batch_size, 100)

    def claim(self) -> list[str]:
        now = utcnow()
        with self.sessions() as db:
            rows = db.scalars(select(Outbox).where(
                Outbox.status == "QUEUED", Outbox.available_at <= now,
                or_(Outbox.lease_expires_at.is_(None), Outbox.lease_expires_at < now),
            ).order_by(Outbox.available_at).with_for_update(skip_locked=True).limit(self.batch_size)).all()
            for row in rows:
                row.status, row.lease_owner, row.lease_expires_at = "PROCESSING", self.worker_id, now + timedelta(seconds=60)
                message = db.get(Notification, row.notification_id)
                if message is None:
                    continue
                message.status = Status.PROCESSING
            db.commit()
            return [row.notification_id for row in rows]

    def deliver(self, notification_id: str) -> None:
        with self.sessions() as db:
            outbox, message = db.get(Outbox, notification_id), db.get(Notification, notification_id)
            if not outbox or not message or outbox.lease_owner != self.worker_id or outbox.status != "PROCESSING":
                return
            template = db.get(TemplateVersion, (message.template_id, message.template_version, message.locale))
            if template is None:
                return record_failure(db, message, outbox, "POLICY_REJECTION", "template_version_not_found")
            try:
                content = render(template.subject, template.text_body, template.html_body, message.parameters, template.required_variables)
                started = time.monotonic()
                try:
                    with httpx.Client(
                        cert=(os.environ["KLYROW_CERT_FILE"], os.environ["KLYROW_KEY_FILE"]),
                        verify=os.environ["KLYROW_CA_FILE"], timeout=10.0,
                    ) as client:
                        access_token = _klyrow_access_token()
                        response = client.post(
                            os.environ["KLYROW_SEND_URL"],
                            json={"notification_id": message.notification_id, "correlation_id": message.correlation_id,
                                  "sender": message.sender, "recipient": message.recipient, "subject": content.subject,
                                  "text": content.text, "html": content.html},
                            headers={"Idempotency-Key": message.notification_id,
                                     "Authorization": "Bearer " + access_token},
                        )
                finally:
                    klyrow_latency.observe(time.monotonic() - started)
                if response.status_code == 429:
                    raise ProviderFailure("RATE_LIMITED")
                if response.status_code >= 500:
                    raise ProviderFailure("TEMPORARY_PROVIDER_FAILURE")
                if response.status_code >= 400:
                    raise ProviderFailure("POLICY_REJECTION")
                provider_id = str(response.json()["provider_message_id"])
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                return record_failure(db, message, outbox, "NETWORK_FAILURE", type(exc).__name__)
            except ProviderFailure as exc:
                return record_failure(db, message, outbox, str(exc), str(exc))
            message.status, message.provider_message_id = Status.SUBMITTED, provider_id
            outbox.status, outbox.lease_owner, outbox.lease_expires_at, outbox.updated_at = "SUBMITTED", None, None, utcnow()
            db.commit()
            sent.inc()


class ProviderFailure(RuntimeError):
    pass


def _secret(name: str) -> str:
    with open(os.environ[name], encoding="utf-8") as handle:
        return handle.read().strip()


def _klyrow_access_token() -> str:
    """Obtain a short-lived token; never persist an access token on disk."""
    response = httpx.post(
        os.environ["KLYROW_OIDC_TOKEN_URL"],
        data={
            "grant_type": "client_credentials",
            "client_id": _secret("KLYROW_OIDC_CLIENT_ID_FILE"),
            "client_secret": _secret("KLYROW_OIDC_CLIENT_SECRET_FILE"),
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10.0,
    )
    response.raise_for_status()
    token = str(response.json().get("access_token", ""))
    if not token or token.count(".") != 2:
        raise ProviderFailure("INVALID_SERVICE_TOKEN")
    return token
