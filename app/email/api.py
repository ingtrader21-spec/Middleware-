from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from .contracts import BEYVRA_TENANT_ID, MAX_BODY_BYTES, ingest_inbound, validate_event
from .models import DeadLetter, DeliveryEvent, Notification, Outbox, Status, Suppression, utcnow
from .metrics import bounced, complaints, delivered, postal_latency, suppressed as suppressed_metric
from .security import AuthorizationError, Principal, TokenValidator
from .service import create_notification

STATUS_MAP = {
    "accepted": Status.SUBMITTED, "submitted": Status.SUBMITTED, "sent": Status.SENT,
    "delivered": Status.DELIVERED, "deferred": Status.DEFERRED, "soft_bounce": Status.BOUNCED_SOFT,
    "hard_bounce": Status.BOUNCED_HARD, "complaint": Status.COMPLAINED, "suppressed": Status.SUPPRESSED,
    "failed": Status.FAILED,
}


def build_app(sessions: sessionmaker[Session], validator: TokenValidator) -> FastAPI:
    app = FastAPI(title="Codestra Beyvra Email API", version="1.0.0")

    def principal(required: str):
        def dependency(authorization: str = Header(default="")) -> Principal:
            if not authorization.startswith("Bearer "):
                raise HTTPException(401, "bearer_token_required")
            try:
                return validator.validate(authorization[7:], required)
            except AuthorizationError as exc:
                raise HTTPException(403 if str(exc) == "insufficient_scope" else 401, str(exc)) from exc
        return dependency

    async def provider_request(request: Request, actor: Principal) -> tuple[bytes, dict, str]:
        if request.headers.get("X-Codestra-Client-Cert-Verified") != "SUCCESS":
            raise HTTPException(401, "provider_mtls_required")
        if actor.service != "klyrow-email-provider" or actor.tenant_id != BEYVRA_TENANT_ID:
            raise HTTPException(403, "provider_tenant_binding_invalid")
        try:
            content_length = int(request.headers.get("content-length", "0"))
        except ValueError as exc:
            raise HTTPException(400, "invalid_content_length") from exc
        if content_length > MAX_BODY_BYTES:
            raise HTTPException(413, "payload_too_large")
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(413, "payload_too_large")
        timestamp = request.headers.get("X-Klyrow-Timestamp", "")
        event_id = request.headers.get("X-Klyrow-Event-Id", "")
        signature = request.headers.get("X-Klyrow-Signature", "").removeprefix("sha256=")
        try:
            if abs(int(time.time()) - int(timestamp)) > 300 or not event_id:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(401, "invalid_or_expired_timestamp") from exc
        secret = _secret("BEYVRA_PROVIDER_WEBHOOK_SECRET_FILE")
        expected = hmac.new(secret.encode(), timestamp.encode() + b"\n" + event_id.encode() + b"\n" + raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(401, "invalid_request_signature")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, "invalid_event_payload") from exc
        if str(value.get("event_id", "")) != event_id:
            raise HTTPException(422, "event_id_mismatch")
        return raw, value, event_id

    @app.get("/v1/email/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/v1/email/ready")
    def ready() -> dict:
        try:
            with sessions() as db:
                db.execute(text("SELECT 1"))
        except Exception as exc:
            raise HTTPException(503, "database_unavailable") from exc
        return {"status": "ready"}

    @app.post("/v1/email/messages", status_code=202)
    @app.post("/v1/beyvra/email/messages", status_code=202)
    async def create(request: Request, actor: Principal = Depends(principal("email.send"))) -> dict:
        try:
            body = await request.json()
            with sessions() as db:
                notification, duplicate = create_notification(db, actor.tenant_id, body)
        except (ValueError, json.JSONDecodeError) as exc:
            status = 409 if str(exc) == "idempotency_conflict" else 422
            raise HTTPException(status, str(exc)) from exc
        return public(notification) | {"duplicate": duplicate}

    @app.post("/internal/v1/beyvra/email/inbound", status_code=202)
    async def inbound(request: Request, actor: Principal = Depends(principal("email.inbound"))) -> dict:
        raw, value, event_id = await provider_request(request, actor)
        try:
            with sessions() as db:
                case, message, duplicate = ingest_inbound(db, actor.service, value, hashlib.sha256(raw).hexdigest())
        except ValueError as exc:
            code = 409 if str(exc) == "webhook_replay" else 403 if "denied" in str(exc) or "mapped" in str(exc) else 422
            raise HTTPException(code, str(exc)) from exc
        return {"accepted": True, "event_id": event_id, "case_id": case.id,
                "message_id": message.id, "duplicate": duplicate}

    @app.post("/internal/v1/beyvra/email/delivery-events", status_code=202)
    async def delivery_event(request: Request, actor: Principal = Depends(principal("email.delivery_event"))) -> dict:
        raw, value, event_id = await provider_request(request, actor)
        try:
            validate_event(value)
        except (ValueError, TypeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        normalized = {
            "DELIVERY_ACCEPTED": Status.SUBMITTED, "DELIVERY_SENT": Status.SENT,
            "DELIVERY_DELIVERED": Status.DELIVERED, "DELIVERY_DEFERRED": Status.DEFERRED,
            "BOUNCE_SOFT": Status.BOUNCED_SOFT, "BOUNCE_HARD": Status.BOUNCED_HARD,
            "COMPLAINT": Status.COMPLAINED, "FAILED": Status.FAILED, "SUPPRESSED": Status.SUPPRESSED,
        }.get(str(value["event_type"]))
        if normalized is None:
            raise HTTPException(422, "invalid_delivery_event_type")
        provider_id = str(value.get("provider_message_id", ""))
        with sessions() as db:
            existing = db.scalar(select(DeliveryEvent).where(DeliveryEvent.provider_event_id == event_id))
            if existing:
                return {"accepted": True, "event_id": event_id, "duplicate": True,
                        "notification_id": existing.notification_id}
            message = db.scalar(select(Notification).where(Notification.provider_message_id == provider_id,
                                                            Notification.tenant_id == BEYVRA_TENANT_ID))
            if not message:
                raise HTTPException(404, "provider_message_unknown")
            occurred = datetime.fromisoformat(str(value["occurred_at"]).replace("Z", "+00:00"))
            db.add(DeliveryEvent(provider_event_id=event_id, provider_message_id=provider_id,
                                 notification_id=message.notification_id, correlation_id=message.correlation_id,
                                 event_type=str(value["event_type"]), normalized_status=normalized,
                                 payload_digest=hashlib.sha256(raw).hexdigest(), occurred_at=occurred))
            message.status = normalized
            if normalized == Status.SENT:
                message.sent_at = occurred
            elif normalized == Status.DELIVERED:
                message.delivered_at = occurred
            db.commit()
        return {"accepted": True, "event_id": event_id, "duplicate": False,
                "notification_id": message.notification_id}

    @app.get("/v1/email/messages/{notification_id}")
    def get(notification_id: str, actor: Principal = Depends(principal("email.read"))) -> dict:
        with sessions() as db:
            row = db.scalar(select(Notification).where(Notification.notification_id == notification_id, Notification.tenant_id == actor.tenant_id))
            if not row:
                raise HTTPException(404, "notification_not_found")
            return public(row)

    @app.post("/v1/email/messages/{notification_id}/retry", status_code=202)
    def retry(notification_id: str, actor: Principal = Depends(principal("email.retry"))) -> dict:
        with sessions() as db:
            row = db.scalar(select(Notification).where(Notification.notification_id == notification_id, Notification.tenant_id == actor.tenant_id))
            if not row or row.status != Status.DEAD_LETTER:
                raise HTTPException(404, "dead_letter_not_found")
            outbox = db.get(Outbox, notification_id)
            if outbox is None:
                raise HTTPException(409, "dead_letter_outbox_missing")
            outbox.status, outbox.available_at, outbox.attempt_count = "QUEUED", utcnow(), 0
            row.status, row.last_error_class = Status.QUEUED, None
            dead = db.get(DeadLetter, notification_id)
            if dead is not None:
                dead.replayed_at = utcnow()
            db.commit()
            return public(row)

    @app.post("/v1/webhooks/postal-native", status_code=202)
    async def postal(request: Request) -> dict:
        started = time.monotonic()
        raw = await request.body()
        timestamp, event_id = request.headers.get("X-Klyrow-Timestamp", ""), request.headers.get("X-Klyrow-Event-Id", "")
        signature, authorization = request.headers.get("X-Klyrow-Signature", ""), request.headers.get("Authorization", "")
        secret, token = _secret("POSTAL_WEBHOOK_SECRET_FILE"), _secret("POSTAL_WEBHOOK_TOKEN_FILE")
        try:
            if abs(int(time.time()) - int(timestamp)) > 300 or not event_id:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(401, "invalid_or_expired_timestamp") from exc
        expected = hmac.new(secret.encode(), timestamp.encode() + b"\n" + event_id.encode() + b"\n" + raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(authorization, "Bearer " + token) or not hmac.compare_digest(signature.removeprefix("sha256="), expected):
            raise HTTPException(401, "invalid_webhook_authentication")
        try:
            value = json.loads(raw)
            provider_id, raw_status = str(value["provider_message_id"]), str(value["status"]).lower()
            occurred = datetime.fromisoformat(str(value["occurred_at"]).replace("Z", "+00:00"))
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(422, "invalid_webhook_payload") from exc
        if raw_status not in STATUS_MAP:
            raise HTTPException(422, "unsupported_provider_status")
        with sessions() as db:
            if db.scalar(select(DeliveryEvent).where(DeliveryEvent.provider_event_id == event_id)):
                raise HTTPException(409, "webhook_replay")
            message = db.scalar(select(Notification).where(Notification.provider_message_id == provider_id))
            if not message:
                raise HTTPException(404, "provider_message_unknown")
            status = STATUS_MAP[raw_status]
            db.add(DeliveryEvent(provider_event_id=event_id, provider_message_id=provider_id,
                                 notification_id=message.notification_id, correlation_id=message.correlation_id,
                                 event_type=str(value.get("event_type", raw_status)), normalized_status=status,
                                 payload_digest=hashlib.sha256(raw).hexdigest(), occurred_at=occurred))
            message.status = status
            if status == Status.SENT:
                message.sent_at = occurred
            elif status == Status.DELIVERED:
                message.delivered_at = occurred
            if status in {Status.BOUNCED_HARD, Status.COMPLAINED, Status.SUPPRESSED}:
                reason = {Status.BOUNCED_HARD: "hard_bounce", Status.COMPLAINED: "complaint", Status.SUPPRESSED: "administrative"}[status]
                existing = db.scalar(select(Suppression).where(Suppression.tenant_id == message.tenant_id,
                                     Suppression.recipient_hash == message.recipient_hash, Suppression.reason == reason))
                if existing:
                    existing.active, existing.updated_at = True, utcnow()
                else:
                    db.add(Suppression(tenant_id=message.tenant_id, recipient_hash=message.recipient_hash, reason=reason))
            db.commit()
        postal_latency.observe(time.monotonic() - started)
        if status == Status.DELIVERED:
            delivered.inc()
        elif status in {Status.BOUNCED_SOFT, Status.BOUNCED_HARD}:
            bounced.labels(kind="soft" if status == Status.BOUNCED_SOFT else "hard").inc()
        elif status == Status.COMPLAINED:
            complaints.inc()
        elif status == Status.SUPPRESSED:
            suppressed_metric.inc()
        return {"accepted": True, "event_id": event_id, "notification_id": message.notification_id}

    return app


def public(row: Notification) -> dict:
    return {key: getattr(row, key).value if isinstance(getattr(row, key), Status) else getattr(row, key) for key in (
        "notification_id", "event_id", "correlation_id", "template_id", "template_version", "event_type", "category",
        "locale", "status", "attempt_count", "last_error_class", "provider_message_id", "created_at", "queued_at", "sent_at", "delivered_at")}


def _secret(name: str) -> str:
    try:
        with open(os.environ[name], encoding="utf-8") as handle:
            return handle.read().strip()
    except (KeyError, OSError) as exc:
        raise HTTPException(503, "webhook_credentials_unavailable") from exc
