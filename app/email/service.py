from __future__ import annotations

import hashlib
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import DeadLetter, Notification, Outbox, Status, Suppression, TemplateVersion, utcnow
from .metrics import created, failed, queued, suppressed as suppressed_metric
from .templates import SENDERS, TEMPLATE_CATEGORY

EMAIL_FORBIDDEN = frozenset(" <>@,;\r\n\t")
PERMANENT = {"INVALID_RECIPIENT", "HARD_BOUNCE", "SUPPRESSED", "POLICY_REJECTION"}
RETRY_DELAYS = (30, 120, 600, 3600, 14400)


def recipient_hash(recipient: str) -> str:
    return hashlib.sha256(recipient.strip().lower().encode()).hexdigest()


def _valid_recipient(recipient: str) -> bool:
    """Apply bounded structural validation without backtracking regexes."""
    if not recipient or len(recipient) > 320 or recipient.count("@") != 1:
        return False
    local, domain = recipient.split("@")
    if not local or len(local) > 64 or not domain or "." not in domain:
        return False
    labels = domain.split(".")
    return (
        all(labels)
        and all(not label.startswith("-") and not label.endswith("-") for label in labels)
        and not any(character in EMAIL_FORBIDDEN for character in recipient)
    )


def create_notification(db: Session, tenant_id: str, body: dict) -> tuple[Notification, bool]:
    required = {"event_id", "correlation_id", "idempotency_key", "user_id", "account_id", "template_id", "template_version", "recipient", "event_type", "category", "locale", "parameters"}
    if missing := sorted(required - body.keys()):
        raise ValueError("missing_fields:" + ",".join(missing))
    category, template_id = str(body["category"]).upper(), str(body["template_id"])
    if TEMPLATE_CATEGORY.get(template_id) != category:
        raise ValueError("template_category_mismatch")
    recipient = str(body["recipient"]).strip().lower()
    if not _valid_recipient(recipient):
        raise ValueError("invalid_recipient")
    digest = recipient_hash(recipient)
    existing = db.scalar(select(Notification).where(Notification.tenant_id == tenant_id, Notification.idempotency_key == str(body["idempotency_key"])))
    if existing:
        invariant = (existing.event_id, existing.template_id, existing.recipient_hash)
        if invariant != (str(body["event_id"]), template_id, digest):
            raise ValueError("idempotency_conflict")
        return existing, True
    template = db.get(TemplateVersion, (template_id, int(body["template_version"]), str(body["locale"])))
    if not template or not template.active:
        raise ValueError("template_version_not_active")
    suppressed = db.scalar(select(Suppression).where(Suppression.tenant_id == tenant_id, Suppression.recipient_hash == digest, Suppression.active.is_(True)))
    stamp = utcnow()
    notification = Notification(
        event_id=str(body["event_id"]), correlation_id=str(body["correlation_id"]), idempotency_key=str(body["idempotency_key"]),
        user_id=str(body["user_id"]), account_id=str(body["account_id"]), tenant_id=tenant_id,
        template_id=template_id, template_version=int(body["template_version"]), recipient=recipient, recipient_hash=digest,
        sender=SENDERS[category], event_type=str(body["event_type"]), category=category, locale=str(body["locale"]),
        parameters=dict(body["parameters"]), status=Status.SUPPRESSED if suppressed else Status.QUEUED, queued_at=stamp,
    )
    db.add(notification)
    db.flush()
    if not suppressed:
        db.add(Outbox(notification_id=notification.notification_id, status="QUEUED", available_at=stamp))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return create_notification(db, tenant_id, body)
    created.inc()
    if suppressed:
        suppressed_metric.inc()
    else:
        queued.inc()
    return notification, False


def record_failure(db: Session, notification: Notification, outbox: Outbox, error_class: str, safe_detail: str) -> None:
    outbox.attempt_count += 1
    notification.attempt_count = outbox.attempt_count
    notification.last_error_class = error_class
    outbox.last_error_class = error_class
    outbox.lease_owner = None
    outbox.lease_expires_at = None
    if error_class in PERMANENT or outbox.attempt_count >= len(RETRY_DELAYS):
        notification.status = Status.DEAD_LETTER
        outbox.status = "DEAD_LETTER"
        db.merge(DeadLetter(notification_id=notification.notification_id, error_class=error_class,
                            error_digest=hashlib.sha256(safe_detail.encode()).hexdigest(), attempt_count=outbox.attempt_count))
        failed.inc()
    else:
        notification.status = Status.DEFERRED
        outbox.status = "QUEUED"
        outbox.available_at = utcnow() + timedelta(seconds=RETRY_DELAYS[outbox.attempt_count - 1])
    outbox.updated_at = utcnow()
    db.commit()
