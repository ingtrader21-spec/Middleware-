"""Contract-v2 receiver: commit event, replay nonce, and acknowledgement together."""

import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from prometheus_client import Counter, Gauge
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.publisher_auth import (
    PublisherAuthenticationError,
    validate_publisher_timestamp,
    verify_publisher_signature,
)
from app.core.quarantine import encrypt_payload, fingerprint, sanitized_preview
from app.db.models import (
    IntegrationEvent,
    InvalidEventQuarantine,
    PublisherAcknowledgement,
    PublisherNonce,
    SecurityRejection,
)
from app.db.session import get_session

router = APIRouter(prefix="/api/v2/telephony", tags=["telephony-publisher"])
REASON_CODES = frozenset(
    {
        "malformed_json",
        "schema_rejected",
        "policy_rejected",
        "publisher_identity_mismatch",
        "event_id_mismatch",
    }
)
AUTH_REASONS = frozenset(
    {
        "missing_authentication",
        "unknown_key",
        "invalid_signature",
        "altered_body",
        "invalid_timestamp",
        "expired_timestamp",
        "future_timestamp",
        "replayed_nonce",
    }
)
QUARANTINE_EVENTS = Counter(
    "quarantine_events_total",
    "Authenticated invalid events",
    ["reason_code", "source", "authentication_state"],
)
SECURITY_REJECTIONS = Counter(
    "security_rejections_total",
    "Rejected unauthenticated requests",
    ["reason_code", "source", "authentication_state"],
)
QUARANTINE_PENDING = Gauge(
    "quarantine_pending_records", "Authenticated records pending review"
)
QUARANTINE_OLDEST = Gauge(
    "quarantine_oldest_pending_seconds", "Age of oldest pending record"
)
ACCEPTED_EVENTS = Counter(
    "canonical_events_accepted_total", "Canonical events accepted", ["source"]
)


def _source_class(request: Request) -> str:
    try:
        address = ipaddress.ip_address(request.client.host if request.client else "")
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private"
    return "public"


def _bounded(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return (
        "".join(
            character
            for character in value
            if character.isalnum() or character in "._:-"
        )[:limit]
        or None
    )


async def _security_rejection(
    db: AsyncSession, request: Request, body: bytes, reason: str
) -> None:
    bounded_reason = reason if reason in AUTH_REASONS else "invalid_signature"
    source = _source_class(request)
    db.add(
        SecurityRejection(
            correlation_id=request.state.correlation_id,
            claimed_publisher=_bounded(
                request.headers.get("X-Codestra-Publisher-ID")
                or request.headers.get("X-Client-Instance-ID"),
                128,
            ),
            authentication_state="UNVERIFIED",
            key_id=_bounded(request.headers.get("X-Codestra-Key-ID"), 64),
            reason_code=bounded_reason,
            payload_fingerprint=fingerprint(
                body, settings.quarantine_fingerprint_secret
            ),
            source_ip_classification=source,
        )
    )
    await db.commit()
    SECURITY_REJECTIONS.labels(bounded_reason, source, "UNVERIFIED").inc()


async def _quarantine(
    db: AsyncSession,
    request: Request,
    body: bytes,
    *,
    key_id: str,
    publisher_id: str,
    reason: str,
    parsed: object | None,
    source_label: str = "telephony",
) -> None:
    bounded_reason = reason if reason in REASON_CODES else "schema_rejected"
    digest = fingerprint(body, settings.quarantine_fingerprint_secret)
    encrypted = None
    if settings.quarantine_store_authenticated_raw:
        encrypted = encrypt_payload(
            body,
            settings.quarantine_encryption_key,
            settings.quarantine_encryption_key_version,
            digest,
        )
    preview = sanitized_preview(body)
    claimed_source = preview.get("source_system")
    claimed_publisher = preview.get("client_instance")
    business_unit = preview.get("business_unit")
    now = datetime.now(timezone.utc)
    existing = await db.scalar(
        select(InvalidEventQuarantine)
        .where(
            InvalidEventQuarantine.authenticated_publisher_id == publisher_id,
            InvalidEventQuarantine.payload_fingerprint == digest,
        )
        .with_for_update()
    )
    if existing:
        existing.last_seen_at = now
        existing.occurrence_count += 1
        existing.record_version += 1
    else:
        db.add(
            InvalidEventQuarantine(
                server_correlation_id=request.state.correlation_id,
                client_correlation_id=request.state.client_correlation_id,
                claimed_source=_bounded(str(claimed_source), 64)
                if claimed_source
                else None,
                claimed_publisher_identity=(
                    _bounded(str(claimed_publisher), 128) if claimed_publisher else None
                ),
                authenticated_publisher_id=publisher_id,
                authentication_state="VERIFIED",
                authentication_key_id=key_id,
                original_signature_verification="VERIFIED",
                payload_fingerprint=digest,
                encrypted_payload=encrypted.ciphertext if encrypted else None,
                encryption_nonce=encrypted.nonce if encrypted else None,
                encryption_key_version=encrypted.key_version if encrypted else None,
                sanitized_preview=preview,
                reason_code=bounded_reason,
                business_unit=_bounded(str(business_unit), 16)
                if business_unit
                else None,
                status="PENDING_REVIEW",
                retention_policy_version=settings.quarantine_retention_policy_version,
                retention_deadline=now
                + timedelta(days=settings.quarantine_retention_days),
                received_at=now,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    await db.commit()
    QUARANTINE_EVENTS.labels(bounded_reason, source_label, "VERIFIED").inc()


def ack(event_id, status, duplicate, retryable, reason_code, acknowledgement_id=None):
    return {
        "schema_version": "2.0",
        "event_id": event_id,
        "acknowledgement_id": str(acknowledgement_id or uuid4()),
        "receiver_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "duplicate": duplicate,
        "retryable": retryable,
        "reason_code": reason_code,
    }


def validate_event(value):
    required = {
        "schema_version",
        "event_id",
        "event_type",
        "source_system",
        "created_at",
        "occurred_at",
        "boot_session_id",
        "sequence",
        "call_uniqueid",
        "correlation_id",
        "business_unit",
        "campaign",
        "agent_id",
        "customer_reference",
        "payload",
        "policy_decision",
        "recording_reference",
        "delivery",
        "privacy",
        "idempotency",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("schema_rejected")
    if value["schema_version"] != "2.0":
        raise ValueError("schema_rejected")
    UUID(value["event_id"])
    if value["event_type"] != "synthetic.publisher_canary":
        raise PermissionError("policy_rejected")
    privacy = value["privacy"]
    if privacy != {"classification": "synthetic", "contains_customer_data": False}:
        raise PermissionError("policy_rejected")
    expires = datetime.fromisoformat(
        value["delivery"]["expires_at"].replace("Z", "+00:00")
    )
    if expires <= datetime.now(timezone.utc):
        raise PermissionError("policy_rejected")
    if value["campaign"] != "TEST_SYN":
        raise PermissionError("policy_rejected")


@router.post("/canary", status_code=202)
async def receive_canary(request: Request, db: AsyncSession = Depends(get_session)):
    if not settings.publisher_canary_enabled:
        raise HTTPException(404, "canary route disabled")
    body = await request.body()
    if len(body) > settings.request_max_bytes:
        raise HTTPException(413, "request too large")
    try:
        key_id, nonce, signed_at, header_event_id = verify_publisher_signature(
            body, request.headers, settings.publisher_hmac_keys
        )
    except PublisherAuthenticationError as exc:
        try:
            await _security_rejection(db, request, body, str(exc))
        except Exception:
            await db.rollback()
        raise HTTPException(401, "request authentication failed") from exc
    try:
        validate_publisher_timestamp(signed_at, window=settings.signature_ttl_seconds)
    except PublisherAuthenticationError as exc:
        await _security_rejection(db, request, body, str(exc))
        raise HTTPException(401, "request authentication failed") from exc
    replay = await db.scalar(
        select(PublisherNonce).where(
            PublisherNonce.key_id == key_id, PublisherNonce.nonce == nonce
        )
    )
    if replay:
        await _security_rejection(db, request, body, "replayed_nonce")
        raise HTTPException(401, "request replay rejected")
    db.add(
        PublisherNonce(
            key_id=key_id,
            nonce=nonce,
            signed_at=signed_at,
            expires_at=datetime.now(timezone.utc),
        )
    )
    invalid_reason = None
    parsed = None
    try:
        value = json.loads(body)
        parsed = value
        validate_event(value)
        if value["event_id"] != header_event_id:
            raise ValueError("event_id_mismatch")
    except PermissionError:
        invalid_reason = "policy_rejected"
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        invalid_reason = (
            "malformed_json"
            if isinstance(exc, json.JSONDecodeError)
            else str(exc)
            if str(exc) in REASON_CODES
            else "schema_rejected"
        )
    if invalid_reason:
        try:
            await _quarantine(
                db,
                request,
                body,
                key_id=key_id,
                publisher_id=key_id,
                reason=invalid_reason,
                parsed=parsed,
            )
        except Exception as exc:
            await db.rollback()
            raise HTTPException(503, "quarantine persistence unavailable") from exc
        raise HTTPException(
            403 if invalid_reason == "policy_rejected" else 422,
            invalid_reason,
        )
    digest = hashlib.sha256(body).hexdigest()
    event_id = value["event_id"]
    existing = await db.scalar(
        select(IntegrationEvent).where(IntegrationEvent.original_event_id == event_id)
    )
    if existing:
        if existing.payload_hash != digest:
            raise HTTPException(409, "idempotency_conflict")
        prior = await db.scalar(
            select(PublisherAcknowledgement).where(
                PublisherAcknowledgement.event_id == event_id
            )
        )
        result = ack(
            event_id,
            "duplicate",
            True,
            False,
            "already_accepted",
            prior.acknowledgement_id if prior else None,
        )
        try:
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            raise HTTPException(401, "request replay rejected") from exc
        return result
    acknowledgement_id = uuid4()
    result = ack(
        event_id, "accepted", False, False, "durably_accepted", acknowledgement_id
    )
    incoming = IntegrationEvent(
        idempotency_key=value["idempotency"]["key"],
        event_type=value["event_type"],
        schema_version="2.0",
        original_event_id=event_id,
        entity_key="synthetic:publisher-canary",
        source_system="asterisk-ami",
        correlation_id=request.state.correlation_id,
        payload_json=value,
        payload_hash=digest,
        state="accepted",
    )
    db.add(incoming)
    db.add(
        PublisherAcknowledgement(
            acknowledgement_id=acknowledgement_id,
            event_id=event_id,
            status="accepted",
            duplicate=False,
            retryable=False,
            reason_code="durably_accepted",
            acknowledgement=result,
        )
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(401, "request replay rejected") from exc
    except Exception as exc:
        await db.rollback()
        raise HTTPException(503, "durable persistence unavailable") from exc
    ACCEPTED_EVENTS.labels("telephony").inc()
    return result
