"""Fast-ACK VICIdial ingress; PostgreSQL commit is the durability boundary."""

import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.call_lifecycle import correlation_id as call_correlation_id, transition
from app.core.security import SecurityError, payload_hash, verify_ingestion_signature
from app.api.v1.publisher import _quarantine, _security_rejection
from app.db.models import (
    AuditEvent,
    IdempotencyRecord,
    IntegrationDelivery,
    IntegrationEvent,
    PublisherNonce,
    TelephonyCallLifecycle,
    TelephonyCallLifecycleEvent,
)
from app.db.session import get_session
from app.schemas.registry import Envelope, parse_event

router = APIRouter(prefix="/api/v1/events", tags=["events"])

# Compatibility import for older callers; unlike the previous permissive model,
# this is now the strict canonical envelope.
VicidialEvent = Envelope


def _entity_key(event_type: str, payload: dict) -> str | None:
    for field in ("call_id", "callback_id", "agent_id", "campaign_id"):
        if value := payload.get(field):
            return f"{field}:{value}"
    return None


def _is_lifecycle(envelope: Envelope) -> bool:
    return envelope.event_type in {
        "vicidial.call.started",
        "vicidial.call.connected",
    } or (
        envelope.event_type == "vicidial.call.ended"
        and "lifecycle_status" in envelope.payload
    )


@router.post("/vicidial", status_code=status.HTTP_202_ACCEPTED)
async def ingest_vicidial(
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    signature: str | None = Header(default=None, alias="X-Signature"),
    timestamp: str | None = Header(default=None, alias="X-Timestamp"),
    client_instance: str | None = Header(default=None, alias="X-Client-Instance-ID"),
    x_correlation_id: str | None = Header(default=None, alias="X-Correlation-ID"),
    nonce: str | None = Header(default=None, alias="X-Nonce"),
    db: AsyncSession = Depends(get_session),
):
    body = await request.body()
    if len(body) > settings.request_max_bytes:
        raise HTTPException(413, "request too large")
    if not client_instance or client_instance not in settings.ingestion_clients:
        await _security_rejection(
            db,
            request,
            body,
            "missing_authentication" if not client_instance else "unknown_key",
        )
        raise HTTPException(401, "client identity is not authorized")
    try:
        verify_ingestion_signature(
            body,
            timestamp or "",
            signature or "",
            settings.ingestion_hmac_secret,
            ttl=settings.signature_ttl_seconds,
        )
    except SecurityError as exc:
        reason = {
            "missing signature credentials": "missing_authentication",
            "invalid signature timestamp": "invalid_timestamp",
            "expired signature": "expired_timestamp",
            "invalid signature": "invalid_signature",
        }.get(str(exc), "invalid_signature")
        await _security_rejection(db, request, body, reason)
        raise HTTPException(401, "request authentication failed") from exc
    if not nonce or len(nonce) > 128:
        await _security_rejection(db, request, body, "missing_authentication")
        raise HTTPException(401, "request nonce is missing or invalid")
    replay = await db.scalar(
        select(PublisherNonce).where(
            PublisherNonce.key_id == client_instance,
            PublisherNonce.nonce == nonce,
        )
    )
    if replay:
        await _security_rejection(db, request, body, "replayed_nonce")
        raise HTTPException(401, "request replay rejected")
    db.add(
        PublisherNonce(
            key_id=client_instance,
            nonce=nonce,
            signed_at=int(timestamp or "0"),
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=settings.signature_ttl_seconds),
        )
    )
    try:
        envelope, parsed_payload = parse_event(body, settings.enabled_events)
    except (ValidationError, ValueError) as exc:
        try:
            await _quarantine(
                db,
                request,
                body,
                key_id=client_instance,
                publisher_id=client_instance,
                reason="schema_rejected",
                parsed=None,
                source_label="vicidial",
            )
        except Exception as persistence_error:
            await db.rollback()
            raise HTTPException(
                503, "quarantine persistence unavailable"
            ) from persistence_error
        raise HTTPException(422, "event schema validation failed") from exc
    if envelope.client_instance != client_instance:
        await _quarantine(
            db,
            request,
            body,
            key_id=client_instance,
            publisher_id=client_instance,
            reason="publisher_identity_mismatch",
            parsed=envelope.model_dump(mode="json"),
            source_label="vicidial",
        )
        raise HTTPException(401, "client identity mismatch")
    if not idempotency_key or len(idempotency_key) > 255:
        await _quarantine(
            db,
            request,
            body,
            key_id=client_instance,
            publisher_id=client_instance,
            reason="schema_rejected",
            parsed=envelope.model_dump(mode="json"),
            source_label="vicidial",
        )
        raise HTTPException(400, "idempotency key is missing or invalid")
    if _is_lifecycle(envelope) and idempotency_key != str(envelope.event_id):
        await _quarantine(
            db,
            request,
            body,
            key_id=client_instance,
            publisher_id=client_instance,
            reason="event_id_mismatch",
            parsed=envelope.model_dump(mode="json"),
            source_label="vicidial",
        )
        raise HTTPException(400, "idempotency key must equal event ID")

    request_hash = payload_hash(body)
    key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
    scope = f"vicidial:{client_instance}"
    corr = request.state.correlation_id
    if _is_lifecycle(envelope):
        corr = call_correlation_id(
            envelope.asterisk_linked_id, envelope.asterisk_unique_id or ""
        )
        request.state.correlation_id = corr
    # Transaction-scoped advisory lock prevents a concurrent duplicate from
    # creating a second logical persistence set.
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
        {"value": f"{scope}:{key_hash}"},
    )
    existing = await db.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.scope == scope, IdempotencyRecord.key_hash == key_hash
        )
    )
    if existing:
        if existing.request_hash != request_hash:
            await db.rollback()
            await _quarantine(
                db,
                request,
                body,
                key_id=client_instance,
                publisher_id=client_instance,
                reason="event_id_mismatch",
                parsed=envelope.model_dump(mode="json"),
                source_label="vicidial",
            )
            raise HTTPException(409, "idempotency key conflict")
        await db.commit()
        result = dict(existing.response)
        response.headers.update(
            {
                "X-Correlation-ID": str(result["correlation_id"]),
                "X-Event-ID": str(result["event_id"]),
                "X-Idempotent-Replay": "true",
                "X-Schema-Version": "1.0",
            }
        )
        return result

    payload = parsed_payload.model_dump(mode="json")
    incoming = IntegrationEvent(
        idempotency_key=key_hash,
        event_type=envelope.event_type,
        schema_version=envelope.schema_version,
        original_event_id=str(envelope.event_id),
        entity_key=_entity_key(envelope.event_type, payload),
        source_system="vicidial",
        correlation_id=corr,
        payload_json=payload,
        payload_hash=request_hash,
        state="accepted",
    )
    db.add(incoming)
    await db.flush()
    if _is_lifecycle(envelope):
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
            {"value": f"telephony-lifecycle:{corr}"},
        )
        call = await db.scalar(
            select(TelephonyCallLifecycle)
            .where(TelephonyCallLifecycle.correlation_id == corr)
            .with_for_update()
        )
        incoming_state = payload["lifecycle_status"]
        previous = call.lifecycle_state if call else None
        decision = transition(previous, incoming_state)
        if call is None:
            call = TelephonyCallLifecycle(
                correlation_id=corr,
                linked_id=envelope.asterisk_linked_id,
                primary_unique_id=envelope.asterisk_unique_id,
                lifecycle_state=decision.resulting,
                source_extension=envelope.source_extension,
                destination=envelope.destination,
                dialplan_context=envelope.dialplan_context,
            )
            db.add(call)
            await db.flush()
        elif decision.applied:
            call.lifecycle_state = decision.resulting
        if incoming_state == "STARTED" and call.started_at is None:
            call.started_at = envelope.occurred_at
        elif incoming_state == "CONNECTED" and call.connected_at is None:
            call.connected_at = envelope.occurred_at
        elif incoming_state == "ENDED" and call.ended_at is None:
            call.ended_at = envelope.occurred_at
            if decision.applied:
                call.disposition = payload.get("disposition")
                call.hangup_cause = payload.get("hangup_cause")
        db.add(
            TelephonyCallLifecycleEvent(
                call_id=call.id,
                integration_event_id=incoming.id,
                original_event_id=str(envelope.event_id),
                unique_id=envelope.asterisk_unique_id,
                channel=envelope.channel,
                incoming_state=incoming_state,
                previous_state=previous,
                resulting_state=decision.resulting,
                transition_applied=decision.applied,
                occurred_at=envelope.occurred_at,
            )
        )
    for target in ("odoo", "n8n"):
        db.add(
            IntegrationDelivery(
                event_id=incoming.id,
                target=target,
                status="disabled",
                max_attempts=settings.outbox_max_attempts,
            )
        )
    result = {
        "accepted": True,
        "event_id": str(incoming.id),
        "status": "accepted",
        "correlation_id": corr,
    }
    db.add(
        IdempotencyRecord(
            scope=scope,
            key_hash=key_hash,
            request_hash=request_hash,
            response=result,
            status_code=202,
            event_id=incoming.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
    )
    db.add(
        AuditEvent(
            action="vicidial.event.accepted",
            subject=str(incoming.id),
            correlation_id=corr,
            decision="accepted",
            redacted_payload={
                "event_type": envelope.event_type,
                "schema_version": "1.0",
            },
        )
    )
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(503, "durable persistence unavailable")
    response.headers.update(
        {
            "X-Correlation-ID": corr,
            "X-Event-ID": str(incoming.id),
            "X-Idempotent-Replay": "false",
            "X-Schema-Version": "1.0",
        }
    )
    return result
