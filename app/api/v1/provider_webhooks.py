"""Signed VICIdial and Telnexa compatibility webhook ingress."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.odoo.webhooks import OdooWebhookAdapter
from app.core.config import settings
from app.core.security import SecurityError, verify_ingestion_signature
from app.db.models import (
    AuditEvent,
    IdempotencyRecord,
    IntegrationDelivery,
    IntegrationEvent,
    OdooResultDelivery,
    OutboxEvent,
)
from app.db.session import get_session


router = APIRouter(prefix="/webhooks", tags=["provider-webhooks"])

DISPOSITION_MAP = {
    "ANSWER": "answered",
    "NOANSWER": "no_answer",
    "BUSY": "busy",
    "SVUNREACH": "failed",
    "DONTCALL": "dnc",
    "CALLBK": "callback_requested",
    "VOICEMAIL": "voicemail",
    "SALE": "sale_completed",
    "DROP": "dropped",
    "NI": "not_interested",
}
_JSON_MEDIA_TYPE = "application/json"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VicidialCallResult(StrictModel):
    call_id: str = Field(min_length=1, max_length=128)
    phone_number: str = Field(pattern=r"^\+[1-9][0-9]{7,14}$")
    disposition: str
    call_time: int = Field(ge=0, le=86400)
    campaign_id: str = Field(min_length=1, max_length=128)
    comments: str | None = Field(default=None, max_length=2000)


class TelnexaInboundSms(StrictModel):
    message_id: str = Field(min_length=1, max_length=128)
    sender: str = Field(alias="from", pattern=r"^\+[1-9][0-9]{7,14}$")
    body: str = Field(min_length=1, max_length=10000)
    received_at: datetime


def _verify_signed_request(
    body: bytes, timestamp: str | None, supplied: str | None, secret: str
) -> None:
    """Provider webhooks sign ``"{timestamp}." + body`` with the shared secret.

    The timestamp is part of the MAC, so a captured request cannot be replayed
    with a fresh timestamp once the ``signature_ttl_seconds`` window passes.
    Same canonical form as ``/api/v1/events/vicidial``.
    """
    if not secret:
        raise HTTPException(503, "webhook authentication is unavailable")
    candidate = (supplied or "").removeprefix("sha256=").lower()
    if len(candidate) != 64:
        raise HTTPException(403, "webhook signature is invalid")
    try:
        verify_ingestion_signature(
            body,
            timestamp or "",
            candidate,
            secret,
            ttl=settings.signature_ttl_seconds,
        )
    except SecurityError as exc:
        detail = {
            "invalid signature timestamp": "webhook timestamp is invalid",
            "expired signature": "webhook timestamp is outside the allowed window",
        }.get(str(exc), "webhook signature is invalid")
        raise HTTPException(403, detail) from exc


async def _read_limited_json_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() != _JSON_MEDIA_TYPE:
        raise HTTPException(415, "webhook content type must be application/json")

    maximum = settings.request_max_bytes
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_length = int(declared)
        except ValueError as exc:
            raise HTTPException(400, "webhook content length is invalid") from exc
        if declared_length < 0:
            raise HTTPException(400, "webhook content length is invalid")
        if declared_length > maximum:
            raise HTTPException(413, "webhook payload exceeds the allowed size")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise HTTPException(413, "webhook payload exceeds the allowed size")
        body.extend(chunk)
    return bytes(body)


def _parse(model: type[BaseModel], body: bytes) -> BaseModel:
    try:
        return model.model_validate_json(body)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(400, "webhook payload is invalid") from exc


async def _persist(
    *,
    db: AsyncSession,
    response: Response,
    provider: str,
    external_id: str,
    event_type: str,
    entity_key: str,
    normalized: dict[str, Any],
    odoo_intent: dict[str, Any],
    body: bytes,
) -> dict[str, Any]:
    staging = getattr(settings, "environment", "") == "staging"
    write_enabled = settings.odoo_write_enabled or (
        staging and getattr(settings, "odoo_staging_writes_enabled", False)
    )
    original_event_id = f"{provider}:{external_id}"
    key_hash = hashlib.sha256(external_id.encode()).hexdigest()
    request_hash = hashlib.sha256(body).hexdigest()
    scope = f"provider-webhook:{provider}"
    correlation_id = original_event_id
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
        {"value": f"{scope}:{key_hash}"},
    )
    existing = await db.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.scope == scope,
            IdempotencyRecord.key_hash == key_hash,
        )
    )
    if existing:
        if existing.request_hash != request_hash:
            await db.rollback()
            raise HTTPException(409, "idempotency key conflict")
        await db.commit()
        return dict(existing.response)

    incoming = IntegrationEvent(
        idempotency_key=key_hash,
        event_type=event_type,
        schema_version="1.0",
        original_event_id=original_event_id,
        entity_key=entity_key,
        source_system=provider,
        correlation_id=correlation_id,
        payload_json=normalized,
        payload_hash=request_hash,
        state="accepted",
    )
    db.add(incoming)
    await db.flush()
    db.add(
        IntegrationDelivery(
            event_id=incoming.id,
            target="odoo",
            status="pending" if write_enabled else "disabled",
            max_attempts=settings.outbox_max_attempts,
            result_json=odoo_intent,
        )
    )
    if write_enabled:
        db.add(
            OdooResultDelivery(
                integration_event_id=incoming.id,
                originating_outbox_public_id=original_event_id,
                request_hash=request_hash,
                status="PENDING",
                standard_result_json=odoo_intent,
            )
        )
    db.add(
        OutboxEvent(
            topic=event_type,
            payload={
                "event_id": original_event_id,
                "event_type": event_type,
                "source": provider,
                "data": normalized,
            },
            correlation_id=correlation_id,
            status="pending",
        )
    )
    result = {
        "accepted": True,
        "event_id": original_event_id,
        "duplicate": False,
        "odoo_write": "pending" if write_enabled else "disabled",
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
            action=f"{provider}.webhook.accepted",
            subject=original_event_id,
            correlation_id=correlation_id,
            decision="accepted",
            redacted_payload={"event_type": event_type},
        )
    )
    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(503, "durable persistence unavailable") from exc
    return result


@router.post("/vicidial/call-result/")
async def vicidial_call_result(
    request: Request,
    response: Response,
    signature: str | None = Header(default=None, alias="X-VICIdial-Signature"),
    timestamp: str | None = Header(default=None, alias="X-VICIdial-Timestamp"),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    body = await _read_limited_json_body(request)
    _verify_signed_request(body, timestamp, signature, settings.vicidial_webhook_secret)
    value = _parse(VicidialCallResult, body)
    assert isinstance(value, VicidialCallResult)
    disposition = DISPOSITION_MAP.get(value.disposition.upper())
    if disposition is None:
        raise HTTPException(400, "VICIdial disposition is unsupported")
    payload = value.model_dump(mode="json")
    payload["disposition"] = disposition
    result = await _persist(
        db=db,
        response=response,
        provider="vicidial",
        external_id=value.call_id,
        event_type="call_disposition_updated",
        entity_key=f"call_id:{value.call_id}",
        normalized=payload,
        odoo_intent=OdooWebhookAdapter.log_call_result(payload, disposition),
        body=body,
    )
    response.status_code = 202
    return result


@router.post("/sms/inbound/")
async def telnexa_inbound_sms(
    request: Request,
    response: Response,
    signature: str | None = Header(default=None, alias="X-Telnexa-Signature"),
    timestamp: str | None = Header(default=None, alias="X-Telnexa-Timestamp"),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    body = await _read_limited_json_body(request)
    _verify_signed_request(body, timestamp, signature, settings.telnexa_webhook_secret)
    value = _parse(TelnexaInboundSms, body)
    assert isinstance(value, TelnexaInboundSms)
    payload = value.model_dump(mode="json", by_alias=True)
    result = await _persist(
        db=db,
        response=response,
        provider="telnexa",
        external_id=value.message_id,
        event_type="sms_received",
        entity_key=f"phone:{value.sender}",
        normalized=payload,
        odoo_intent=OdooWebhookAdapter.log_inbound_sms(payload),
        body=body,
    )
    response.status_code = 202
    return result
