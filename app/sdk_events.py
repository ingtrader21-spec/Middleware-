from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import EventEnvelope, IngressResult
from app.core.runtime import RuntimeContainer as Runtime
from .storage import canonical_payload_sha256


SDK_EVENT_SOURCE = "middleware-api"
CALL_DISPOSITION_UPDATED = "codestra.events.call_disposition_updated"
SMS_RECEIVED = "codestra.events.sms_received"

CallDisposition = Literal[
    "answered",
    "no_answer",
    "busy",
    "voicemail",
    "dnc",
    "callback_requested",
    "sale_completed",
    "failed",
    "dropped",
    "not_interested",
    "unknown",
]


class CallDispositionUpdatedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: Literal["call_disposition_updated"] = "call_disposition_updated"
    correlation_id: str = Field(min_length=1, max_length=180)
    causation_id: str = Field(
        min_length=1,
        max_length=180,
        description="Provider call ID that caused this event",
    )
    odoo_contact_id: int | None = Field(
        default=None,
        ge=0,
        description="Odoo res.partner ID; null if contact could not be matched",
    )
    odoo_lead_id: int | None = Field(
        default=None,
        ge=0,
        description="Odoo crm.lead ID; null if no active lead exists for the contact",
    )
    disposition: CallDisposition
    phone_number: str = Field(
        pattern=r"^\+[1-9]\d{1,14}$",
        description="E.164 format phone number",
    )
    duration_seconds: int | None = Field(default=None, ge=0)
    campaign_id: str | None = Field(default=None, min_length=1, max_length=180)
    provider_call_id: str = Field(
        min_length=1,
        max_length=180,
        description="VICIdial call ID (uniqueid)",
    )
    dry_run: bool = Field(
        default=False,
        description="True when ODOO_WRITE=false; event published but Odoo not written",
    )


class SmsReceivedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: Literal["sms_received"] = "sms_received"
    correlation_id: str = Field(min_length=1, max_length=180)
    causation_id: str = Field(
        min_length=1,
        max_length=180,
        description="Telnexa message ID that caused this event",
    )
    odoo_contact_id: int | None = Field(
        default=None,
        ge=0,
        description="Odoo res.partner ID; null if phone not matched",
    )
    odoo_message_id: int | None = Field(
        default=None,
        ge=0,
        description="Odoo mail.message ID of chatter entry",
    )
    from_number: str = Field(
        pattern=r"^\+[1-9]\d{1,14}$",
        description="E.164 format sender phone number",
    )
    body_preview: str = Field(
        max_length=120,
        description="First 120 characters of the inbound SMS body",
    )
    provider_event_id: str = Field(
        min_length=1,
        max_length=180,
        description="Telnexa message ID",
    )
    dry_run: bool = Field(
        default=False,
        description="True when ODOO_WRITE=false; event published but Odoo not written",
    )


def build_call_disposition_updated_event(
    *,
    tenant_id: str,
    payload: CallDispositionUpdatedPayload,
    occurred_at: datetime,
    received_at: datetime | None = None,
    customer_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> EventEnvelope:
    return _build_sdk_event(
        event_type=CALL_DISPOSITION_UPDATED,
        event_id=_stable_event_id(
            "sdk-call-disposition",
            tenant_id,
            payload.provider_call_id,
        ),
        tenant_id=tenant_id,
        payload=payload,
        occurred_at=occurred_at,
        received_at=received_at,
        customer_id=customer_id,
        metadata=metadata,
    )


def build_sms_received_event(
    *,
    tenant_id: str,
    payload: SmsReceivedPayload,
    occurred_at: datetime,
    received_at: datetime | None = None,
    customer_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> EventEnvelope:
    return _build_sdk_event(
        event_type=SMS_RECEIVED,
        event_id=_stable_event_id(
            "sdk-sms-received",
            tenant_id,
            payload.provider_event_id,
        ),
        tenant_id=tenant_id,
        payload=payload,
        occurred_at=occurred_at,
        received_at=received_at,
        customer_id=customer_id,
        metadata=metadata,
    )


async def record_sdk_event(
    runtime: Runtime,
    envelope: EventEnvelope,
) -> IngressResult:
    payload = envelope.model_dump(mode="json")
    semantic_sha256 = canonical_payload_sha256(payload)
    return await runtime.inbox.accept(
        envelope,
        producer_client_id=SDK_EVENT_SOURCE,
        body_sha256=semantic_sha256,
        semantic_sha256=semantic_sha256,
    )


def _build_sdk_event(
    *,
    event_type: str,
    event_id: str,
    tenant_id: str,
    payload: BaseModel,
    occurred_at: datetime,
    received_at: datetime | None,
    customer_id: str | None,
    metadata: dict[str, object] | None,
) -> EventEnvelope:
    body = payload.model_dump(mode="json")
    return EventEnvelope(
        event_id=event_id,
        event_type=event_type,
        event_version="1.0",
        occurred_at=_require_aware_datetime(occurred_at, "occurred_at"),
        received_at=_require_aware_datetime(
            received_at or datetime.now(UTC),
            "received_at",
        ),
        source=SDK_EVENT_SOURCE,
        tenant_id=tenant_id,
        customer_id=customer_id,
        correlation_id=str(body["correlation_id"]),
        causation_id=str(body["causation_id"]),
        idempotency_key=event_id,
        payload=body,
        metadata=metadata or {},
    )


def _stable_event_id(prefix: str, tenant_id: str, provider_id: str) -> str:
    digest = hashlib.sha256(
        f"{prefix}\0{tenant_id}\0{provider_id}".encode("utf-8")
    ).hexdigest()[:32]
    return f"{prefix}-{digest}"


def _require_aware_datetime(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include an explicit timezone")
    return value
