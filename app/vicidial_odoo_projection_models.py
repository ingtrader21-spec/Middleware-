from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from .models import EventEnvelope
from .vicidial_odoo_projection_errors import ProjectionError

LIFECYCLE_EVENT_MAP = {
    "codestra.vicidial.call.lifecycle.created": "call.created",
    "codestra.vicidial.call.lifecycle.offered": "call.offered",
    "codestra.vicidial.call.lifecycle.queued": "call.queued",
    "codestra.vicidial.call.lifecycle.dialing": "call.dialing",
    "codestra.vicidial.call.lifecycle.ringing": "call.ringing",
    "codestra.vicidial.call.lifecycle.answered": "call.answered",
    "codestra.vicidial.call.lifecycle.connected": "call.connected",
    "codestra.vicidial.call.lifecycle.held": "call.held",
    "codestra.vicidial.call.lifecycle.resumed": "call.resumed",
    "codestra.vicidial.call.lifecycle.transfer.started": "call.transfer.started",
    "codestra.vicidial.call.lifecycle.transfer.completed": "call.transfer.completed",
    "codestra.vicidial.call.lifecycle.hangup": "call.hangup",
    "codestra.vicidial.call.lifecycle.completed": "call.completed",
    "codestra.vicidial.call.lifecycle.failed": "call.failed",
    "codestra.vicidial.call.lifecycle.busy": "call.busy",
    "codestra.vicidial.call.lifecycle.no_answer": "call.no_answer",
    "codestra.vicidial.call.lifecycle.rejected": "call.rejected",
    "codestra.vicidial.call.lifecycle.canceled": "call.canceled",
}
CALL_EVENT_PATH = "/codestra/middleware/v1/call-events"
CALL_EVENT_STATUS_PATH = "/codestra/middleware/v1/call-events/{event_id}/status"
AMBIGUOUS_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


class OdooCallEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^1\.0$")
    event_id: str = Field(min_length=8, max_length=128)
    event_type: str = Field(min_length=1, max_length=100)
    timestamp: datetime
    correlation_id: str = Field(min_length=1, max_length=180)
    tenant_id: str = Field(min_length=1, max_length=128)
    business_unit_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    call_id: str = Field(min_length=1, max_length=128)
    asterisk_uniqueid: str = Field(min_length=1, max_length=128)
    linkedid: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    extension: str = Field(min_length=1, max_length=128)
    sequence: int = Field(ge=1, le=1_000_000)
    keycloak_subject: str = Field(min_length=1, max_length=255)
    synthetic_test: bool
    direction: str = Field(pattern=r"^(?:inbound|outbound)$")
    caller_number: str | None = Field(default=None, max_length=64)
    destination_number: str | None = Field(default=None, max_length=64)
    talk_duration: int | None = Field(default=None, ge=0, le=86_400)
    duration: int | None = Field(default=None, ge=0, le=86_400)
    transfer_destination: str | None = Field(default=None, max_length=255)
    transfer_type: str | None = Field(default=None, pattern=r"^(?:blind|attended)$")
    hangup_cause: str | None = Field(default=None, max_length=255)
    hangup_cause_code: int | None = Field(default=None, ge=0, le=999)
    dial_status: str | None = Field(default=None, max_length=32, pattern=r"^[A-Z_]+$")
    hangup_leg: str | None = Field(default=None, pattern=r"^(?:agent_leg|peer_leg)$")

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("call-event timestamp must include a timezone")
        return value

    @field_validator("event_type")
    @classmethod
    def require_supported_type(cls, value: str) -> str:
        if value not in set(LIFECYCLE_EVENT_MAP.values()):
            raise ValueError("unsupported Odoo call-event type")
        return value

    @model_validator(mode="after")
    def enforce_synthetic_marker(self) -> "OdooCallEvent":
        if self.synthetic_test != (self.campaign_id == "TEST_SYN"):
            raise ValueError("TEST_SYN and synthetic_test must agree")
        return self


def project_envelope(envelope: EventEnvelope, *, synthetic_only: bool) -> OdooCallEvent:
    if envelope.source != "vicidial-adapter":
        raise ProjectionError("event source is not vicidial-adapter")
    mapped = LIFECYCLE_EVENT_MAP.get(envelope.event_type)
    if mapped is None:
        raise ProjectionError("event type is not an AMI lifecycle event")
    raw = dict(envelope.payload)
    campaign_id = str(raw.get("campaign_id") or "")
    raw.update(
        {
            "schema_version": "1.0",
            "event_id": envelope.event_id,
            "event_type": mapped,
            "timestamp": envelope.occurred_at,
            "correlation_id": envelope.correlation_id,
            "tenant_id": envelope.tenant_id,
            "synthetic_test": campaign_id == "TEST_SYN",
        }
    )
    try:
        event = OdooCallEvent.model_validate(raw)
    except ValidationError as exc:
        raise ProjectionError("VICIdial lifecycle payload does not match Odoo") from exc
    if synthetic_only and not event.synthetic_test:
        raise ProjectionError("this projection accepts TEST_SYN events only")
    return event


def canonical_event_body(event: OdooCallEvent) -> bytes:
    return json.dumps(
        event.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_call_event(
    secret: bytes,
    *,
    timestamp: str,
    event_id: str,
    method: str,
    path: str,
    tenant_id: str,
    correlation_id: str,
    body: bytes,
) -> str:
    canonical = b"\n".join(
        (
            timestamp.encode("ascii"),
            event_id.encode(),
            method.upper().encode("ascii"),
            path.encode(),
            tenant_id.encode(),
            correlation_id.encode(),
            event_id.encode(),
            body,
        )
    )
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()
