from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import EventEnvelope, IngressResult
from app.core.runtime import RuntimeContainer as Runtime
from .storage import canonical_payload_sha256


LEAD_SUBMITTED = "codestra.events.lead_submitted"
INTAKE_PRODUCER_CLIENT_ID = "sdk-intake"


class ConsentState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    marketing: bool | None = None
    sms: bool | None = None
    email: bool | None = None
    privacyPolicyVersion: str | None = Field(default=None, max_length=100)


class Attribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str | None = Field(default=None, max_length=180)
    medium: str | None = Field(default=None, max_length=180)
    campaign: str | None = Field(default=None, max_length=180)
    term: str | None = Field(default=None, max_length=180)
    content: str | None = Field(default=None, max_length=180)
    referrer: str | None = Field(default=None, max_length=2048)
    landingPage: str | None = Field(default=None, max_length=2048)


class LeadSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenantId: str = Field(min_length=1, max_length=128)
    siteId: str = Field(min_length=1, max_length=180)
    submittedAt: datetime
    source: Literal["form", "landing_page", "chat", "voice", "api", "other"]
    formId: str | None = Field(default=None, max_length=180)
    campaignId: str | None = Field(default=None, max_length=180)
    name: str | None = Field(default=None, max_length=300)
    email: str | None = Field(default=None, max_length=320)
    phone: str | None = Field(default=None, max_length=64)
    message: str | None = Field(default=None, max_length=10000)
    conversationId: str | None = Field(default=None, max_length=180)
    transcript: str | None = Field(default=None, max_length=50000)
    consent: ConsentState | None = None
    attribution: Attribution | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("submittedAt")
    @classmethod
    def require_submitted_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("submittedAt must include an explicit timezone")
        return value


def build_lead_submitted_event(
    submission: LeadSubmission,
    *,
    idempotency_key: str,
    correlation_id: str,
) -> EventEnvelope:
    event_id = _stable_event_id(submission.tenantId, idempotency_key)
    submitted_at = submission.submittedAt
    return EventEnvelope(
        event_id=event_id,
        event_type=LEAD_SUBMITTED,
        event_version="1.0",
        occurred_at=submitted_at,
        received_at=submitted_at,
        source="middleware-api",
        tenant_id=submission.tenantId,
        customer_id=None,
        correlation_id=correlation_id,
        causation_id=idempotency_key,
        idempotency_key=idempotency_key,
        payload=submission.model_dump(mode="json", exclude_none=True),
        metadata={"site_id": submission.siteId, "source": submission.source},
    )


async def accept_lead_submission(
    runtime: Runtime,
    submission: LeadSubmission,
    *,
    idempotency_key: str,
    correlation_id: str,
) -> IngressResult:
    envelope = build_lead_submitted_event(
        submission,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
    )
    payload = envelope.model_dump(mode="json")
    semantic_sha256 = canonical_payload_sha256(payload)
    return await runtime.inbox.accept(
        envelope,
        producer_client_id=INTAKE_PRODUCER_CLIENT_ID,
        body_sha256=semantic_sha256,
        semantic_sha256=semantic_sha256,
    )


def _stable_event_id(tenant_id: str, idempotency_key: str) -> str:
    digest = hashlib.sha256(
        f"lead-submitted\0{tenant_id}\0{idempotency_key}".encode("utf-8")
    ).hexdigest()[:32]
    return f"lead-submitted-{digest}"
