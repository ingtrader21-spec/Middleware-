from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import EventEnvelope, IngressResult
from app.core.runtime import RuntimeContainer as Runtime
from .storage import canonical_payload_sha256


SURVEY_RESPONSE_SUBMITTED = "codestra.events.survey_response_submitted"
INTAKE_PRODUCER_CLIENT_ID = "sdk-intake"


class SurveyResponseSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenantId: str = Field(min_length=1, max_length=128)
    siteId: str = Field(min_length=1, max_length=180)
    submittedAt: datetime
    source: Literal["form", "landing_page", "chat", "voice", "api", "other"] = "form"
    surveyId: str = Field(min_length=1, max_length=180)
    surveyVersion: str = Field(min_length=1, max_length=64)
    surveyCategory: str = Field(min_length=1, max_length=100)
    campaignId: str | None = Field(default=None, max_length=180)
    anonymous: bool = False
    contactId: str | None = Field(default=None, max_length=180)
    leadId: str | None = Field(default=None, max_length=180)
    locale: str | None = Field(default=None, max_length=32)
    answers: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("submittedAt")
    @classmethod
    def require_submitted_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("submittedAt must include an explicit timezone")
        return value

    @field_validator("contactId", "leadId")
    @classmethod
    def normalize_optional_identity(cls, value: str | None) -> str | None:
        return value.strip() if isinstance(value, str) and value.strip() else None

    def model_post_init(self, __context: Any) -> None:
        if self.anonymous and (self.contactId is not None or self.leadId is not None):
            raise ValueError("anonymous survey responses may not include contactId or leadId")


def build_survey_response_event(
    submission: SurveyResponseSubmission,
    *,
    idempotency_key: str,
    correlation_id: str,
) -> EventEnvelope:
    event_id = _stable_event_id(submission.tenantId, idempotency_key)
    submitted_at = submission.submittedAt
    return EventEnvelope(
        event_id=event_id,
        event_type=SURVEY_RESPONSE_SUBMITTED,
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
        metadata={
            "site_id": submission.siteId,
            "source": submission.source,
            "survey_id": submission.surveyId,
            "survey_version": submission.surveyVersion,
            "survey_category": submission.surveyCategory,
            "anonymous": submission.anonymous,
        },
    )


async def accept_survey_response(
    runtime: Runtime,
    submission: SurveyResponseSubmission,
    *,
    idempotency_key: str,
    correlation_id: str,
) -> IngressResult:
    envelope = build_survey_response_event(
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
        f"survey-response-submitted\0{tenant_id}\0{idempotency_key}".encode("utf-8")
    ).hexdigest()[:32]
    return f"survey-response-submitted-{digest}"
