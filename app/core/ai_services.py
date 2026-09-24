"""Fail-closed, provider-independent AI staging contracts and deterministic policy."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

BUSINESS_UNITS = {"TL", "DEV", "SCP"}
TASK_TYPES = {
    "lead_prequalification",
    "lead_fit_scoring",
    "urgency_classification",
    "campaign_recommendation",
    "language_detection",
    "call_transcription",
    "call_summary",
    "sentiment_analysis",
    "objection_detection",
    "disclosure_detection",
    "forbidden_phrase_detection",
    "compliance_review",
    "qa_review",
    "next_best_action",
    "retention_risk",
    "upsell_recommendation",
    "failed_payment_recommendation",
    "supervisor_escalation",
}
SENSITIVE_KEYS = {
    "card_number",
    "cvv",
    "password",
    "secret",
    "sip_password",
    "private_key",
    "authorization",
    "medical_diagnosis",
}


class AIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = Field(1, ge=1, le=1)
    task_id: str = Field(min_length=8, max_length=128)
    task_type: str
    business_unit: str
    campaign_id: str = Field(min_length=1, max_length=64)
    entity_type: str = Field(min_length=1, max_length=32)
    entity_id: str = Field(min_length=1, max_length=128)
    language: str = Field(pattern=r"^[a-z]{2}(?:-[A-Z]{2})?$")
    priority: int = Field(ge=0, le=3)
    minimized_input: dict[str, Any]
    output_schema: str
    correlation_id: str
    idempotency_key: str
    request_timestamp: str
    consent: bool

    @field_validator("task_type")
    @classmethod
    def valid_task(cls, value: str) -> str:
        if value not in TASK_TYPES:
            raise ValueError("unsupported task type")
        return value

    @field_validator("business_unit")
    @classmethod
    def valid_unit(cls, value: str) -> str:
        if value not in BUSINESS_UNITS:
            raise ValueError("unsupported business unit")
        return value

    @field_validator("minimized_input")
    @classmethod
    def no_sensitive_fields(cls, value: dict[str, Any]) -> dict[str, Any]:
        bad = SENSITIVE_KEYS.intersection(k.lower() for k in value)
        if bad:
            raise ValueError("sensitive input is prohibited")
        return value


class AIResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1
    task_id: str
    task_type: str
    status: str
    provider: str
    model: str
    output_schema: str
    result: dict[str, Any]
    confidence: float = Field(ge=0, le=1)
    human_review_required: bool
    warnings: list[str] = []
    correlation_id: str


class ProviderAdapter(Protocol):
    def submit_task(self, request: AIRequest) -> AIResult: ...
    def validate_health(self) -> bool: ...
    def normalize_result(self, result: dict[str, Any]) -> AIResult: ...
    def classify_error(self, error: Exception) -> str: ...


@dataclass(frozen=True)
class Qualification:
    score: int
    fit_category: str
    urgency: str
    category: str
    confidence: float
    human_review_required: bool
    explanation: tuple[str, ...]


def request_hash(request: AIRequest) -> str:
    return hashlib.sha256(request.model_dump_json().encode()).hexdigest()


def redact_text(text: str) -> str:
    text = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_PAYMENT]", text)
    text = re.sub(
        r"(?i)(password|secret|api[_ -]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", text
    )
    return text


def qualify(unit: str, factors: dict[str, Any]) -> Qualification:
    if unit not in BUSINESS_UNITS:
        raise ValueError("unsupported business unit")
    if not factors.get("consent", False) or factors.get("dnc", False):
        return Qualification(
            0,
            "blocked_or_ineligible",
            "deferred",
            "suppressed",
            1.0,
            True,
            ("deterministic compliance override",),
        )
    if unit == "SCP" and factors.get("medical_claim", False):
        return Qualification(
            0,
            "blocked_or_ineligible",
            "critical",
            "compliance_review",
            1.0,
            True,
            ("medical claims require human review",),
        )
    score = max(0, min(100, int(factors.get("base_score", 50))))
    if score >= 90:
        fit = "exceptional_fit"
    elif score >= 75:
        fit = "strong_fit"
    elif score >= 60:
        fit = "moderate_fit"
    elif score >= 40:
        fit = "weak_fit"
    elif score > 0:
        fit = "very_low_fit"
    else:
        fit = "blocked_or_ineligible"
    confidence = float(factors.get("confidence", 0.8))
    review = confidence < 0.7
    category = (
        "needs_human_review" if review else ("qualified" if score >= 60 else "nurture")
    )
    urgency = str(factors.get("urgency", "medium"))
    if urgency not in {"critical", "high", "medium", "low", "deferred"}:
        raise ValueError("invalid urgency")
    return Qualification(
        score,
        fit,
        urgency,
        category,
        confidence,
        review,
        ("deterministic score", f"business_unit={unit}"),
    )


def knowledge_allowed(
    item: dict[str, Any], unit: str, campaign: str, language: str
) -> bool:
    return (
        item.get("business_unit") == unit
        and item.get("campaign_id") == campaign
        and item.get("language") == language
        and item.get("status") == "published"
        and not item.get("archived", False)
    )


class FeatureFlags:
    """AI features default false and cannot bypass the global provider kill switch."""

    def __init__(self, values: dict[str, bool] | None = None):
        self.values = values or {}

    def enabled(self, feature: str) -> bool:
        return bool(
            self.values.get("ENABLE_AI_PROVIDERS", False)
            and self.values.get(feature, False)
        )
