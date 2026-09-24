"""Strict, redacted provider read-back evidence for staging canaries."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CanaryChannel = Literal["email", "sms", "voice", "social"]
EvidenceSource = Literal["provider_api", "provider_webhook", "provider_cdr"]
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9._:/-]{1,512}$")
_LOCAL_PROVIDER_NAMES = frozenset({"fake", "internal", "local", "mock", "simulator"})

TARGET_CHANNELS: dict[str, CanaryChannel] = {
    "klyrow-email": "email",
    "telnexa-sms": "sms",
    "vicidial-restricted": "voice",
    "postly-social": "social",
}

SUCCESS_STATUSES: dict[CanaryChannel, frozenset[str]] = {
    "email": frozenset({"delivered"}),
    "sms": frozenset({"delivered"}),
    "voice": frozenset({"completed"}),
    "social": frozenset({"published"}),
}


def canonical_fingerprint(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ProviderReadbackEvidence(BaseModel):
    """Provider-side proof safe enough to persist in Middleware."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    channel: CanaryChannel
    provider: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    provider_reference: str = Field(min_length=1, max_length=512)
    terminal_status: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    observed_at: datetime
    source: EvidenceSource
    destination_fingerprint: str
    payload_fingerprint: str
    facts: dict[str, Any]

    @field_validator("provider_reference")
    @classmethod
    def safe_provider_reference(cls, value: str) -> str:
        if _SAFE_REFERENCE.fullmatch(value) is None:
            raise ValueError("provider_reference contains unsafe characters")
        return value

    @field_validator("destination_fingerprint", "payload_fingerprint")
    @classmethod
    def exact_fingerprint(cls, value: str) -> str:
        if _FINGERPRINT.fullmatch(value) is None:
            raise ValueError("evidence fingerprints must be canonical sha256 values")
        return value

    @field_validator("observed_at")
    @classmethod
    def aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value

    @model_validator(mode="after")
    def require_channel_facts(self) -> ProviderReadbackEvidence:
        expected = {
            "email": {
                "delivery_event_id",
                "delivery_status",
                "provider_message_id",
                "recipient_fingerprint",
                "occurred_at",
            },
            "sms": {
                "delivery_receipt_id",
                "delivery_status",
                "provider_message_id",
                "destination_fingerprint",
                "occurred_at",
            },
            "voice": {
                "cdr_id",
                "disposition",
                "duration_seconds",
                "hangup_cause",
                "destination_fingerprint",
                "occurred_at",
            },
            "social": {
                "post_id",
                "account_reference_fingerprint",
                "content_fingerprint",
                "publication_state",
                "occurred_at",
            },
        }[self.channel]
        if set(self.facts) != expected:
            raise ValueError(
                f"{self.channel} evidence facts must be exactly: "
                + ", ".join(sorted(expected))
            )

        for key, value in self.facts.items():
            if key.endswith("_fingerprint"):
                if not isinstance(value, str) or _FINGERPRINT.fullmatch(value) is None:
                    raise ValueError(f"{key} must be a canonical sha256 fingerprint")
            elif key == "duration_seconds":
                if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                    raise ValueError(
                        "voice duration_seconds must be a positive integer"
                    )
            elif not isinstance(value, str) or not value or len(value) > 512:
                raise ValueError(f"{key} must be a non-empty bounded string")

        raw_occurred_at = self.facts["occurred_at"]
        try:
            occurred_at = datetime.fromisoformat(raw_occurred_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("occurred_at must be an ISO 8601 timestamp") from exc
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        if occurred_at > self.observed_at:
            raise ValueError("occurred_at cannot be later than observed_at")

        if self.channel == "email":
            if self.provider != "postal":
                raise ValueError("email evidence must identify Postal as the provider")
            if self.source not in {"provider_api", "provider_webhook"}:
                raise ValueError(
                    "email evidence must come from Postal read-back or webhook"
                )
            if self.facts["delivery_status"] != self.terminal_status:
                raise ValueError("email delivery status does not match terminal status")
            if self.facts["provider_message_id"] != self.provider_reference:
                raise ValueError("email provider message identity does not match")
            if self.facts["recipient_fingerprint"] != self.destination_fingerprint:
                raise ValueError(
                    "email recipient fingerprint does not match command intent"
                )
        elif self.channel == "sms":
            if self.provider != "jasmin":
                raise ValueError("SMS evidence must identify Jasmin as the provider")
            if self.source not in {"provider_api", "provider_webhook"}:
                raise ValueError("SMS evidence must come from provider DLR read-back")
            if self.facts["delivery_status"] != self.terminal_status:
                raise ValueError("SMS delivery status does not match terminal status")
            if self.facts["provider_message_id"] != self.provider_reference:
                raise ValueError("SMS provider message identity does not match")
            if self.facts["destination_fingerprint"] != self.destination_fingerprint:
                raise ValueError(
                    "SMS destination fingerprint does not match command intent"
                )
        elif self.channel == "voice":
            if self.provider != "vicidial":
                raise ValueError("voice evidence must identify VICIdial as the provider")
            if self.source != "provider_cdr":
                raise ValueError("voice evidence must come from a VICIdial CDR")
            if self.facts["cdr_id"] != self.provider_reference:
                raise ValueError("voice CDR identity does not match provider identity")
            if self.facts["disposition"].upper() not in {
                "ANSWER",
                "ANSWERED",
                "COMPLETED",
            }:
                raise ValueError("voice CDR does not prove an answered call")
            if self.facts["destination_fingerprint"] != self.destination_fingerprint:
                raise ValueError(
                    "voice destination fingerprint does not match command intent"
                )
        else:
            if self.provider in _LOCAL_PROVIDER_NAMES:
                raise ValueError("social evidence must identify an external provider")
            if self.source != "provider_api":
                raise ValueError(
                    "social evidence must come from a provider post read-back API"
                )
            if self.facts["publication_state"] != self.terminal_status:
                raise ValueError("social publication state does not match terminal status")
            if self.facts["post_id"] != self.provider_reference:
                raise ValueError("social post identity does not match provider identity")
            if (
                self.facts["account_reference_fingerprint"]
                != self.destination_fingerprint
            ):
                raise ValueError(
                    "social account fingerprint does not match command intent"
                )
            if self.facts["content_fingerprint"] != self.payload_fingerprint:
                raise ValueError(
                    "social content fingerprint does not match command intent"
                )

        return self


def validate_provider_canary_evidence(
    value: object,
    *,
    target: str,
    destination_fingerprint: str,
    payload_fingerprint: str,
    require_success: bool = True,
) -> ProviderReadbackEvidence:
    try:
        channel = TARGET_CHANNELS[target]
    except KeyError as exc:
        raise ValueError(f"{target} is not a provider-canary target") from exc
    evidence = ProviderReadbackEvidence.model_validate(value)
    if evidence.channel != channel:
        raise ValueError("read-back channel does not match connector target")
    if evidence.destination_fingerprint != destination_fingerprint:
        raise ValueError(
            "read-back destination fingerprint does not match command intent"
        )
    if evidence.payload_fingerprint != payload_fingerprint:
        raise ValueError("read-back payload fingerprint does not match command intent")
    if require_success and evidence.terminal_status not in SUCCESS_STATUSES[channel]:
        raise ValueError(
            f"{channel} canary did not reach a successful provider terminal status"
        )
    return evidence


def provider_evidence_digest(value: object) -> str:
    return canonical_fingerprint(value)
