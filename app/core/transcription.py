"""Synthetic-only transcription control-plane contracts and redaction."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from threading import Lock
from typing import Any
from uuid import uuid4

UNITS = {"TL", "DEV", "SCP"}
SEGMENT_STATES = {
    "partial",
    "stabilizing",
    "final",
    "corrected",
    "redacted",
    "rejected",
}
RESOLUTIONS = {
    "resolved_by_ivr",
    "resolved_by_ai_voice",
    "resolved_by_human",
    "resolved_by_ai_and_human",
    "transferred_to_closer",
    "transferred_to_support",
    "appointment_scheduled",
    "ticket_created",
    "order_completed",
    "payment_completed",
    "follow_up_required",
    "escalated",
    "customer_disconnected",
    "unresolved",
    "incorrectly_routed",
}
FEATURE_FLAGS = {
    "ENABLE_LIVE_TRANSCRIPTION",
    "ENABLE_FINAL_TRANSCRIPTION",
    "ENABLE_WHISPERX_ALIGNMENT",
    "ENABLE_SPEAKER_DIARIZATION",
    "ENABLE_TRANSCRIPT_REDACTION",
    "ENABLE_LIVE_KEYWORD_DETECTION",
    "ENABLE_LIVE_AGENT_ASSIST",
    "ENABLE_AI_CALL_SUMMARY",
    "ENABLE_INTENT_CLASSIFICATION",
    "ENABLE_RESOLUTION_CLASSIFICATION",
    "ENABLE_QA_ANALYSIS",
    "ENABLE_COMPLIANCE_ANALYSIS",
    "ENABLE_TRANSCRIPT_SEARCH",
}


class TranscriptionDenied(PermissionError):
    pass


class IdempotencyConflict(ValueError):
    pass


@dataclass(frozen=True)
class AudioSession:
    session_id: str
    call_reference: str
    business_unit: str
    campaign: str
    media_checksum: str
    consent: bool
    classification: str
    retention_policy: str
    correlation_id: str
    state: str = "created"
    test_only: bool = True


@dataclass(frozen=True)
class TranscriptSegment:
    call_reference: str
    channel: str
    speaker: str
    sequence: int
    start_ms: int
    end_ms: int
    language: str
    confidence: float
    state: str
    text: str


def create_audio_session(
    *,
    call_reference: str,
    business_unit: str,
    campaign: str,
    media_checksum: str,
    consent: bool,
    classification: str,
    retention_policy: str,
    correlation_id: str,
) -> AudioSession:
    if business_unit not in UNITS or not campaign.startswith(f"{business_unit}-"):
        raise TranscriptionDenied("invalid business-unit campaign scope")
    if not consent:
        raise TranscriptionDenied("recording consent required")
    if not re.fullmatch(r"[a-f0-9]{64}", media_checksum):
        raise ValueError("SHA-256 media checksum required")
    return AudioSession(
        str(uuid4()),
        call_reference,
        business_unit,
        campaign,
        media_checksum,
        consent,
        classification,
        retention_policy,
        correlation_id,
    )


def finalize_audio_session(
    session: AudioSession, observed_checksum: str
) -> AudioSession:
    if observed_checksum != session.media_checksum:
        raise ValueError("media integrity check failed")
    return replace(session, state="finalized")


def validate_segment(segment: TranscriptSegment) -> None:
    if segment.state not in SEGMENT_STATES or segment.sequence < 0:
        raise ValueError("invalid segment state or sequence")
    if segment.start_ms < 0 or segment.end_ms <= segment.start_ms:
        raise ValueError("invalid segment timestamps")
    if not 0 <= segment.confidence <= 1:
        raise ValueError("invalid confidence")
    if segment.channel not in {
        "agent",
        "customer",
        "mixed",
        "supervisor",
        "interpreter",
    }:
        raise ValueError("unknown channel")


REDACTION_PATTERNS = (
    ("payment_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("cvv", re.compile(r"(?i)\b(?:cvv|security code)\s*[:=]?\s*\d{3,4}\b")),
    (
        "credential",
        re.compile(r"(?i)\b(?:password|api[_ -]?key|sip secret)\s*[:=]\s*\S+"),
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
    ),
    ("government_id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
)


def redact(text: str) -> tuple[str, tuple[dict[str, Any], ...]]:
    output = text
    events: list[dict[str, Any]] = []
    for category, pattern in REDACTION_PATTERNS:

        def replacement(match: re.Match[str], category: str = category) -> str:
            events.append(
                {
                    "category": category,
                    "fingerprint": hashlib.sha256(match.group(0).encode()).hexdigest()[
                        :16
                    ],
                }
            )
            return f"[REDACTED:{category}]"

        output = pattern.sub(replacement, output)
    return output, tuple(events)


def channel_identity(channel: str, participant_map: dict[str, str]) -> tuple[str, bool]:
    if channel in participant_map:
        return participant_map[channel], False
    return "unknown", True


def structured_analysis(
    *,
    primary_intent: str,
    secondary_intents: list[str],
    resolution: str,
    sentiment: str,
    objections: list[str],
    action_items: list[str],
    dnc: bool,
    confusion: bool,
) -> dict[str, Any]:
    if resolution not in RESOLUTIONS:
        raise ValueError("unsupported resolution")
    if sentiment not in {"positive", "neutral", "negative", "mixed", "unknown"}:
        raise ValueError("unsupported sentiment")
    return {
        "primary_intent": primary_intent[:64],
        "secondary_intents": secondary_intents[:10],
        "resolution": resolution,
        "sentiment": sentiment,
        "objections": objections[:20],
        "action_items": action_items[:20],
        "dnc": dnc,
        "customer_confusion": confusion,
        "advisory_only": True,
        "allowed_commands": [],
    }


class FeaturePolicy:
    def __init__(self, overrides: dict[tuple[str, str, str, str], bool] | None = None):
        self._overrides = overrides or {}

    def enabled(self, flag: str, environment: str, unit: str, campaign: str) -> bool:
        if flag not in FEATURE_FLAGS:
            raise ValueError("unknown transcription feature flag")
        return self._overrides.get((environment, unit, campaign, flag), False)


class IdempotencyLedger:
    def __init__(self):
        self._values: dict[str, tuple[str, Any]] = {}
        self._lock = Lock()

    def claim(self, key: str, payload: bytes, result: Any) -> Any:
        digest = hashlib.sha256(payload).hexdigest()
        with self._lock:
            prior = self._values.get(key)
            if prior:
                if prior[0] != digest:
                    raise IdempotencyConflict("idempotency conflict")
                return prior[1]
            self._values[key] = (digest, result)
            return result
