"""Default-deny production WebRTC/PSTN authorization policy.

This module performs authorization only.  It never registers SIP endpoints,
opens signaling sessions, or dispatches calls.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


logger = logging.getLogger("codestra.telephony_policy")
E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DENY_NO_CONSENT = "DENY_NO_CONSENT"
    DENY_OUTSIDE_CALLING_HOURS = "DENY_OUTSIDE_CALLING_HOURS"
    DENY_EMERGENCY = "DENY_EMERGENCY"
    DENY_PREMIUM = "DENY_PREMIUM"
    DENY_PROHIBITED = "DENY_PROHIBITED"
    DENY_UNSUPPORTED_COUNTRY = "DENY_UNSUPPORTED_COUNTRY"
    DENY_UNAUTHORIZED_AGENT = "DENY_UNAUTHORIZED_AGENT"
    DENY_UNAUTHORIZED_CAMPAIGN = "DENY_UNAUTHORIZED_CAMPAIGN"
    DENY_UNAUTHORIZED_CALLER_ID = "DENY_UNAUTHORIZED_CALLER_ID"
    DENY_OUTSIDE_PILOT_WINDOW = "DENY_OUTSIDE_PILOT_WINDOW"
    DENY_CAPACITY = "DENY_CAPACITY"


@dataclass(frozen=True)
class Consent:
    status: str
    scope: str
    timestamp: datetime | None
    expiration: datetime | None
    source: str
    reference: str


@dataclass(frozen=True)
class CallRequest:
    correlation_id: str
    agent_subject: str
    tenant: str
    business_unit: str
    campaign: str
    extension: str
    caller_id: str
    destination: str
    destination_class: str
    destination_country: str
    destination_timezone: str
    recording_requested: bool
    consent: Consent | None
    requested_at: datetime


@dataclass(frozen=True)
class RecordingPolicy:
    mode: str = "disabled"
    notice_required: bool = False
    consent_required: bool = False
    retention_class: str | None = None


@dataclass(frozen=True)
class Policy:
    version: str
    enabled: bool = False
    kill_switch: bool = True
    allowed_campaign: str | None = None
    allowed_business_unit: str | None = None
    allowed_agent: str | None = None
    allowed_extension: str | None = None
    allowed_caller_id: str | None = None
    allowed_destination: str | None = None
    allowed_destination_classes: frozenset[str] = field(default_factory=frozenset)
    allowed_countries: frozenset[str] = field(default_factory=frozenset)
    prohibited_destinations: frozenset[str] = field(default_factory=frozenset)
    timezone: str | None = None
    calling_start: time | None = None
    calling_end: time | None = None
    allowed_weekdays: frozenset[int] = field(default_factory=frozenset)
    pilot_start: datetime | None = None
    pilot_end: datetime | None = None
    max_concurrent_calls: int = 1
    max_call_attempts: int = 1
    recording: RecordingPolicy = field(default_factory=RecordingPolicy)
    emergency_blocking: bool = True
    premium_blocking: bool = True
    consent_required: bool = True

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        raw = json.loads(path.read_text(encoding="utf-8"))
        window = raw.get("calling_window") or {}
        pilot = raw.get("pilot_window") or {}
        recording = raw.get("recording") or {}
        return cls(
            version=str(raw["version"]),
            enabled=raw.get("enabled") is True,
            kill_switch=raw.get("kill_switch") is not False,
            allowed_campaign=raw.get("allowed_campaign"),
            allowed_business_unit=raw.get("allowed_business_unit"),
            allowed_agent=raw.get("allowed_agent"),
            allowed_extension=raw.get("allowed_extension"),
            allowed_caller_id=raw.get("allowed_caller_id"),
            allowed_destination=raw.get("allowed_destination"),
            allowed_destination_classes=frozenset(
                raw.get("allowed_destination_classes") or []
            ),
            allowed_countries=frozenset(raw.get("allowed_countries") or []),
            prohibited_destinations=frozenset(raw.get("prohibited_destinations") or []),
            timezone=window.get("timezone"),
            calling_start=time.fromisoformat(window["start"])
            if window.get("start")
            else None,
            calling_end=time.fromisoformat(window["end"])
            if window.get("end")
            else None,
            allowed_weekdays=frozenset(window.get("weekdays") or []),
            pilot_start=datetime.fromisoformat(pilot["start"])
            if pilot.get("start")
            else None,
            pilot_end=datetime.fromisoformat(pilot["end"])
            if pilot.get("end")
            else None,
            max_concurrent_calls=int(raw.get("max_concurrent_calls", 1)),
            max_call_attempts=int(raw.get("max_call_attempts", 1)),
            recording=RecordingPolicy(**recording),
            emergency_blocking=raw.get("emergency_blocking") is True,
            premium_blocking=raw.get("premium_blocking") is True,
            consent_required=raw.get("consent_required") is True,
        )

    def validate_for_activation(self) -> list[str]:
        errors: list[str] = []
        required = {
            "allowed_campaign": self.allowed_campaign,
            "allowed_business_unit": self.allowed_business_unit,
            "allowed_agent": self.allowed_agent,
            "allowed_extension": self.allowed_extension,
            "allowed_caller_id": self.allowed_caller_id,
            "allowed_destination": self.allowed_destination,
            "timezone": self.timezone,
            "calling_start": self.calling_start,
            "calling_end": self.calling_end,
            "pilot_start": self.pilot_start,
            "pilot_end": self.pilot_end,
        }
        errors.extend(
            f"missing_{name}" for name, value in required.items() if value is None
        )
        if not self.emergency_blocking:
            errors.append("emergency_blocking_required")
        if not self.premium_blocking:
            errors.append("premium_blocking_required")
        if not self.consent_required:
            errors.append("consent_engine_required")
        if not self.allowed_countries:
            errors.append("country_allowlist_required")
        if not self.allowed_destination_classes:
            errors.append("destination_class_allowlist_required")
        if self.max_concurrent_calls != 1:
            errors.append("max_concurrent_calls_must_equal_1")
        if self.max_call_attempts != 1:
            errors.append("max_call_attempts_must_equal_1")
        if self.recording.mode not in {"disabled", "allowed", "required"}:
            errors.append("invalid_recording_mode")
        return errors


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def _is_emergency(destination: str, country: str) -> bool:
    digits = _digits(destination)
    national = (
        digits[1:]
        if country in {"US", "CA", "DO"} and digits.startswith("1")
        else digits
    )
    return national in {"911", "112", "999", "000", "110", "118", "119"}


def _is_premium(destination: str, country: str) -> bool:
    digits = _digits(destination)
    national = (
        digits[1:]
        if country in {"US", "CA", "DO"} and digits.startswith("1")
        else digits
    )
    return (country in {"US", "CA", "DO"} and national.startswith("900")) or (
        country == "GB" and national.startswith("9")
    )


class Capacity:
    def __init__(self) -> None:
        self.active = 0
        self.attempts = 0
        self._lock = Lock()

    def reserve(self, policy: Policy) -> bool:
        with self._lock:
            if (
                self.active >= policy.max_concurrent_calls
                or self.attempts >= policy.max_call_attempts
            ):
                return False
            self.active += 1
            self.attempts += 1
            return True

    def release(self) -> None:
        with self._lock:
            self.active = max(0, self.active - 1)


def authorize(
    policy: Policy, request: CallRequest, capacity: Capacity | None = None
) -> Decision:
    now = request.requested_at.astimezone(timezone.utc)
    result = Decision.DENY
    if not policy.enabled or policy.kill_switch or policy.validate_for_activation():
        result = Decision.DENY
    elif (
        request.campaign != policy.allowed_campaign
        or request.business_unit != policy.allowed_business_unit
    ):
        result = Decision.DENY_UNAUTHORIZED_CAMPAIGN
    elif (
        request.agent_subject != policy.allowed_agent
        or request.extension != policy.allowed_extension
        or request.tenant == ""
    ):
        result = Decision.DENY_UNAUTHORIZED_AGENT
    elif request.caller_id != policy.allowed_caller_id:
        result = Decision.DENY_UNAUTHORIZED_CALLER_ID
    elif _is_emergency(request.destination, request.destination_country):
        result = Decision.DENY_EMERGENCY
    elif _is_premium(request.destination, request.destination_country):
        result = Decision.DENY_PREMIUM
    elif (
        not E164.fullmatch(request.destination)
        or request.destination != policy.allowed_destination
        or request.destination in policy.prohibited_destinations
        or request.destination_class not in policy.allowed_destination_classes
    ):
        result = Decision.DENY_PROHIBITED
    elif request.destination_country not in policy.allowed_countries:
        result = Decision.DENY_UNSUPPORTED_COUNTRY
    elif now < cast(datetime, policy.pilot_start).astimezone(
        timezone.utc
    ) or now >= cast(datetime, policy.pilot_end).astimezone(timezone.utc):
        result = Decision.DENY_OUTSIDE_PILOT_WINDOW
    elif policy.consent_required and (
        request.consent is None
        or request.consent.status != "granted"
        or not request.consent.reference
        or request.consent.scope != "production-webrtc-pilot"
        or request.consent.timestamp is None
        or (request.consent.expiration and request.consent.expiration <= now)
    ):
        result = Decision.DENY_NO_CONSENT
    elif policy.recording.mode == "disabled" and request.recording_requested:
        result = Decision.DENY
    elif policy.recording.mode == "required" and not request.recording_requested:
        result = Decision.DENY
    else:
        try:
            local = now.astimezone(ZoneInfo(request.destination_timezone))
        except ZoneInfoNotFoundError:
            result = Decision.DENY_OUTSIDE_CALLING_HOURS
        else:
            if (
                request.destination_timezone != policy.timezone
                or local.weekday() not in policy.allowed_weekdays
                or not (
                    cast(time, policy.calling_start)
                    <= local.time().replace(tzinfo=None)
                    < cast(time, policy.calling_end)
                )
            ):
                result = Decision.DENY_OUTSIDE_CALLING_HOURS
            elif capacity is not None and not capacity.reserve(policy):
                result = Decision.DENY_CAPACITY
            else:
                result = Decision.ALLOW
    audit = {
        "event": "telephony.policy.decision",
        "correlation_id": request.correlation_id,
        "agent_subject": request.agent_subject,
        "tenant": request.tenant,
        "business_unit": request.business_unit,
        "campaign": request.campaign,
        "extension": request.extension,
        "caller_id_reference": hashlib.sha256(request.caller_id.encode()).hexdigest()[
            :16
        ],
        "destination_reference": hashlib.sha256(
            request.destination.encode()
        ).hexdigest()[:16],
        "policy_result": result.value,
        "policy_version": policy.version,
        "timestamp": now.isoformat(),
    }
    logger.info(
        "telephony_policy %s", json.dumps(audit, sort_keys=True, separators=(",", ":"))
    )
    return result
