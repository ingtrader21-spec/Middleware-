"""Callback aggregate invariants, state machine, and reminder policy."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

TERMINAL = frozenset({"COMPLETED", "CANCELLED"})
TRANSITIONS = {
    "DRAFT": {"SCHEDULED", "CANCELLED", "BLOCKED_COMPLIANCE"},
    "SCHEDULED": {
        "REMINDER_PENDING",
        "READY",
        "DUE",
        "SNOOZED",
        "RESCHEDULED",
        "CANCELLED",
        "BLOCKED_COMPLIANCE",
    },
    "REMINDER_PENDING": {
        "READY",
        "DUE",
        "SNOOZED",
        "RESCHEDULED",
        "CANCELLED",
        "FAILED",
    },
    "READY": {"DUE", "SNOOZED", "RESCHEDULED", "CANCELLED"},
    "DUE": {"IN_PROGRESS", "SNOOZED", "RESCHEDULED", "MISSED", "CANCELLED"},
    "IN_PROGRESS": {"COMPLETED", "FAILED", "RESCHEDULED"},
    "SNOOZED": {"REMINDER_PENDING", "READY", "DUE", "RESCHEDULED", "CANCELLED"},
    "RESCHEDULED": {"REMINDER_PENDING", "READY", "DUE", "SNOOZED", "CANCELLED"},
    "MISSED": {"ESCALATED", "IN_PROGRESS", "RESCHEDULED", "CANCELLED"},
    "ESCALATED": {"IN_PROGRESS", "RESCHEDULED", "CANCELLED", "FAILED"},
    "FAILED": {"SCHEDULED", "CANCELLED"},
    "BLOCKED_COMPLIANCE": {"SCHEDULED", "CANCELLED"},
    "COMPLETED": set(),
    "CANCELLED": set(),
}
PRIORITIES = frozenset({"LOW", "NORMAL", "HIGH", "URGENT"})


class CallbackConflict(ValueError):
    pass


def normalized_phone(value: str) -> str:
    result = "+" + re.sub(r"\D", "", value)
    if not 8 <= len(result) <= 16:
        raise ValueError("invalid phone number")
    return result


def canonical_time(value: datetime, timezone: str) -> datetime:
    try:
        zone = ZoneInfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("unknown customer timezone") from exc
    if value.tzinfo is None:
        raise ValueError("scheduled_at must include UTC offset")
    # The supplied offset must agree with the named zone, preventing browser-local ambiguity.
    local = value.astimezone(zone)
    if local.utcoffset() != value.utcoffset():
        raise ValueError("scheduled_at offset does not match customer_timezone")
    return value.astimezone(UTC)


def reminders(scheduled_at: datetime) -> tuple[datetime, datetime, datetime]:
    return (
        scheduled_at - timedelta(hours=24),
        scheduled_at - timedelta(hours=1),
        scheduled_at - timedelta(minutes=15),
    )


def compliance_state(
    *,
    consent: bool,
    dnc: bool,
    suppressed: bool,
    within_calling_hours: bool,
    campaign_allowed: bool,
) -> tuple[str, dict[str, bool]]:
    checks = {
        "consent": consent,
        "dnc_clear": not dnc,
        "suppression_clear": not suppressed,
        "calling_hours": within_calling_hours,
        "campaign_allowed": campaign_allowed,
    }
    return ("SCHEDULED" if all(checks.values()) else "BLOCKED_COMPLIANCE"), checks


def transition(current: str, target: str) -> None:
    if target not in TRANSITIONS.get(current, set()):
        raise CallbackConflict(f"invalid callback transition {current} -> {target}")
