"""Fail-closed appointment scheduling and fake telephony contracts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import Lock
from zoneinfo import ZoneInfo

STATES = {
    "draft",
    "scheduled",
    "confirmed",
    "reminder_pending",
    "reminder_sent",
    "preparing",
    "due",
    "in_progress",
    "completed",
    "rescheduled",
    "cancelled",
    "customer_no_answer",
    "agent_missed",
    "customer_requested_callback",
    "supervisor_review",
    "failed",
}
TRANSITIONS = {
    "draft": {"scheduled", "cancelled"},
    "scheduled": {"confirmed", "reminder_pending", "rescheduled", "cancelled"},
    "confirmed": {"reminder_pending", "preparing", "rescheduled", "cancelled"},
    "reminder_pending": {
        "reminder_sent",
        "preparing",
        "due",
        "rescheduled",
        "cancelled",
    },
    "reminder_sent": {"preparing", "due", "rescheduled", "cancelled"},
    "preparing": {"due", "in_progress", "rescheduled", "cancelled", "failed"},
    "due": {
        "in_progress",
        "agent_missed",
        "customer_no_answer",
        "rescheduled",
        "failed",
    },
    "in_progress": {"completed", "customer_requested_callback", "failed"},
    "agent_missed": {"supervisor_review", "rescheduled"},
    "supervisor_review": {"rescheduled", "cancelled", "completed"},
}
EVENT_OFFSETS = {
    "popup_15m": -15,
    "email_15m": -15,
    "warning_5m": -5,
    "pause_2m": -2,
    "due": 0,
    "overdue_2m": 2,
    "supervisor_5m": 5,
    "manager_15m": 15,
}


def transition(current: str, target: str) -> str:
    if (
        current not in STATES
        or target not in STATES
        or target not in TRANSITIONS.get(current, set())
    ):
        raise ValueError(f"invalid appointment transition {current}->{target}")
    return target


def reminder_events(
    appointment_id: str, start_utc: datetime
) -> list[dict[str, object]]:
    return [
        {
            "type": kind,
            "scheduled_at": start_utc + timedelta(minutes=offset),
            "idempotency_key": f"appointment:{appointment_id}:{kind}",
        }
        for kind, offset in EVENT_OFFSETS.items()
    ]


def local_time(value: datetime, timezone: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError("appointment timestamps must be timezone-aware")
    return value.astimezone(ZoneInfo(timezone))


def may_access(
    actor_unit: str, actor_campaigns: set[str], unit: str, campaign: str
) -> bool:
    return actor_unit == unit and campaign in actor_campaigns


@dataclass(frozen=True)
class TelephonyState:
    state: str
    confirmed: bool


class FakeTelephonyAdapter:
    """Synthetic adapter: never dials, registers, or touches Server B."""

    def pause(self, agent: str, active_call: bool) -> TelephonyState:
        return (
            TelephonyState("pause_pending", False)
            if active_call
            else TelephonyState("APPT_PREP", True)
        )

    def resume(self, disposition_complete: bool) -> TelephonyState:
        if not disposition_complete:
            return TelephonyState("APPT_PREP", False)
        return TelephonyState("READY", True)

    def start_call(self) -> None:
        raise PermissionError("live dial authorization is not granted")


class IdempotencyLedger:
    def __init__(self):
        self._values: dict[str, tuple[str, object]] = {}
        self._lock = Lock()

    def claim(self, key: str, body: str, result: object) -> object:
        digest = hashlib.sha256(body.encode()).hexdigest()
        with self._lock:
            prior = self._values.get(key)
            if prior:
                if prior[0] != digest:
                    raise ValueError("idempotency conflict")
                return prior[1]
            self._values[key] = (digest, result)
            return result
