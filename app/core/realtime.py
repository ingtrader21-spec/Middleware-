"""Low-latency, fail-closed real-time control-plane primitives."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

FEATURE_FLAGS = {
    "ENABLE_REALTIME_TELEPHONY_EVENTS",
    "ENABLE_REDIS_CALL_STATE",
    "ENABLE_WEBSOCKET_SCREEN_POP",
    "ENABLE_LAZY_CUSTOMER_CONTEXT",
    "ENABLE_WEBRTC_AGENT_PHONE",
    "ENABLE_LIVE_VAD",
    "ENABLE_STREAMING_STT",
    "ENABLE_STREAMING_LLM",
    "ENABLE_STREAMING_TTS",
    "ENABLE_AI_BARGE_IN",
    "ENABLE_AI_LOW_LATENCY_MODE",
    "ENABLE_LOCAL_AI_INFERENCE",
    "ENABLE_EXTERNAL_AI_FALLBACK",
    "ENABLE_PRODUCTION_TRAFFIC",
}


class RealtimeDenied(PermissionError):
    pass


@dataclass(frozen=True)
class TraceSpan:
    name: str
    started_ns: int
    ended_ns: int
    trace_id: str
    correlation_id: str

    @property
    def duration_ms(self) -> float:
        return (self.ended_ns - self.started_ns) / 1_000_000


class TraceRecorder:
    def __init__(self, trace_id: str, correlation_id: str):
        self.trace_id = trace_id
        self.correlation_id = correlation_id
        self.spans: list[TraceSpan] = []

    def measure(self, name: str, operation):
        started = time.perf_counter_ns()
        result = operation()
        self.spans.append(
            TraceSpan(
                name,
                started,
                time.perf_counter_ns(),
                self.trace_id,
                self.correlation_id,
            )
        )
        return result


@dataclass(frozen=True)
class SocketScope:
    user_id: str
    user_session_id: str
    business_unit: str
    campaigns: frozenset[str]
    active_call_id: str
    endpoint_id: str


@dataclass(frozen=True)
class ScreenPop:
    sequence: int
    uniqueid: str
    assigned_user_id: str
    business_unit: str
    campaign: str
    masked_customer_reference: str
    company: str | None
    lead_id: str | None
    customer_id: str | None
    language: str
    ivr_intent: str | None
    appointment: bool
    compact_ai_summary: str | None
    high_priority_alerts: tuple[str, ...] = ()


def authorize_socket(scope: SocketScope, event: ScreenPop) -> None:
    if (
        event.assigned_user_id != scope.user_id
        or event.business_unit != scope.business_unit
        or event.campaign not in scope.campaigns
        or event.uniqueid != scope.active_call_id
    ):
        raise RealtimeDenied(
            "cross-agent, cross-unit, campaign, or call delivery denied"
        )


class ReplayBuffer:
    """Bounded stand-in for Redis Stream behavior; never durable truth."""

    def __init__(self, maximum: int = 1000):
        self._events: deque[ScreenPop] = deque(maxlen=maximum)
        self._seen: set[tuple[str, int]] = set()
        self._lock = Lock()

    def publish(self, event: ScreenPop) -> bool:
        identity = (event.uniqueid, event.sequence)
        with self._lock:
            if identity in self._seen:
                return False
            self._seen.add(identity)
            self._events.append(event)
            return True

    def replay(self, uniqueid: str, last_sequence: int) -> tuple[ScreenPop, ...]:
        return tuple(
            e
            for e in self._events
            if e.uniqueid == uniqueid and e.sequence > last_sequence
        )


REDIS_KEY_TTLS = {
    "agent_presence": 90,
    "active_call": 7200,
    "call_agent": 7200,
    "call_campaign": 7200,
    "websocket_route": 90,
    "screen_pop_context": 900,
    "rate_limit": 60,
    "distributed_lock": 30,
    "appointment_preparation": 3600,
    "ai_conversation": 3600,
    "partial_transcript": 900,
}


@dataclass(frozen=True)
class CustomerReadModel:
    customer_id: str | None
    lead_id: str | None
    masked_phone: str
    business_unit: str
    campaign: str
    owner_id: str
    name_or_masked_reference: str
    company: str | None
    language: str
    previous_disposition: str | None
    active_appointment: bool
    opportunity_id: str | None
    compact_summary: str | None


LAZY_CONTEXT_ORDER = (
    "basic_card",
    "opportunity",
    "recent_interactions",
    "open_tickets",
    "orders_and_payment_status",
    "full_history_on_request",
)


@dataclass
class ConversationState:
    business_unit: str
    campaign: str
    customer_reference: str
    current_intent: str | None = None
    current_stage: str | None = None
    disclosures: set[str] = field(default_factory=set)
    objections: deque[str] = field(default_factory=lambda: deque(maxlen=10))
    recent_turns: deque[str] = field(default_factory=lambda: deque(maxlen=12))
    tools_used: set[str] = field(default_factory=set)


VAD_THRESHOLDS_MS = {
    "default": {"end_silence": 275, "pre_speech": 150, "post_speech": 100},
    "SCP": {"end_silence": 350, "pre_speech": 200, "post_speech": 150},
}


def webrtc_ready(
    *, registered: bool, audio_device: bool, websocket: bool, campaign_authorized: bool
) -> bool:
    return registered and audio_device and websocket and campaign_authorized


def failure_degradation(dependency: str) -> dict[str, Any]:
    policies: dict[str, dict[str, Any]] = {
        "stt": {
            "telephony_continues": True,
            "live_transcript": False,
            "queue_post_call": True,
        },
        "llm": {
            "telephony_continues": True,
            "fallback": "deterministic_human_transfer",
        },
        "tts": {
            "telephony_continues": True,
            "fallback": "cached_announcement_human_transfer",
        },
        "redis": {
            "telephony_continues": True,
            "new_ai_sessions": False,
            "cross_agent_delivery": False,
        },
        "odoo": {
            "telephony_continues": True,
            "persist_events": True,
            "reconcile_later": True,
        },
        "websocket": {
            "telephony_continues": True,
            "manual_lookup": True,
            "reconnect": True,
        },
    }
    if dependency not in policies:
        raise ValueError("unknown dependency")
    return policies[dependency]


class FeaturePolicy:
    def enabled(self, flag: str, environment: str, unit: str, campaign: str) -> bool:
        if flag not in FEATURE_FLAGS:
            raise ValueError("unknown real-time flag")
        return False
