"""Private MCR telemetry. Only fixed vocabularies cross this boundary.

No tenant, lead, campaign, address, payload, exception, or caller-supplied trace
identifier is exported. The registry is deliberately NOT Prometheus' default.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import logging
import math
from uuid import uuid4
from typing import TypeGuard

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

CHANNELS = frozenset({"email", "sms", "whatsapp", "voice", "none"})
EVENT_TYPES = frozenset(
    {
        "accepted",
        "queued",
        "dispatched",
        "delivered",
        "deferred",
        "soft_bounce",
        "hard_bounce",
        "complaint",
        "unsubscribe",
        "open",
        "read",
        "click",
        "reply",
        "conversion",
    }
)
MODES = frozenset({"plan", "read", "execute"})
OUTCOMES = frozenset(
    {"applied", "partial", "duplicate", "replayed", "rejected", "failed"}
)


def _bounded(value: str, allowed: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "unknown"


def _nonnegative(value: object) -> TypeGuard[float]:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


class MCRObservability:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.decisions = Counter(
            "codestra_mcr_decisions_total",
            "Decision reasons (one per unique reason).",
            ("mode", "channel", "reason"),
            registry=self.registry,
        )
        self.blocks = Counter(
            "codestra_mcr_blocks_total",
            "Suppression, health and cap decision reasons.",
            ("channel", "family", "reason"),
            registry=self.registry,
        )
        self.deliveries = Counter(
            "codestra_mcr_delivery_total",
            "Committed projection outcomes or failed attempts.",
            ("channel", "outcome"),
            registry=self.registry,
        )
        self.delivery_health = Counter(
            "codestra_mcr_delivery_health_total",
            "Completed normalized event projections, excluding duplicates and partial attempts.",
            ("channel", "event_type"),
            registry=self.registry,
        )
        self.readbacks = Counter(
            "codestra_mcr_readback_total",
            "Tenant-scoped readback attempts.",
            ("outcome",),
            registry=self.registry,
        )
        self.replays = Counter(
            "codestra_mcr_replays_total",
            "Replayed delivery projections including incomplete retries.",
            ("channel", "outcome"),
            registry=self.registry,
        )
        self.lag = Histogram(
            "codestra_mcr_projection_lag_seconds",
            "Receive-to-commit lag for completed projections.",
            ("channel",),
            buckets=(1, 5, 30, 60, 300, 900, 3600),
            registry=self.registry,
        )
        self.duration = Histogram(
            "codestra_mcr_operation_seconds",
            "Local operation duration.",
            ("operation",),
            registry=self.registry,
        )
        self.evidence_available = Gauge(
            "codestra_mcr_dead_letter_evidence_available",
            "One only when a durable MCR dead-letter authority is implemented.",
            registry=self.registry,
        )
        self.evidence_available.set(0)

    def _span(self, operation: str, attributes: dict, duration: float) -> None:
        elapsed = duration if _nonnegative(duration) else 0.0
        self.duration.labels(operation).observe(elapsed)
        # Local completed spans use generated identities: no untrusted baggage,
        # exception messages or inbound correlation IDs enter logs/traces.
        record = {
            "event": "mcr.span.completed",
            "operation": operation,
            "trace_id": uuid4().hex,
            "span_id": uuid4().hex[:16],
            "duration_seconds": elapsed,
            **attributes,
        }
        try:
            logging.getLogger("codestra.mcr").info(json.dumps(record, sort_keys=True))
        except Exception:
            # A broken log sink must not rewrite a committed projection result.
            pass

    def decision(
        self, *, mode: str, channel: str, reasons: tuple[str, ...], duration: float = 0
    ) -> None:
        from app.core.campaign_recycling import REASON_PRECEDENCE

        safe_mode = _bounded(mode, MODES)
        safe_channel = _bounded(channel, CHANNELS)
        safe_reasons = sorted(
            {
                r if isinstance(r, str) and r in REASON_PRECEDENCE else "UNKNOWN"
                for r in reasons
            }
        ) or ["UNKNOWN"]
        for reason in safe_reasons:
            self.decisions.labels(safe_mode, safe_channel, reason).inc()
            family = (
                "suppression"
                if reason.startswith("SUPPRESSED_")
                else "health"
                if reason.startswith("CHANNEL_HEALTH_")
                else "cap"
                if reason
                in {
                    "LIFETIME_EXPOSURE_CAP_REACHED",
                    "RECENT_WINDOW_CAP_REACHED",
                    "CHANNEL_CAP_REACHED",
                    "REACTIVATION_LIMIT_REACHED",
                    "CAMPAIGN_VERSION_EXHAUSTED",
                }
                else None
            )
            if family:
                self.blocks.labels(safe_channel, family, reason).inc()
        self._span(
            "decision",
            {"mode": safe_mode, "channel": safe_channel, "reasons": safe_reasons},
            duration,
        )

    def delivery(
        self,
        *,
        channel: str,
        outcome: str,
        lag_seconds: float | None = None,
        duration: float = 0,
        replayed: bool = False,
        event_type: str = "unknown",
    ) -> None:
        safe_channel = _bounded(channel, CHANNELS)
        safe_outcome = _bounded(outcome, OUTCOMES)
        self.deliveries.labels(safe_channel, safe_outcome).inc()
        if replayed or safe_outcome in {"replayed", "duplicate"}:
            self.replays.labels(safe_channel, safe_outcome).inc()
        if safe_outcome in {"applied", "replayed"}:
            self.delivery_health.labels(
                safe_channel, _bounded(event_type, EVENT_TYPES)
            ).inc()
        if safe_outcome in {"applied", "replayed"} and _nonnegative(lag_seconds):
            self.lag.labels(safe_channel).observe(lag_seconds)
        self._span(
            "delivery_projection",
            {"channel": safe_channel, "outcome": safe_outcome},
            duration,
        )

    def readback(self, *, outcome: str) -> None:
        safe = _bounded(
            outcome, frozenset({"ready", "blocked", "unavailable", "denied"})
        )
        self.readbacks.labels(safe).inc()
        self._span("delivery_readback", {"outcome": safe}, 0)


MCR_TELEMETRY = MCRObservability()


def delivery_readback(
    *,
    pending: int,
    partial: int,
    oldest_seconds: float,
    dead_letter: int | None,
    sampled_at: datetime | None,
    now: datetime | None = None,
) -> dict:
    """Assess trusted tenant-scoped evidence; unknown is never healthy.

    This is a contract boundary, not authentication. Callers must scope their
    database query from the authenticated principal, never from request labels.
    """
    for count in (pending, partial) + (() if dead_letter is None else (dead_letter,)):
        if type(count) is not int or count < 0:
            raise ValueError("invalid MCR readback evidence")
    if not _nonnegative(oldest_seconds):
        raise ValueError("invalid MCR readback evidence")
    now = now or datetime.now(UTC)
    if now.tzinfo is None or (sampled_at is not None and sampled_at.tzinfo is None):
        raise ValueError("invalid MCR readback evidence")
    reasons = []
    if sampled_at is None or not 0 <= (now - sampled_at).total_seconds() <= 60:
        reasons.append("PROJECTION_EVIDENCE_STALE_OR_MISSING")
    if dead_letter is None:
        reasons.append("DEAD_LETTER_EVIDENCE_UNAVAILABLE")
    elif dead_letter:
        reasons.append("DEAD_LETTER_PRESENT")
    if partial:
        reasons.append("PARTIAL_PROJECTION")
    if oldest_seconds > 300:
        reasons.append("PROJECTION_LAG_EXCEEDED")
    return {
        "ready": not reasons,
        "pending": pending,
        "partial": partial,
        "oldest_seconds": oldest_seconds,
        "dead_letter": dead_letter,
        "sampled_at": sampled_at.isoformat() if sampled_at else None,
        "reasons": reasons,
        "provider_effects_enabled": False,
    }
