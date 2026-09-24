"""Deterministic, business-unit-scoped analytics and scoring primitives."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Mapping


def safe_ratio(
    numerator: float, denominator: float, percent: bool = True
) -> float | None:
    if denominator == 0:
        return None
    value = Decimal(str(numerator)) / Decimal(str(denominator))
    if percent:
        value *= 100
    return float(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def asa(wait_seconds: float, answered_inbound: int) -> float | None:
    return safe_ratio(wait_seconds, answered_inbound, percent=False)


def service_level(
    answered_within_threshold: int, eligible_inbound: int
) -> float | None:
    return safe_ratio(answered_within_threshold, eligible_inbound)


def abandonment(abandoned_queue_calls: int, queue_entered_calls: int) -> float | None:
    return safe_ratio(abandoned_queue_calls, queue_entered_calls)


def aht(
    talk_seconds: float, hold_seconds: float, wrap_seconds: float, handled_calls: int
) -> float | None:
    return safe_ratio(
        talk_seconds + hold_seconds + wrap_seconds, handled_calls, percent=False
    )


def occupancy(
    talk_seconds: float,
    hold_seconds: float,
    wrap_seconds: float,
    logged_in_available_seconds: float,
) -> float | None:
    return safe_ratio(
        talk_seconds + hold_seconds + wrap_seconds, logged_in_available_seconds
    )


def speed_to_lead_bucket(seconds: float) -> str:
    if seconds < 0:
        raise ValueError("speed-to-lead cannot be negative")
    if seconds < 30:
        return "under_30_seconds"
    if seconds < 60:
        return "30_to_60_seconds"
    if seconds < 120:
        return "1_to_2_minutes"
    if seconds < 300:
        return "2_to_5_minutes"
    if seconds < 900:
        return "5_to_15_minutes"
    return "over_15_minutes"


def lead_rating(score: int, blocked: bool = False) -> str:
    if blocked or score == 0:
        return "blocked_or_ineligible"
    if not 0 <= score <= 100:
        raise ValueError("score out of range")
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "E"


def call_rating(score: int, critical_violation: bool = False) -> str:
    if critical_violation:
        return "compliance_failure"
    if not 0 <= score <= 100:
        raise ValueError("score out of range")
    for threshold, label in (
        (95, "exceptional"),
        (85, "strong"),
        (75, "acceptable"),
        (65, "coaching_needed"),
        (50, "poor"),
        (0, "failed"),
    ):
        if score >= threshold:
            return label
    raise AssertionError


ROLE_WEIGHTS = {
    "sdr": {
        "attendance": 10,
        "contact": 20,
        "productivity": 15,
        "conversion": 20,
        "value": 5,
        "qa": 10,
        "compliance": 10,
        "satisfaction": 5,
        "follow_up": 5,
    },
    "closer": {
        "attendance": 5,
        "contact": 5,
        "productivity": 10,
        "conversion": 25,
        "value": 25,
        "qa": 10,
        "compliance": 10,
        "satisfaction": 5,
        "follow_up": 5,
    },
    "support": {
        "attendance": 10,
        "contact": 15,
        "productivity": 15,
        "conversion": 5,
        "value": 5,
        "qa": 15,
        "compliance": 15,
        "satisfaction": 15,
        "follow_up": 5,
    },
    "retention": {
        "attendance": 10,
        "contact": 10,
        "productivity": 10,
        "conversion": 20,
        "value": 20,
        "qa": 10,
        "compliance": 10,
        "satisfaction": 5,
        "follow_up": 5,
    },
    "upsell": {
        "attendance": 10,
        "contact": 10,
        "productivity": 10,
        "conversion": 20,
        "value": 20,
        "qa": 10,
        "compliance": 10,
        "satisfaction": 5,
        "follow_up": 5,
    },
    "transfer_coordinator": {
        "attendance": 10,
        "contact": 20,
        "productivity": 20,
        "conversion": 15,
        "value": 5,
        "qa": 10,
        "compliance": 10,
        "satisfaction": 5,
        "follow_up": 5,
    },
    "fulfillment": {
        "attendance": 10,
        "contact": 10,
        "productivity": 20,
        "conversion": 5,
        "value": 5,
        "qa": 15,
        "compliance": 15,
        "satisfaction": 10,
        "follow_up": 10,
    },
    "appointment_agent": {
        "attendance": 10,
        "contact": 15,
        "productivity": 15,
        "conversion": 15,
        "value": 10,
        "qa": 10,
        "compliance": 10,
        "satisfaction": 5,
        "follow_up": 10,
    },
}


@dataclass(frozen=True)
class ScoreResult:
    score: float | None
    level: str
    sample_size: int
    advisory_only: bool = True


def weighted_agent_score(
    role: str,
    components: Mapping[str, float],
    sample_size: int,
    minimum_sample: int = 5,
    critical_compliance: bool = False,
) -> ScoreResult:
    if role not in ROLE_WEIGHTS:
        raise ValueError("unknown role")
    if sample_size < minimum_sample:
        return ScoreResult(None, "insufficient_sample", sample_size)
    if set(components) != set(ROLE_WEIGHTS[role]):
        raise ValueError("component set does not match role")
    if any(not 0 <= value <= 100 for value in components.values()):
        raise ValueError("component score out of range")
    value = (
        sum(components[key] * weight for key, weight in ROLE_WEIGHTS[role].items())
        / 100
    )
    value = round(value, 2)
    if critical_compliance:
        return ScoreResult(value, "critical_review", sample_size)
    level = (
        "elite_performer"
        if value >= 95
        else "top_performer"
        if value >= 90
        else "strong_performer"
        if value >= 80
        else "meets_expectations"
        if value >= 70
        else "coaching_required"
        if value >= 60
        else "performance_plan"
        if value >= 50
        else "critical_review"
    )
    return ScoreResult(value, level, sample_size)


def aggregate_score(
    component_scores: Mapping[str, float],
    minimum_sample_met: bool,
    critical_compliance: bool = False,
) -> ScoreResult:
    if not minimum_sample_met:
        return ScoreResult(None, "insufficient_sample", 0)
    if not component_scores:
        raise ValueError("components required")
    value = round(sum(component_scores.values()) / len(component_scores), 2)
    if critical_compliance:
        return ScoreResult(value, "critical", len(component_scores))
    level = (
        "elite"
        if value >= 90
        else "strong"
        if value >= 80
        else "stable"
        if value >= 70
        else ("needs_improvement" if value >= 60 else "at_risk")
    )
    return ScoreResult(value, level, len(component_scores))
