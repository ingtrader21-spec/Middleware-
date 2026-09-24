import pytest

from app.core.analytics import (
    ROLE_WEIGHTS,
    abandonment,
    aggregate_score,
    aht,
    asa,
    call_rating,
    lead_rating,
    occupancy,
    safe_ratio,
    service_level,
    speed_to_lead_bucket,
    weighted_agent_score,
)


def test_authoritative_formulas():
    assert asa(100, 4) == 25
    assert service_level(80, 100) == 80
    assert abandonment(5, 100) == 5
    assert aht(800, 100, 100, 10) == 100
    assert occupancy(800, 100, 100, 2000) == 50


@pytest.mark.parametrize(
    "fn,args",
    [
        (safe_ratio, (1, 0)),
        (asa, (1, 0)),
        (service_level, (1, 0)),
        (abandonment, (1, 0)),
        (aht, (1, 1, 1, 0)),
        (occupancy, (1, 1, 1, 0)),
    ],
)
def test_zero_denominator_is_na(fn, args):
    assert fn(*args) is None


@pytest.mark.parametrize(
    "seconds,bucket",
    [
        (0, "under_30_seconds"),
        (30, "30_to_60_seconds"),
        (60, "1_to_2_minutes"),
        (120, "2_to_5_minutes"),
        (300, "5_to_15_minutes"),
        (900, "over_15_minutes"),
    ],
)
def test_speed_to_lead_buckets(seconds, bucket):
    assert speed_to_lead_bucket(seconds) == bucket


@pytest.mark.parametrize(
    "score,label",
    [
        (95, "A+"),
        (85, "A"),
        (75, "B"),
        (65, "C"),
        (45, "D"),
        (20, "E"),
        (0, "blocked_or_ineligible"),
    ],
)
def test_lead_rating(score, label):
    assert lead_rating(score) == label


def test_compliance_overrides_call_score():
    assert call_rating(100, critical_violation=True) == "compliance_failure"
    assert call_rating(95) == "exceptional"


@pytest.mark.parametrize("role", sorted(ROLE_WEIGHTS))
def test_role_weights_sum_to_one_hundred(role):
    assert sum(ROLE_WEIGHTS[role].values()) == 100


def test_agent_score_is_advisory_and_sample_gated():
    components = {key: 80 for key in ROLE_WEIGHTS["sdr"]}
    assert weighted_agent_score("sdr", components, 2).level == "insufficient_sample"
    result = weighted_agent_score("sdr", components, 10)
    assert result.score == 80 and result.level == "strong_performer"
    assert result.advisory_only


def test_supervisor_or_campaign_score_is_sample_gated_and_compliance_overridden():
    assert aggregate_score({"qa": 90}, False).score is None
    assert aggregate_score({"qa": 95, "conversion": 95}, True).level == "elite"
    assert (
        aggregate_score({"qa": 95}, True, critical_compliance=True).level == "critical"
    )
