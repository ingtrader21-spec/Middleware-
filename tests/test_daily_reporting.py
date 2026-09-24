from datetime import datetime, timezone

import pytest

from app.core.daily_reporting import (
    METRICS,
    Recipient,
    authorized,
    previous_local_day,
    quality_status,
    render_html,
    report_key,
    safe_ratio,
)


def test_metric_catalog_complete():
    assert len(METRICS) == 24 and len({m.code for m in METRICS}) == 24


def test_zero_denominator_is_na():
    assert safe_ratio(1, 0) is None
    assert safe_ratio(1, 4) == 25


def test_campaign_manager_scope():
    row = Recipient("mgr", "campaign_manager", frozenset({"TL"}), frozenset({"TL-C1"}))
    assert authorized(row, "TL", "TL-C1")
    assert not authorized(row, "TL", "TL-C2")
    assert not authorized(row, "DEV", "DEV-C1")


def test_director_and_superuser_scope():
    director = Recipient(
        "dir", "business_unit_director", frozenset({"DEV"}), frozenset()
    )
    admin = Recipient("root", "platform_superuser", frozenset(), frozenset())
    assert authorized(director, "DEV", "any")
    assert not authorized(director, "SCP", "any")
    assert authorized(admin, "SCP", "any")
    assert not authorized(admin, "SCP", "any", detail=True)


def test_technical_admin_health_only():
    tech = Recipient("tech", "technical_admin", frozenset({"TL"}), frozenset())
    assert authorized(tech, "TL", "x")
    assert not authorized(tech, "TL", "x", detail=True)


def test_idempotency_and_amendment_version():
    assert report_key("2026-07-24", "campaign", "TL-C1", 1) == report_key(
        "2026-07-24", "campaign", "TL-C1", 1
    )
    assert report_key("2026-07-24", "campaign", "TL-C1", 1) != report_key(
        "2026-07-24", "campaign", "TL-C1", 2
    )


def test_timezone_previous_day_including_dst():
    start, end = previous_local_day(
        datetime(2026, 3, 9, 12, tzinfo=timezone.utc), "America/New_York"
    )
    assert start.date().isoformat() == "2026-03-08"
    assert end.date().isoformat() == "2026-03-09"


def test_quality_gate():
    assert quality_status(True, []) == "complete"
    assert quality_status(True, ["vicidial"]) == "partial"
    assert quality_status(False, []) == "blocked"


def test_html_is_escaped_and_secure():
    result = render_html(
        "<Daily>", "TL", "C1", {"x": "<secret>"}, "https://reports.invalid/r/opaque"
    )
    assert "<secret>" not in result and "&lt;secret&gt;" in result
    with pytest.raises(ValueError):
        render_html("x", "TL", "C1", {}, "http://unsafe")
