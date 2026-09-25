from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.campaign_recycling import (
    CampaignRecyclingEngine,
    Candidate,
    ChannelHealth,
    Exposure,
    LeadSnapshot,
    PolicyProfile,
    Suppression,
)

NOW = datetime(2026, 9, 24, 16, 0, tzinfo=UTC)
SENDER = "00000000-0000-4000-8000-000000000111"


def candidate(
    *,
    campaign_id: str = "klyrow:cmp-a",
    channel: str = "email",
    priority: int = 10,
    touch_index: int = 1,
    sender_identity_id: str | None = SENDER,
    **overrides,
) -> Candidate:
    values = {
        "campaign_id": campaign_id,
        "campaign_version": 1,
        "channel": channel,
        "priority": priority,
        "touch_index": touch_index,
        "sender_identity_id": sender_identity_id,
        "active": True,
        "version_approved": True,
        "consent_granted": True,
        "sender_authorized": True,
        "dialing_eligible": False,
    }
    values.update(overrides)
    return Candidate(**values)


def snapshot(
    *,
    lifecycle_state: str = "ELIGIBLE",
    channel_health: dict | None = None,
    suppressions=(),
    exposures=(),
    cooling_until=None,
    reactivation_cycles: int = 0,
) -> LeadSnapshot:
    return LeadSnapshot(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        lifecycle_state=lifecycle_state,
        lifecycle_version=3,
        channel_health=channel_health
        or {
            "email": ChannelHealth("valid", NOW - timedelta(days=1)),
            "sms": ChannelHealth("valid", NOW - timedelta(days=1)),
            "whatsapp": ChannelHealth("valid", NOW - timedelta(days=1)),
            "voice": ChannelHealth("valid", NOW - timedelta(days=1)),
        },
        suppressions=suppressions,
        exposures=exposures,
        cooling_until=cooling_until,
        reactivation_cycles=reactivation_cycles,
    )


def engine(profile: str = "test") -> CampaignRecyclingEngine:
    return CampaignRecyclingEngine(PolicyProfile.load(profile))


def test_test_profile_is_configured_and_production_is_fail_closed() -> None:
    assert PolicyProfile.load("test").configured is True
    assert PolicyProfile.load("production").configured is False
    result = engine("production").evaluate(snapshot(), [candidate()], now=NOW)
    assert result.eligible is False
    assert result.reason_codes[0] == "POLICY_NOT_CONFIGURED"
    assert "PRODUCTION_NOT_AUTHORIZED" not in result.reason_codes


def test_deterministic_priority_selects_one_candidate() -> None:
    result = engine().evaluate(
        snapshot(),
        [
            candidate(campaign_id="klyrow:cmp-b", priority=20),
            candidate(campaign_id="klyrow:cmp-a", priority=10),
        ],
        now=NOW,
    )
    assert result.eligible is True
    assert result.selected is not None
    assert result.selected.campaign_id == "klyrow:cmp-a"
    assert result.reason_codes == ("ELIGIBLE",)


def test_hash_is_stable_for_same_inputs() -> None:
    first = engine().evaluate(snapshot(), [candidate()], now=NOW)
    second = engine().evaluate(snapshot(), [candidate()], now=NOW + timedelta(hours=1))
    assert first.decision_hash == second.decision_hash


def test_global_suppression_precedes_channel_suppression() -> None:
    suppressions = (
        Suppression(
            scope="channel",
            channel="email",
            campaign_id=None,
            reason="unsubscribe",
            occurred_at=NOW - timedelta(days=2),
            suppression_id="b",
        ),
        Suppression(
            scope="global",
            channel=None,
            campaign_id=None,
            reason="operator_block",
            occurred_at=NOW - timedelta(days=1),
            suppression_id="a",
        ),
    )
    result = engine().evaluate(
        snapshot(suppressions=suppressions), [candidate()], now=NOW
    )
    assert result.eligible is False
    assert result.reason_codes[0] == "SUPPRESSED_GLOBAL"


def test_bad_email_does_not_block_valid_sms() -> None:
    health = {
        "email": ChannelHealth("hard_bounce", NOW - timedelta(hours=2)),
        "sms": ChannelHealth("valid", NOW - timedelta(hours=2)),
    }
    result = engine().evaluate(
        snapshot(channel_health=health),
        [
            candidate(channel="email", priority=1),
            candidate(
                channel="sms",
                priority=2,
                sender_identity_id="00000000-0000-4000-8000-000000000222",
            ),
        ],
        now=NOW,
    )
    assert result.eligible is True
    assert result.selected is not None
    assert result.selected.channel == "sms"


def test_soft_bounce_defers_until_retry_time_then_clears() -> None:
    health = {"email": ChannelHealth("soft_bounce", NOW - timedelta(hours=1))}
    blocked = engine().evaluate(snapshot(channel_health=health), [candidate()], now=NOW)
    assert blocked.eligible is False
    assert blocked.reason_codes == ("CHANNEL_HEALTH_DEFERRED",)
    assert blocked.next_eligible_at == NOW + timedelta(hours=23)

    cleared = engine().evaluate(
        snapshot(channel_health=health),
        [candidate()],
        now=NOW + timedelta(days=2),
    )
    assert cleared.eligible is True


def test_duplicate_touch_is_rejected() -> None:
    existing = Exposure(
        campaign_id="klyrow:cmp-a",
        campaign_version=1,
        channel="email",
        touch_index=1,
        status="reserved",
        reserved_at=NOW - timedelta(days=3),
    )
    result = engine().evaluate(
        snapshot(exposures=(existing,)), [candidate()], now=NOW
    )
    assert result.eligible is False
    assert "DUPLICATE_TOUCH" in result.reason_codes


def test_campaign_cooldown_is_temporal() -> None:
    existing = Exposure(
        campaign_id="klyrow:cmp-a",
        campaign_version=1,
        channel="sms",
        touch_index=1,
        status="delivered",
        reserved_at=NOW - timedelta(days=1),
    )
    result = engine().evaluate(
        snapshot(exposures=(existing,)),
        [candidate(touch_index=2)],
        now=NOW,
    )
    assert result.eligible is False
    assert "CAMPAIGN_COOLDOWN_ACTIVE" in result.reason_codes
    assert result.next_eligible_at == NOW + timedelta(days=1)


def test_channel_cap_is_temporal_and_uses_channel_only() -> None:
    exposures = tuple(
        Exposure(
            campaign_id=f"klyrow:cmp-{index}",
            campaign_version=1,
            channel="email",
            touch_index=1,
            status="delivered",
            reserved_at=NOW - timedelta(days=index + 1),
        )
        for index in range(3)
    )
    result = engine().evaluate(snapshot(exposures=exposures), [candidate()], now=NOW)
    assert result.eligible is False
    assert "CHANNEL_CAP_REACHED" in result.reason_codes
    assert result.next_eligible_at is not None


def test_execute_remains_fail_closed_for_whatsapp() -> None:
    result = engine().evaluate(
        snapshot(),
        [
            candidate(
                campaign_id="whatsapp:cmp-a",
                channel="whatsapp",
                sender_identity_id="00000000-0000-4000-8000-000000000333",
            )
        ],
        mode="execute",
        now=NOW,
    )
    assert result.eligible is False
    assert result.reason_codes[:2] == (
        "PRODUCTION_NOT_AUTHORIZED",
        "CHANNEL_EXECUTION_NOT_SUPPORTED",
    )


def test_voice_can_plan_but_execute_is_unsupported() -> None:
    voice = candidate(
        campaign_id="klyrow:cmp-voice",
        channel="voice",
        sender_identity_id=None,
        dialing_eligible=True,
    )
    planned = engine().evaluate(snapshot(), [voice], now=NOW)
    assert planned.eligible is True
    executed = engine().evaluate(snapshot(), [voice], mode="execute", now=NOW)
    assert executed.eligible is False
    assert "PRODUCTION_NOT_AUTHORIZED" in executed.reason_codes
    assert "CHANNEL_EXECUTION_NOT_SUPPORTED" in executed.reason_codes


def test_lifecycle_terminal_state_blocks_all_candidates() -> None:
    result = engine().evaluate(
        snapshot(lifecycle_state="CONVERTED"), [candidate()], now=NOW
    )
    assert result.eligible is False
    assert "LIFECYCLE_TERMINAL" in result.reason_codes


def test_reactivation_limit_blocks_when_exhausted() -> None:
    result = engine().evaluate(
        snapshot(lifecycle_state="REACTIVATION", reactivation_cycles=2),
        [candidate()],
        now=NOW,
    )
    assert result.eligible is False
    assert "REACTIVATION_LIMIT_REACHED" in result.reason_codes


def test_recent_window_cap_over_by_two_waits_for_threshold_exposure() -> None:
    # 12 exposures vs cap 10, all outside the 7-day email channel window.
    exposures = tuple(
        Exposure(
            campaign_id=f"klyrow:cmp-old-{index}",
            campaign_version=1,
            channel="email",
            touch_index=1,
            status="delivered",
            reserved_at=NOW - timedelta(days=29 - index),
        )
        for index in range(12)
    )
    result = engine().evaluate(
        snapshot(exposures=exposures),
        [candidate(campaign_id="klyrow:cmp-new")],
        now=NOW,
    )
    assert result.reason_codes == ("RECENT_WINDOW_CAP_REACHED",)
    # Third-oldest (-27d) must expire before the count drops to 9.
    assert result.next_eligible_at == NOW + timedelta(days=3)

    still_capped = engine().evaluate(
        snapshot(exposures=exposures),
        [candidate(campaign_id="klyrow:cmp-new")],
        now=NOW + timedelta(days=1, seconds=1),
    )
    assert still_capped.reason_codes == ("RECENT_WINDOW_CAP_REACHED",)
    released = engine().evaluate(
        snapshot(exposures=exposures),
        [candidate(campaign_id="klyrow:cmp-new")],
        now=result.next_eligible_at,
    )
    assert released.eligible is True


def test_channel_cap_over_by_two_waits_for_threshold_exposure() -> None:
    # 5 email exposures vs cap 3 in a 168h window.
    exposures = tuple(
        Exposure(
            campaign_id=f"klyrow:cmp-old-{hours}",
            campaign_version=1,
            channel="email",
            touch_index=1,
            status="delivered",
            reserved_at=NOW - timedelta(hours=hours),
        )
        for hours in (150, 140, 130, 120, 110)
    )
    result = engine().evaluate(
        snapshot(exposures=exposures),
        [candidate(campaign_id="klyrow:cmp-new")],
        now=NOW,
    )
    assert result.reason_codes == ("CHANNEL_CAP_REACHED",)
    assert result.next_eligible_at == NOW + timedelta(hours=38)

    still_capped = engine().evaluate(
        snapshot(exposures=exposures),
        [candidate(campaign_id="klyrow:cmp-new")],
        now=NOW + timedelta(hours=18, seconds=1),
    )
    assert still_capped.reason_codes == ("CHANNEL_CAP_REACHED",)
    released = engine().evaluate(
        snapshot(exposures=exposures),
        [candidate(campaign_id="klyrow:cmp-new")],
        now=result.next_eligible_at,
    )
    assert released.eligible is True


def test_reactivation_requires_distinct_campaign_version() -> None:
    prior = Exposure(
        campaign_id="klyrow:cmp-a",
        campaign_version=1,
        channel="email",
        touch_index=1,
        status="delivered",
        reserved_at=NOW - timedelta(days=100),
    )
    reactivating = snapshot(
        lifecycle_state="REACTIVATION", reactivation_cycles=1, exposures=(prior,)
    )
    same_version = engine().evaluate(
        reactivating, [candidate(touch_index=2)], now=NOW
    )
    assert same_version.eligible is False
    assert same_version.reason_codes == ("CAMPAIGN_VERSION_EXHAUSTED",)
    assert same_version.next_eligible_at is None

    new_version = engine().evaluate(
        reactivating, [candidate(campaign_version=2)], now=NOW
    )
    assert new_version.eligible is True
    assert new_version.selected is not None
    assert new_version.selected.campaign_version == 2

    active = engine().evaluate(
        snapshot(lifecycle_state="ACTIVE_CYCLE", exposures=(prior,)),
        [candidate(touch_index=2)],
        now=NOW,
    )
    assert active.eligible is True
