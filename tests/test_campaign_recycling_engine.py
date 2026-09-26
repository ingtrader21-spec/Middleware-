from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from app.commands import (
    CommandEnvelope,
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    PostgresCommandStore,
)
from app.core.campaign_recycling import (
    CampaignRecyclingConflict,
    CampaignRecyclingPolicyError,
    CampaignRecyclingIdempotencyConflict,
    CampaignRecyclingLifecycleConflict,
    CampaignRecyclingNotFound,
    CampaignRecyclingEngine,
    Candidate,
    ChannelHealth,
    Exposure,
    LeadSnapshot,
    PolicyProfile,
    PostgresCampaignRecyclingStore,
    Suppression,
    canonical_digest,
    delivery_event_payload_hash,
    next_action_document,
)
from app.core.campaign_recycling_contract import validator as mcr_contract_validator

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


def delivery_event(**overrides):
    value = {
        "schema_version": "1.0",
        "automated_suspected": False,
        "event_id": "evt-mcr-00000001",
        "event_type": "open",
        "source": "klyrow",
        "provider": "postal",
        "tenant_id": "TEST_SYN_TENANT",
        "lead_id": "100-L-00000001",
        "channel": "email",
        "campaign_id": "klyrow:cmp-a",
        "campaign_version": 1,
        "exposure_idempotency_key": "mcr1:" + "1" * 64,
        "message_id": None,
        "provider_message_id": "pm-1",
        "correlation_id": "corr-event-1",
        "causation_id": None,
        "occurred_at": NOW.isoformat(),
        "received_at": NOW.isoformat(),
        "payload_hash": "e" * 64,
        "origin": {
            "inbox": "klyrow_delivery_event_inbox",
            "inbox_event_id": "raw-1",
        },
    }
    value.update(overrides)
    if value["event_type"] in {"soft_bounce", "hard_bounce"}:
        value["bounce_class"] = "soft" if value["event_type"] == "soft_bounce" else "hard"
    return value


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


def test_hash_changes_when_material_inputs_change_even_if_decision_does_not() -> None:
    base = engine().evaluate(snapshot(), [candidate(priority=10)], now=NOW)
    changed_priority = engine().evaluate(snapshot(), [candidate(priority=20)], now=NOW)
    changed_health_evidence = engine().evaluate(
        snapshot(channel_health={
            "email": ChannelHealth("valid", NOW - timedelta(days=2)),
            "sms": ChannelHealth("valid", NOW - timedelta(days=1)),
            "whatsapp": ChannelHealth("valid", NOW - timedelta(days=1)),
            "voice": ChannelHealth("valid", NOW - timedelta(days=1)),
        }),
        [candidate(priority=10)],
        now=NOW,
    )
    assert base.eligible and changed_priority.eligible and changed_health_evidence.eligible
    assert base.reason_codes == changed_priority.reason_codes == changed_health_evidence.reason_codes
    assert base.decision_hash != changed_priority.decision_hash
    assert base.decision_hash != changed_health_evidence.decision_hash


def test_no_candidate_is_explicitly_blocked() -> None:
    result = engine().evaluate(snapshot(), [], now=NOW)
    assert result.eligible is False
    assert result.selected is None
    assert result.reason_codes == ("NO_CANDIDATE",)
    assert result.next_eligible_at is None


def test_lifetime_exposure_cap_is_enforced() -> None:
    exposures = tuple(
        Exposure(
            campaign_id=f"klyrow:cmp-{index}",
            campaign_version=1,
            channel="email",
            touch_index=1,
            status="delivered",
            reserved_at=NOW - timedelta(days=60 + index),
        )
        for index in range(40)
    )
    result = engine().evaluate(snapshot(exposures=exposures), [candidate()], now=NOW)
    assert result.eligible is False
    assert "LIFETIME_EXPOSURE_CAP_REACHED" in result.reason_codes


def test_unconfigured_policy_fails_closed_without_applying_code_defaults() -> None:
    result = engine("production").evaluate(
        snapshot(
            lifecycle_state="REACTIVATION",
            channel_health={"email": ChannelHealth("possible", NOW - timedelta(days=1))},
            reactivation_cycles=999,
        ),
        [candidate()],
        now=NOW,
    )
    assert result.eligible is False
    assert result.reason_codes[0] == "POLICY_NOT_CONFIGURED"
    assert "CHANNEL_HEALTH_POLICY_GATED" not in result.reason_codes
    assert "REACTIVATION_LIMIT_REACHED" not in result.reason_codes
    assert "CAMPAIGN_VERSION_EXHAUSTED" not in result.reason_codes


def test_next_action_document_matches_frozen_contract() -> None:
    lead = snapshot()
    decision = engine().evaluate(lead, [candidate()], now=NOW)
    document = next_action_document(
        decision,
        lead,
        mode="plan",
        evaluated_at=NOW,
        correlation_id="corr-mcr-contract-1",
    )
    assert mcr_contract_validator(
        "./next-action.v1.schema.json"
    ).is_valid(document), list(
        mcr_contract_validator("./next-action.v1.schema.json").iter_errors(document)
    )
    assert document["provider_effects"] == "none"
    assert document["dry_run"] is True
    assert document["selected"]["exposure_idempotency_key"].startswith("mcr1:")
    assert document["decision_hash"] == decision.decision_hash


def test_next_action_document_redacts_candidates_without_changing_decision() -> None:
    lead = snapshot()
    decision = engine().evaluate(
        lead,
        [
            candidate(campaign_id="klyrow:cmp-a", priority=1),
            candidate(campaign_id="klyrow:cmp-b", priority=2),
        ],
        now=NOW,
    )
    document = next_action_document(
        decision,
        lead,
        mode="read",
        evaluated_at=NOW,
        correlation_id="corr-mcr-contract-2",
        candidates_redacted=True,
    )
    assert document["candidates_redacted"] is True
    assert document["candidates"] == []
    assert mcr_contract_validator("./next-action.v1.schema.json").is_valid(document)


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


class _Txn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeConn:
    def __init__(self):
        self.fetchrow_results = []
        self.fetch_results = []
        self.executed = []

    def transaction(self):
        return _Txn()

    async def fetchrow(self, sql, *args):
        self.executed.append(("fetchrow", sql, args))
        if self.fetchrow_results:
            return self.fetchrow_results.pop(0)
        return None

    async def fetch(self, sql, *args):
        self.executed.append(("fetch", sql, args))
        if self.fetch_results:
            return self.fetch_results.pop(0)
        return []

    async def execute(self, sql, *args):
        self.executed.append(("execute", sql, args))
        normalized = " ".join(sql.split())
        if normalized.startswith("UPDATE "):
            return "UPDATE 1"
        if normalized.startswith("DELETE "):
            return "DELETE 1"
        return "INSERT 0 1"


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _Acquire(self.conn)


@pytest.mark.asyncio
async def test_journey_read_is_bounded_and_serializable() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [
        {
            "tenant_id": "TEST_SYN_TENANT",
            "lead_id": "100-L-00000001",
            "state": "ELIGIBLE",
            "version": 3,
            "updated_at": NOW,
        }
    ]
    conn.fetch_results = [
        [
            {
                "event_id": 1,
                "version": 1,
                "from_state": None,
                "to_state": "NEW",
                "reason_code": "LEAD_REGISTERED",
                "source": "leads",
                "occurred_at": NOW - timedelta(days=2),
                "recorded_at": NOW - timedelta(days=2),
                "correlation_id": "corr-1",
                "evidence_hash": "a" * 64,
                "evidence_ref": None,
            }
        ],
        [
            {
                "channel": "email",
                "address_ref": "addr-email-1",
                "state": "valid",
                "previous_state": "unknown",
                "source": "lead_validation",
                "reason_code": "VALIDATION_PASSED",
                "occurred_at": NOW - timedelta(days=1),
                "recorded_at": NOW - timedelta(days=1),
                "evidence_hash": "b" * 64,
                "health_version": 2,
                "correlation_id": "corr-2",
                "updated_at": NOW - timedelta(days=1),
            }
        ],
        [],
        [],
    ]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    result = await store.journey(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        limit=100,
    )
    assert result["current"]["state"] == "ELIGIBLE"
    assert result["lifecycle"][0]["to_state"] == "NEW"
    assert result["channel_health"][0]["channel"] == "email"
    assert result["truncated"] is False


@pytest.mark.asyncio
async def test_journey_limit_fails_closed() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="journey limit"):
        await store.journey(
            tenant_id="TEST_SYN_TENANT",
            lead_id="100-L-00000001",
            limit=201,
        )


@pytest.mark.asyncio
async def test_load_snapshot_uses_explicit_address_refs() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [
        {"state": "ELIGIBLE", "version": 3, "updated_at": NOW},
        {
            "channel": "email",
            "address_ref": "addr-email-1",
            "state": "valid",
            "occurred_at": NOW - timedelta(days=1),
        },
    ]
    conn.fetch_results = [[], [], []]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    loaded = await store.load_snapshot(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        address_refs={"email": "addr-email-1"},
        policy=PolicyProfile.load("test"),
    )
    assert loaded.lifecycle_state == "ELIGIBLE"
    assert loaded.channel_health["email"].address_ref == "addr-email-1"
    assert loaded.exposures == ()
    assert loaded.suppressions == ()


@pytest.mark.asyncio
async def test_suppression_health_requires_atomic_suppression() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="requires an atomic suppression"):
        await store.record_channel_health(
            tenant_id="TEST_SYN_TENANT",
            lead_id="100-L-00000001",
            channel="email",
            address_ref="addr-email-1",
            state="unsubscribed",
            source="klyrow_delivery_event",
            reason_code="UNSUBSCRIBE",
            occurred_at=NOW,
            evidence_hash="d" * 64,
            correlation_id="corr-health-1",
        )


@pytest.mark.asyncio
async def test_delivery_health_cannot_create_global_suppression() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="channel-scoped unsubscribe"):
        await store.record_channel_health(
            tenant_id="TEST_SYN_TENANT",
            lead_id="100-L-00000001",
            channel="email",
            address_ref="addr-email-1",
            state="unsubscribed",
            source="klyrow_delivery_event",
            reason_code="UNSUBSCRIBE",
            occurred_at=NOW,
            evidence_hash="d" * 64,
            correlation_id="corr-health-global-block",
            suppression_id=uuid4(),
            suppression_scope="global",
            suppression_reason="unsubscribe",
            suppression_requested_by="svc-klyrow",
        )


@pytest.mark.asyncio
async def test_stale_weaker_health_is_atomic_noop() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [
        {"state": "hard_bounce", "health_version": 4},
        None,
        {"health_version": 4},
    ]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    version = await store.record_channel_health(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        channel="email",
        address_ref="addr-email-1",
        state="valid",
        source="klyrow_delivery_event",
        reason_code="DELIVERY_CONFIRMED",
        occurred_at=NOW - timedelta(days=1),
        evidence_hash="d" * 64,
        correlation_id="corr-health-stale-valid",
    )
    assert version == 4
    upsert = next(
        sql for kind, sql, _ in conn.executed if "INSERT INTO mcr_channel_health" in sql
    )
    assert "EXCLUDED.occurred_at < mcr_channel_health.occurred_at" in upsert
    assert "END > CASE mcr_channel_health.state" in upsert


@pytest.mark.asyncio
async def test_channel_health_and_suppression_share_transaction() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [None, {"health_version": 1}]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    version = await store.record_channel_health(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        channel="email",
        address_ref="addr-email-1",
        state="unsubscribed",
        source="klyrow_delivery_event",
        reason_code="UNSUBSCRIBE",
        occurred_at=NOW,
        evidence_hash="d" * 64,
        correlation_id="corr-health-2",
        suppression_id=uuid4(),
        suppression_scope="channel",
        suppression_reason="unsubscribe",
        suppression_requested_by="svc-klyrow",
    )
    assert version == 1
    statements = [item[1] for item in conn.executed]
    assert any("INSERT INTO mcr_channel_health" in sql for sql in statements)
    assert any("INSERT INTO mcr_suppressions" in sql for sql in statements)


@pytest.mark.asyncio
async def test_channel_health_returns_committed_version_on_conflict() -> None:
    conn = FakeConn()
    # The pre-read saw no row, but a concurrent insert won; the upsert
    # takes the ON CONFLICT path and PostgreSQL commits version 2.
    conn.fetchrow_results = [None, {"health_version": 2}]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    version = await store.record_channel_health(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        channel="email",
        address_ref="addr-email-1",
        state="valid",
        source="lead_validation",
        reason_code="VALIDATION_PASSED",
        occurred_at=NOW,
        evidence_hash="d" * 64,
        correlation_id="corr-health-3",
    )
    assert version == 2
    upsert = next(
        sql for kind, sql, _ in conn.executed if "INSERT INTO mcr_channel_health" in sql
    )
    assert "RETURNING health_version" in upsert

    missing = FakeConn()
    missing.fetchrow_results = [None, None]
    with pytest.raises(CampaignRecyclingConflict, match="no committed version"):
        await PostgresCampaignRecyclingStore(FakePool(missing)).record_channel_health(
            tenant_id="TEST_SYN_TENANT",
            lead_id="100-L-00000001",
            channel="email",
            address_ref="addr-email-1",
            state="valid",
            source="lead_validation",
            reason_code="VALIDATION_PASSED",
            occurred_at=NOW,
            evidence_hash="d" * 64,
            correlation_id="corr-health-4",
        )


def _soft_bounce_conn(streak: int) -> FakeConn:
    conn = FakeConn()
    conn.fetchrow_results = [
        {"id": 11, "projection_state": "pending"},
        {
            "exposure_id": uuid4(),
            "lead_id": "100-L-00000001",
            "campaign_id": "klyrow:cmp-a",
            "campaign_version": 1,
            "channel": "email",
            "status": "delivered",
            "engagement_outcome": "none",
            "negative_outcome": "soft_bounce",
            "message_id": None,
            "provider_message_id": "pm-1",
            "status_at": NOW - timedelta(days=3),
            "engagement_outcome_at": None,
            "negative_outcome_at": NOW - timedelta(days=2),
            "ledger_version": 2,
        },
        {
            "state": "soft_bounce",
            "health_version": 2,
            "occurred_at": NOW - timedelta(days=2),
        },
        {"soft_bounce_count": streak},
    ]
    return conn


def _health_upsert_args(conn: FakeConn) -> tuple:
    return next(
        args
        for kind, sql, args in conn.executed
        if kind == "execute" and "INSERT INTO mcr_channel_health" in sql
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("streak", "expected_state", "expected_reason"),
    [
        (2, "soft_bounce", "SOFT_BOUNCE"),
        (3, "hard_bounce", "SOFT_BOUNCE_ESCALATED"),
    ],
)
async def test_repeated_soft_bounce_escalates_at_policy_threshold(
    streak: int, expected_state: str, expected_reason: str
) -> None:
    # Test profile soft_bounce_escalation_count is 3.
    conn = _soft_bounce_conn(streak)
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    result = await store.apply_delivery_event(
        delivery_event(event_type="soft_bounce"),
        policy=PolicyProfile.load("test"),
        address_ref="addr-email-1",
    )
    assert result["projection_state"] == "applied"
    streak_sql = next(
        sql for kind, sql, _ in conn.executed if "soft_bounce_count" in sql
    )
    assert "event_type='soft_bounce'" in streak_sql
    assert "event_type='delivered'" in streak_sql
    args = _health_upsert_args(conn)
    assert args[4] == expected_state
    assert args[5] == "soft_bounce"
    assert args[7] == expected_reason
    # Repeated soft bounces advance authoritative timing to the new event.
    assert args[8] == NOW


@pytest.mark.asyncio
async def test_soft_bounce_escalation_unconfigured_policy_is_partial() -> None:
    conn = _soft_bounce_conn(99)
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    result = await store.apply_delivery_event(
        delivery_event(event_type="soft_bounce"),
        policy=PolicyProfile.load("production"),
        address_ref="addr-email-1",
    )
    assert result["projection_state"] == "partial"
    assert result["projection_note"] == "soft_bounce_escalation_not_configured"
    assert not any("soft_bounce_count" in sql for _, sql, _ in conn.executed)
    assert _health_upsert_args(conn)[4] == "soft_bounce"


@pytest.mark.asyncio
async def test_delivery_event_requires_frozen_schema_version() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    event = delivery_event()
    event.pop("schema_version")
    with pytest.raises(CampaignRecyclingConflict, match="invalid normalized delivery event"):
        await store.apply_delivery_event(
            event,
            policy=PolicyProfile.load("test"),
            address_ref="addr-email-1",
        )


@pytest.mark.asyncio
async def test_delivery_event_rejects_unknown_source() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="invalid normalized delivery event"):
        await store.apply_delivery_event(
            delivery_event(source="unknown-provider"),
            policy=PolicyProfile.load("test"),
            address_ref="addr-email-1",
        )


@pytest.mark.asyncio
async def test_delivery_event_health_effect_requires_address_ref() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="address_ref"):
        await store.apply_delivery_event(
            delivery_event(event_type="delivered"),
            policy=PolicyProfile.load("test"),
            address_ref=None,
        )


@pytest.mark.asyncio
async def test_delivery_event_source_channel_pair_fails_closed() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="invalid normalized delivery event"):
        await store.apply_delivery_event(
            delivery_event(channel="sms"),
            policy=PolicyProfile.load("test"),
            address_ref="addr-sms-1",
        )


@pytest.mark.asyncio
async def test_delivery_event_exact_replay_returns_duplicate() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [
        None,
        {
            "id": 7,
            "source": "klyrow",
            "event_id": "evt-mcr-00000001",
            "payload_hash": "e" * 64,
            "origin_inbox": "klyrow_delivery_event_inbox",
            "origin_event_id": "raw-1",
            "projection_state": "applied",
        },
    ]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    result = await store.apply_delivery_event(
        delivery_event(), policy=PolicyProfile.load("test")
    )
    assert result == {
        "event_id": "evt-mcr-00000001",
        "duplicate": True,
        "projection_state": "applied",
        "projection_note": None,
    }


@pytest.mark.asyncio
async def test_delivery_event_digest_collision_is_rejected() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [
        None,
        {
            "id": 7,
            "source": "klyrow",
            "event_id": "evt-mcr-00000001",
            "payload_hash": "f" * 64,
            "origin_inbox": "klyrow_delivery_event_inbox",
            "origin_event_id": "raw-1",
            "projection_state": "applied",
        },
    ]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    with pytest.raises(CampaignRecyclingConflict, match="different evidence"):
        await store.apply_delivery_event(
            delivery_event(), policy=PolicyProfile.load("test")
        )


@pytest.mark.asyncio
async def test_delivery_event_without_exposure_is_durable_partial() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [{"id": 9, "projection_state": "pending"}, None]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    result = await store.apply_delivery_event(
        delivery_event(), policy=PolicyProfile.load("test")
    )
    assert result["duplicate"] is False
    assert result["projection_state"] == "partial"
    assert result["projection_note"] == "exposure_not_found"
    assert any(
        "UPDATE mcr_delivery_events" in item[1]
        for item in conn.executed
        if item[0] == "execute"
    )


@pytest.mark.asyncio
async def test_illegal_lifecycle_transition_fails_before_db() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict):
        await store.transition_lifecycle(
            tenant_id="t",
            lead_id="l",
            from_state="NEW",
            to_state="ACTIVE_CYCLE",
            reason_code="CYCLE_STARTED",
            source="middleware_policy",
            correlation_id="corr",
            evidence_hash="a" * 64,
            occurred_at=NOW,
        )


@pytest.mark.asyncio
async def test_generic_command_authorization_cannot_bypass_mcr_execution_boundary() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [
        {"exposure_id": uuid4()},
        {"state": "ELIGIBLE", "version": 3},
        {"state": "ELIGIBLE", "version": 3},
    ]
    pool = FakePool(conn)
    command_store = PostgresCommandStore(pool, owns_pool=False)
    command_store.submit_on_connection = AsyncMock(return_value=object())
    policies = CommandPolicyRegistry(
        (
            CommandPolicy(
                prefix="mcr.test.",
                target="mcr-test",
                capability="MCR_TEST",
                readback_required=True,
            ),
        ),
        {"MCR_TEST": True},
    )
    service = CommandService(store=command_store, policies=policies)
    command_id = uuid4()
    key = "mcr1:" + "1" * 64
    command = CommandEnvelope(
        command_id=command_id,
        command_type="mcr.test.send.v1",
        command_version="1.0",
        target="mcr-test",
        tenant_id="TEST_SYN_TENANT",
        requested_by="svc-mcr",
        correlation_id="corr-mcr-1",
        idempotency_key=key,
        capability="MCR_TEST",
        payload={"test": True},
    )
    store = PostgresCampaignRecyclingStore(pool)
    with pytest.raises(CampaignRecyclingConflict, match="PRODUCTION_NOT_AUTHORIZED"):
        await store.reserve_exposure_and_command(
            tenant_id="TEST_SYN_TENANT",
            lead_id="100-L-00000001",
            campaign_id="klyrow:cmp-a",
            campaign_version=1,
            channel="email",
            touch_index=1,
            exposure_id=uuid4(),
            decision_id=uuid4(),
            policy_version="mcr-policy-1.0.0",
            sender_identity_id=UUID(SENDER),
            idempotency_key=key,
            command=command,
            command_service=service,
            authenticated_subject="svc-mcr",
            authenticated_client_id="mcr-test",
            reserved_at=NOW,
        )
    command_store.submit_on_connection.assert_not_awaited()
    assert conn.executed == []





def _synthetic_command(command_id: UUID, key: str) -> CommandEnvelope:
    return CommandEnvelope(
        command_id=command_id,
        command_type="test.syn.mcr.reserve.v1",
        command_version="1.0",
        target="test-syn",
        tenant_id="TEST_SYN_TENANT",
        requested_by="svc-mcr",
        correlation_id="corr-mcr-reserve",
        idempotency_key=key,
        capability="TEST_SYN_EXECUTE",
        payload={"synthetic": True},
    )


def _synthetic_command_service(pool: FakePool) -> tuple[CommandService, PostgresCommandStore]:
    command_store = PostgresCommandStore(pool, owns_pool=False)
    command_store.submit_on_connection = AsyncMock(return_value=object())
    policies = CommandPolicyRegistry(
        (
            CommandPolicy(
                prefix="test.syn.",
                target="test-syn",
                capability="TEST_SYN_EXECUTE",
                readback_required=True,
            ),
        ),
        {"TEST_SYN_EXECUTE": True},
    )
    return CommandService(store=command_store, policies=policies), command_store


@pytest.mark.asyncio
async def test_synthetic_reservation_and_command_are_atomic_intent() -> None:
    conn = _CountingConn()
    conn.fetchrow_results = [None, None]
    pool = FakePool(conn)
    service, command_store = _synthetic_command_service(pool)
    command_id = uuid4()
    exposure_id = uuid4()
    decision_id = uuid4()
    key = "mcr1:" + "2" * 64
    reserved, operation = await PostgresCampaignRecyclingStore(pool).reserve_exposure_and_command(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        campaign_id="klyrow:test-syn-mcr",
        campaign_version=1,
        channel="email",
        touch_index=1,
        exposure_id=exposure_id,
        decision_id=decision_id,
        policy_version="mcr-policy-1.0.0",
        sender_identity_id=UUID(SENDER),
        idempotency_key=key,
        command=_synthetic_command(command_id, key),
        command_service=service,
        authenticated_subject="svc-mcr",
        authenticated_client_id="mcr-test",
        reserved_at=NOW,
        synthetic_execution_authorized=True,
    )
    assert reserved is True
    assert operation is command_store.submit_on_connection.return_value
    assert conn.transactions == 1
    statements = _statements(conn)
    assert any("pg_advisory_xact_lock" in sql for sql in statements)
    insert = next(
        args for kind, sql, args in conn.executed
        if kind == "execute" and "INSERT INTO mcr_exposures" in sql
    )
    assert insert[0] == exposure_id
    assert insert[1:8] == (
        "TEST_SYN_TENANT", "100-L-00000001", "klyrow:test-syn-mcr",
        1, "email", 1, key,
    )
    command_store.submit_on_connection.assert_awaited_once()
    args, kwargs = command_store.submit_on_connection.await_args
    assert args[0] is conn
    assert kwargs["authenticated_client_id"] == "mcr-test"
    assert kwargs["decision_evidence"]["exposure_id"] == str(exposure_id)
    assert kwargs["decision_evidence"]["decision_id"] == str(decision_id)


@pytest.mark.asyncio
async def test_synthetic_reservation_identical_replay_does_not_emit_second_command() -> None:
    command_id = uuid4()
    decision_id = uuid4()
    key = "mcr1:" + "3" * 64
    conn = FakeConn()
    conn.fetchrow_results = [{
        "exposure_id": uuid4(),
        "idempotency_key": key,
        "command_id": command_id,
        "decision_id": decision_id,
        "policy_version": "mcr-policy-1.0.0",
        "sender_identity_id": UUID(SENDER),
        "status": "reserved",
    }]
    pool = FakePool(conn)
    service, command_store = _synthetic_command_service(pool)
    reserved, operation = await PostgresCampaignRecyclingStore(pool).reserve_exposure_and_command(
        tenant_id="TEST_SYN_TENANT",
        lead_id="100-L-00000001",
        campaign_id="klyrow:test-syn-mcr",
        campaign_version=1,
        channel="email",
        touch_index=1,
        exposure_id=uuid4(),
        decision_id=decision_id,
        policy_version="mcr-policy-1.0.0",
        sender_identity_id=UUID(SENDER),
        idempotency_key=key,
        command=_synthetic_command(command_id, key),
        command_service=service,
        authenticated_subject="svc-mcr",
        authenticated_client_id="mcr-test",
        reserved_at=NOW,
        synthetic_execution_authorized=True,
    )
    assert reserved is False and operation is None
    command_store.submit_on_connection.assert_not_awaited()
    assert not any("INSERT INTO mcr_exposures" in sql for sql in _statements(conn))


@pytest.mark.asyncio
async def test_synthetic_reservation_conflicting_replay_fails_before_command() -> None:
    key = "mcr1:" + "4" * 64
    conn = FakeConn()
    conn.fetchrow_results = [{
        "exposure_id": uuid4(),
        "idempotency_key": key,
        "command_id": uuid4(),
        "decision_id": uuid4(),
        "policy_version": "mcr-policy-1.0.0",
        "sender_identity_id": UUID(SENDER),
        "status": "reserved",
    }]
    pool = FakePool(conn)
    service, command_store = _synthetic_command_service(pool)
    with pytest.raises(CampaignRecyclingIdempotencyConflict):
        await PostgresCampaignRecyclingStore(pool).reserve_exposure_and_command(
            tenant_id="TEST_SYN_TENANT",
            lead_id="100-L-00000001",
            campaign_id="klyrow:test-syn-mcr",
            campaign_version=1,
            channel="email",
            touch_index=1,
            exposure_id=uuid4(),
            decision_id=uuid4(),
            policy_version="mcr-policy-1.0.0",
            sender_identity_id=UUID(SENDER),
            idempotency_key=key,
            command=_synthetic_command(uuid4(), key),
            command_service=service,
            authenticated_subject="svc-mcr",
            authenticated_client_id="mcr-test",
            reserved_at=NOW,
            synthetic_execution_authorized=True,
        )
    command_store.submit_on_connection.assert_not_awaited()


@pytest.mark.asyncio
async def test_synthetic_authorization_flag_cannot_enable_non_synthetic_tenant() -> None:
    conn = FakeConn()
    pool = FakePool(conn)
    service, command_store = _synthetic_command_service(pool)
    key = "mcr1:" + "5" * 64
    command = _synthetic_command(uuid4(), key)
    command = CommandEnvelope(
        command_id=command.command_id,
        command_type=command.command_type,
        command_version=command.command_version,
        target=command.target,
        tenant_id="PROD_TENANT",
        requested_by=command.requested_by,
        correlation_id=command.correlation_id,
        idempotency_key=command.idempotency_key,
        capability=command.capability,
        payload=command.payload,
    )
    with pytest.raises(CampaignRecyclingConflict, match="PRODUCTION_NOT_AUTHORIZED"):
        await PostgresCampaignRecyclingStore(pool).reserve_exposure_and_command(
            tenant_id="PROD_TENANT",
            lead_id="100-L-00000001",
            campaign_id="klyrow:test-syn-mcr",
            campaign_version=1,
            channel="email",
            touch_index=1,
            exposure_id=uuid4(),
            decision_id=uuid4(),
            policy_version="mcr-policy-1.0.0",
            sender_identity_id=UUID(SENDER),
            idempotency_key=key,
            command=command,
            command_service=service,
            authenticated_subject="svc-mcr",
            authenticated_client_id="mcr-test",
            reserved_at=NOW,
            synthetic_execution_authorized=True,
        )
    command_store.submit_on_connection.assert_not_awaited()
    assert conn.executed == []




@pytest.mark.asyncio
async def test_reconciliation_report_is_tenant_bound_read_only_and_bounded() -> None:
    conn = FakeConn()
    conn.fetch_results = [
        [{
            "exposure_id": uuid4(), "lead_id": "100-L-00000001",
            "campaign_id": "klyrow:test-syn-mcr", "campaign_version": 1,
            "channel": "email", "touch_index": 1,
            "idempotency_key": "mcr1:" + "6" * 64,
            "command_id": uuid4(), "correlation_id": "corr-gap",
            "status": "reserved", "reserved_at": NOW,
        }],
        [],
        [{
            "id": 7, "source": "klyrow", "event_id": "evt-gap",
            "event_type": "delivered", "lead_id": "100-L-00000001",
            "channel": "email", "campaign_id": "klyrow:test-syn-mcr",
            "campaign_version": 1,
            "exposure_idempotency_key": "mcr1:" + "7" * 64,
            "correlation_id": "corr-event", "payload_hash": "a" * 64,
            "projection_state": "partial", "projection_note": "exposure_missing",
            "received_at": NOW,
        }],
        [],
    ]
    report = await PostgresCampaignRecyclingStore(FakePool(conn)).reconciliation_report(
        tenant_id="TEST_SYN_TENANT", limit=25
    )
    assert report["tenant_id"] == "TEST_SYN_TENANT"
    assert report["healthy"] is False
    assert report["counts"] == {
        "missing_commands": 1,
        "command_drift": 0,
        "delivery_backlog": 1,
        "orphan_delivery_events": 0,
    }
    assert len(conn.executed) == 4
    assert all(kind == "fetch" for kind, _, _ in conn.executed)
    assert all(args == ("TEST_SYN_TENANT", 25) for _, _, args in conn.executed)
    assert not any(
        any(token in " ".join(sql.split()).upper() for token in (" INSERT ", " UPDATE ", " DELETE "))
        for _, sql, _ in conn.executed
    )


@pytest.mark.asyncio
async def test_reconciliation_report_healthy_when_no_drift() -> None:
    conn = FakeConn()
    conn.fetch_results = [[], [], [], []]
    report = await PostgresCampaignRecyclingStore(FakePool(conn)).reconciliation_report(
        tenant_id="TEST_SYN_TENANT"
    )
    assert report["healthy"] is True
    assert all(value == 0 for value in report["counts"].values())


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, 501])
async def test_reconciliation_report_rejects_unbounded_limits(limit: int) -> None:
    conn = FakeConn()
    with pytest.raises(CampaignRecyclingConflict, match="limit"):
        await PostgresCampaignRecyclingStore(FakePool(conn)).reconciliation_report(
            tenant_id="TEST_SYN_TENANT", limit=limit
        )
    assert conn.executed == []


def test_migration_is_single_successor_and_does_not_enable_effects() -> None:
    source = (
        __import__("pathlib").Path("migrations/versions/0068_campaign_recycling_core.py")
        .read_text(encoding="utf-8")
    )
    assert 'revision = "0068_campaign_recycling_core"' in source
    assert 'down_revision = "0067_service_catalog_monitoring_state"' in source
    assert "transition_id uuid NOT NULL UNIQUE" in source
    assert "correlation_id text NOT NULL" in source
    assert "ledger_version bigint NOT NULL DEFAULT 1" in source
    for table in (
        "mcr_lead_lifecycle_current",
        "mcr_lead_lifecycle_events",
        "mcr_channel_health",
        "mcr_suppressions",
        "mcr_exposures",
    ):
        assert f"CREATE TABLE {table}" in source
    assert "WHATSAPP_DELIVERY" not in source
    assert "EMAIL_DELIVERY" not in source
    assert "SMS_DELIVERY" not in source
    assert "PRODUCTION_DIALING" not in source



def test_delivery_event_migration_is_successor_and_fail_closed() -> None:
    source = (
        __import__("pathlib")
        .Path("migrations/versions/0069_campaign_recycling_delivery_events.py")
        .read_text(encoding="utf-8")
    )
    assert 'revision = "0069_campaign_recycling_delivery_events"' in source
    assert 'down_revision = "0068_campaign_recycling_core"' in source
    assert "CREATE TABLE mcr_delivery_events" in source
    assert "UNIQUE (tenant_id, source, event_id)" in source
    assert "uq_mcr_delivery_event_origin" in source
    assert "projection_state" in source
    assert "WHATSAPP_DELIVERY" not in source
    assert "EMAIL_DELIVERY" not in source
    assert "SMS_DELIVERY" not in source
    assert "PRODUCTION_DIALING" not in source


# --- suppression recording (idempotent, tenant-bound, atomic) -------------------


def _suppression_request(**overrides):
    value = {
        "schema_version": "1.0",
        "lead_id": "100-L-00000001",
        "scope": "global",
        "channel": None,
        "campaign_id": None,
        "reason": "do_not_contact_request",
        "source": "operator",
        "occurred_at": NOW.isoformat(),
        "evidence": {"kind": "operator_change", "evidence_hash": "b" * 64},
        "requested_by": "operator:synthetic",
    }
    value.update(overrides)
    return value


class _CountingConn(FakeConn):
    def __init__(self):
        super().__init__()
        self.transactions = 0

    def transaction(self):
        self.transactions += 1
        return super().transaction()


async def _record(conn, request=None, tenant="TEST_SYN_TENANT", key="suppress-key-1"):
    return await PostgresCampaignRecyclingStore(FakePool(conn)).record_suppression_request(
        tenant_id=tenant,
        idempotency_key=key,
        request=request or _suppression_request(),
        correlation_id="corr-suppress-1",
    )


def _statements(conn):
    return [" ".join(sql.split()) for _, sql, _ in conn.executed]


@pytest.mark.asyncio
async def test_global_suppression_and_lifecycle_commit_in_one_transaction() -> None:
    conn = _CountingConn()
    conn.fetchrow_results = [
        None,
        {"state": "ELIGIBLE"},
        {"created_at": NOW},
        {"state": "ELIGIBLE", "version": 3},
    ]
    result = await _record(conn)
    assert conn.transactions == 1
    assert result["duplicate"] is False and result["scope"] == "global"
    assert result["effective_at"] == NOW.isoformat()
    statements = _statements(conn)
    order = [
        next(i for i, sql in enumerate(statements) if needle in sql)
        for needle in (
            "pg_advisory_xact_lock",
            "FROM idempotency_record",
            "FROM mcr_lead_lifecycle_current WHERE tenant_id=$1 AND lead_id=$2 FOR UPDATE",
            "INSERT INTO mcr_suppressions",
            "UPDATE mcr_lead_lifecycle_current",
            "INSERT INTO mcr_lead_lifecycle_events",
            "INSERT INTO idempotency_record",
        )
    ]
    assert order == sorted(order)
    event = next(args for _, sql, args in conn.executed
                 if "INSERT INTO mcr_lead_lifecycle_events" in sql)
    assert event[4:8] == ("ELIGIBLE", "SUPPRESSED", "GLOBAL_SUPPRESSION_APPLIED", "operator")
    assert event[-1] == f"suppression:{result['suppression_id']}"
    evidence = next(args for _, sql, args in conn.executed
                    if "INSERT INTO idempotency_record" in sql)
    assert evidence[1] == "mcr:suppression_record:v1"
    assert json.loads(evidence[4]) == result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": "channel", "channel": "email", "reason": "unsubscribe"},
        {"scope": "campaign", "campaign_id": "klyrow:cmp-a"},
        {"scope": "campaign_channel", "channel": "sms", "campaign_id": "klyrow:cmp-a"},
    ],
)
async def test_narrow_suppression_never_changes_lifecycle(overrides) -> None:
    conn = FakeConn()
    conn.fetchrow_results = [None, {"state": "ACTIVE_CYCLE"}, {"created_at": NOW}]
    result = await _record(conn, _suppression_request(**overrides))
    assert result["scope"] == overrides["scope"]
    statements = _statements(conn)
    assert any("INSERT INTO mcr_suppressions" in sql for sql in statements)
    assert not any("UPDATE mcr_lead_lifecycle_current" in sql for sql in statements)
    assert not any("INSERT INTO mcr_lead_lifecycle_events" in sql for sql in statements)
    inserted = next(args for _, sql, args in conn.executed if "INSERT INTO mcr_suppressions" in sql)
    assert inserted[4:6] == (overrides.get("channel"), overrides.get("campaign_id"))


@pytest.mark.asyncio
async def test_global_suppression_of_suppressed_lead_is_additive_and_absorbing() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [None, {"state": "SUPPRESSED"}, {"created_at": NOW}]
    await _record(conn)
    statements = _statements(conn)
    assert any("INSERT INTO mcr_suppressions" in sql for sql in statements)
    assert not any("mcr_lead_lifecycle_events" in sql for sql in statements)


@pytest.mark.asyncio
async def test_identical_suppression_replay_returns_the_original_ack() -> None:
    request = _suppression_request()
    original = {"suppression_id": str(uuid4()), "duplicate": False, "scope": "global",
                "effective_at": NOW.isoformat()}
    conn = FakeConn()
    conn.fetchrow_results = [
        {"request_hash": canonical_digest(request), "response": json.dumps(original)}
    ]
    assert await _record(conn, request) == {**original, "duplicate": True}
    assert not any("INSERT" in sql or "UPDATE" in sql for sql in _statements(conn))


@pytest.mark.asyncio
async def test_idempotency_key_reuse_with_different_request_is_rejected() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [{"request_hash": "0" * 64, "response": "{}"}]
    with pytest.raises(CampaignRecyclingIdempotencyConflict):
        await _record(conn)
    assert not any("INSERT" in sql or "UPDATE" in sql for sql in _statements(conn))


@pytest.mark.asyncio
async def test_suppression_for_unknown_lead_is_not_found_and_writes_nothing() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [None, None]
    with pytest.raises(CampaignRecyclingNotFound):
        await _record(conn)
    assert not any("INSERT" in sql for sql in _statements(conn))


@pytest.mark.asyncio
async def test_suppression_identity_without_evidence_fails_closed() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [None, {"state": "ELIGIBLE"}, None]
    with pytest.raises(CampaignRecyclingIdempotencyConflict):
        await _record(conn)
    assert not any("idempotency_record (" in sql or "lifecycle_events" in sql
                   for sql in _statements(conn))


@pytest.mark.asyncio
async def test_idempotency_evidence_is_bound_to_the_exact_tenant() -> None:
    keys = []
    for tenant in ("TENANT_A", "TENANT_B"):
        conn = FakeConn()
        conn.fetchrow_results = [None, {"state": "ELIGIBLE"}, {"created_at": NOW},
                                 {"state": "ELIGIBLE", "version": 1}]
        result = await _record(conn, tenant=tenant)
        lookup = next(args for _, sql, args in conn.executed if "FROM idempotency_record" in sql)
        keys.append((lookup[1], result["suppression_id"]))
        for _, sql, args in conn.executed:
            if "mcr_" not in sql or not args:
                continue
            tenant_index = 1 if "INSERT INTO mcr_lead_lifecycle_events" in sql else 0
            assert args[tenant_index] == tenant
    assert keys[0][0] != keys[1][0] and keys[0][1] != keys[1][1]


@pytest.mark.asyncio
async def test_global_suppression_requires_a_lifecycle_authority_source() -> None:
    conn = FakeConn()
    with pytest.raises(CampaignRecyclingConflict, match="lifecycle authority"):
        await _record(conn, _suppression_request(source="klyrow_delivery_event"))
    assert conn.executed == []


@pytest.mark.asyncio
async def test_lifecycle_conflicts_are_typed() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [None, {"state": "ELIGIBLE"}, {"created_at": NOW},
                             {"state": "COOLING", "version": 4}]
    with pytest.raises(CampaignRecyclingLifecycleConflict):
        await _record(conn)
    assert issubclass(CampaignRecyclingLifecycleConflict, CampaignRecyclingConflict)


@pytest.mark.asyncio
async def test_identical_replay_of_partial_projection_is_a_duplicate() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [
        None,
        {
            "id": 7,
            "source": "klyrow",
            "event_id": "evt-mcr-00000001",
            "payload_hash": "e" * 64,
            "origin_inbox": "klyrow_delivery_event_inbox",
            "origin_event_id": "raw-1",
            "projection_state": "partial",
        },
        None,
    ]
    result = await PostgresCampaignRecyclingStore(FakePool(conn)).apply_delivery_event(
        delivery_event(), policy=PolicyProfile.load("test")
    )
    assert result["duplicate"] is True
    assert result["projection_state"] == "partial"


def test_delivery_payload_hash_excludes_received_at_and_itself() -> None:
    event = delivery_event()
    digest = delivery_event_payload_hash(event)
    assert digest == delivery_event_payload_hash({**event, "received_at": "x", "payload_hash": "y"})
    assert digest != delivery_event_payload_hash({**event, "event_type": "click"})


def test_policy_loads_candidate_disclosure_limit() -> None:
    assert PolicyProfile.load("test").max_candidates_disclosed == 200


def test_candidate_set_above_disclosure_limit_fails_closed() -> None:
    candidates = [
        candidate(campaign_id=f"klyrow:cmp-{index:03d}", priority=index)
        for index in range(201)
    ]
    with pytest.raises(
        CampaignRecyclingPolicyError,
        match="candidate set exceeds decision.max_candidates_disclosed",
    ):
        engine().evaluate(snapshot(), candidates, now=NOW)
