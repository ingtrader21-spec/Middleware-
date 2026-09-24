from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
    CampaignRecyclingEngine,
    Candidate,
    ChannelHealth,
    Exposure,
    LeadSnapshot,
    PolicyProfile,
    PostgresCampaignRecyclingStore,
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


def delivery_event(**overrides):
    value = {
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
async def test_channel_health_and_suppression_share_transaction() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [None]
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
    statements = [item[1] for item in conn.executed if item[0] == "execute"]
    assert any("INSERT INTO mcr_channel_health" in sql for sql in statements)
    assert any("INSERT INTO mcr_suppressions" in sql for sql in statements)


@pytest.mark.asyncio
async def test_delivery_event_health_effect_requires_address_ref() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="address_ref"):
        await store.apply_delivery_event(
            delivery_event(event_type="delivered"),
            address_ref=None,
        )


@pytest.mark.asyncio
async def test_delivery_event_source_channel_pair_fails_closed() -> None:
    store = PostgresCampaignRecyclingStore(FakePool(FakeConn()))
    with pytest.raises(CampaignRecyclingConflict, match="Klyrow"):
        await store.apply_delivery_event(
            delivery_event(channel="sms"),
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
    result = await store.apply_delivery_event(delivery_event())
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
        await store.apply_delivery_event(delivery_event())


@pytest.mark.asyncio
async def test_delivery_event_without_exposure_is_durable_partial() -> None:
    conn = FakeConn()
    conn.fetchrow_results = [{"id": 9, "projection_state": "pending"}, None]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    result = await store.apply_delivery_event(delivery_event())
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
async def test_exposure_and_command_share_one_transaction_boundary() -> None:
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
    created, operation = await store.reserve_exposure_and_command(
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
    assert created is True
    assert operation is not None
    command_store.submit_on_connection.assert_awaited_once()
    called_conn = command_store.submit_on_connection.await_args.args[0]
    assert called_conn is conn


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
