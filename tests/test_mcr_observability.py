from datetime import UTC, datetime, timedelta
import json
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
from prometheus_client import REGISTRY, generate_latest

from app import mcr_observability as obs
from app.core.campaign_recycling import (
    CampaignRecyclingConflict,
    CampaignRecyclingEngine,
    Candidate,
    ChannelHealth,
    LeadSnapshot,
    PolicyProfile,
    PostgresCampaignRecyclingStore,
    Suppression,
)

NOW = datetime(2026, 9, 24, tzinfo=UTC)
SECRET = "person@example.test Bearer super-secret"


def test_decision_reasons_are_bounded_and_private(caplog):
    telemetry = obs.MCRObservability()
    engine = CampaignRecyclingEngine(PolicyProfile.load("test"), telemetry=telemetry)
    lead = LeadSnapshot(
        SECRET,
        SECRET,
        "ELIGIBLE",
        1,
        {"email": ChannelHealth("hard_bounce", NOW)},
        suppressions=(Suppression("global", SECRET, NOW, SECRET),),
    )
    item = Candidate("klyrow:secret", 1, "email", 1, 1, SECRET)
    with caplog.at_level(logging.INFO, logger="codestra.mcr"):
        result = engine.evaluate(lead, [item], now=NOW)
    assert not result.eligible
    output = generate_latest(telemetry.registry).decode()
    assert 'reason="SUPPRESSED_GLOBAL"' in output
    assert 'reason="CHANNEL_HEALTH_BLOCKED"' in output
    assert 'family="suppression"' in output
    assert 'family="health"' in output
    assert SECRET not in output + caplog.text
    assert "tenant_id" not in output
    assert "codestra_mcr_" not in generate_latest(REGISTRY).decode()
    span = json.loads(caplog.records[-1].message)
    assert len(span["trace_id"]) == 32 and len(span["span_id"]) == 16
    assert span["operation"] == "decision"


def test_unknown_labels_and_invalid_lag_fail_closed(caplog):
    telemetry = obs.MCRObservability()
    with caplog.at_level(logging.INFO, logger="codestra.mcr"):
        telemetry.decision(mode=SECRET, channel=SECRET, reasons=(SECRET,))
        telemetry.delivery(channel=SECRET, outcome=SECRET, lag_seconds=float("nan"))
    output = generate_latest(telemetry.registry).decode()
    assert SECRET not in output + caplog.text
    assert 'reason="UNKNOWN"' in output
    assert 'outcome="unknown"' in output
    assert "NaN" not in output


@pytest.mark.asyncio
async def test_invalid_event_never_echoes_input_or_touches_database(caplog):
    pool = MagicMock()
    telemetry = obs.MCRObservability()
    store = PostgresCampaignRecyclingStore(pool, telemetry=telemetry)
    with caplog.at_level(logging.INFO, logger="codestra.mcr"):
        with pytest.raises(CampaignRecyclingConflict) as raised:
            await store.apply_delivery_event(
                {"secret": SECRET}, policy=PolicyProfile.load("test")
            )
    assert SECRET not in str(raised.value) + caplog.text
    pool.acquire.assert_not_called()
    assert 'outcome="rejected"' in generate_latest(telemetry.registry).decode()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "duplicate,replayed,state,outcome",
    [
        (False, False, "applied", "applied"),
        (True, False, "applied", "duplicate"),
        (False, True, "applied", "replayed"),
        (False, True, "partial", "partial"),
    ],
)
async def test_delivery_observed_only_after_projection_returns(
    duplicate, replayed, state, outcome
):
    telemetry = obs.MCRObservability()
    store = PostgresCampaignRecyclingStore(MagicMock(), telemetry=telemetry)
    store._apply_delivery_event = AsyncMock(
        return_value={
            "duplicate": duplicate,
            "replayed": replayed,
            "projection_state": state,
        }
    )
    await store.apply_delivery_event(
        {"channel": "email", "received_at": NOW.isoformat()},
        policy=PolicyProfile.load("test"),
    )
    assert f'outcome="{outcome}"' in generate_latest(telemetry.registry).decode()


def test_readback_is_fail_closed_on_missing_stale_or_future_evidence():
    for sampled_at in (None, NOW - timedelta(seconds=61), NOW + timedelta(seconds=1)):
        result = obs.delivery_readback(
            pending=0,
            partial=0,
            oldest_seconds=0,
            dead_letter=0,
            sampled_at=sampled_at,
            now=NOW,
        )
        assert result["ready"] is False
    result = obs.delivery_readback(
        pending=0,
        partial=0,
        oldest_seconds=0,
        dead_letter=None,
        sampled_at=NOW,
        now=NOW,
    )
    assert result["ready"] is False
    assert result["dead_letter"] is None
    assert "DEAD_LETTER_EVIDENCE_UNAVAILABLE" in result["reasons"]
    assert (
        obs.delivery_readback(
            pending=0,
            partial=0,
            oldest_seconds=0,
            dead_letter=0,
            sampled_at=NOW,
            now=NOW,
        )["ready"]
        is True
    )


@pytest.mark.parametrize(
    "values",
    [
        dict(pending=-1),
        dict(partial=True),
        dict(oldest_seconds=float("inf")),
        dict(dead_letter=-1),
    ],
)
def test_invalid_readback_evidence_is_rejected(values):
    args = dict(
        pending=0, partial=0, oldest_seconds=0, dead_letter=0, sampled_at=NOW, now=NOW
    )
    args.update(values)
    with pytest.raises(ValueError, match="invalid MCR readback evidence"):
        obs.delivery_readback(**args)


@pytest.mark.asyncio
async def test_cross_tenant_readback_is_denied_before_query():
    pool = MagicMock()
    store = PostgresCampaignRecyclingStore(pool)
    with pytest.raises(CampaignRecyclingConflict, match="scope denied"):
        await store.delivery_readback(
            tenant_id="tenant-a", authorized_tenant_id="tenant-b"
        )
    pool.acquire.assert_not_called()


@pytest.mark.asyncio
async def test_readback_uses_tenant_query_and_never_claims_missing_dlq_is_empty():
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "pending": 2,
        "partial": 1,
        "oldest_seconds": 400,
        "sampled_at": datetime.now(UTC),
    }
    pool = MagicMock()
    pool.acquire.return_value.__aenter__.return_value = conn
    result = await PostgresCampaignRecyclingStore(pool).delivery_readback(
        tenant_id="tenant-a", authorized_tenant_id="tenant-a"
    )
    sql, tenant = conn.fetchrow.call_args.args
    assert "WHERE tenant_id=$1" in sql
    assert tenant == "tenant-a"
    assert result["ready"] is False
    assert result["dead_letter"] is None
    assert "PARTIAL_PROJECTION" in result["reasons"]
    assert "PROJECTION_LAG_EXCEEDED" in result["reasons"]


@pytest.mark.asyncio
async def test_failed_projection_does_not_emit_success_or_exception_text(caplog):
    telemetry = obs.MCRObservability()
    store = PostgresCampaignRecyclingStore(MagicMock(), telemetry=telemetry)
    store._apply_delivery_event = AsyncMock(side_effect=RuntimeError(SECRET))
    with caplog.at_level(logging.INFO, logger="codestra.mcr"):
        with pytest.raises(RuntimeError):
            await store.apply_delivery_event(
                {"channel": "email"}, policy=PolicyProfile.load("test")
            )
    output = generate_latest(telemetry.registry).decode()
    assert 'outcome="failed"' in output
    assert 'outcome="applied"' not in output
    assert SECRET not in caplog.text + output


def test_cap_counters_and_candidate_channel_survive_selected_other_candidate():
    telemetry = obs.MCRObservability()
    engine = CampaignRecyclingEngine(PolicyProfile.load("test"), telemetry=telemetry)
    lead = LeadSnapshot(
        SECRET,
        SECRET,
        "ELIGIBLE",
        1,
        {
            "email": ChannelHealth("valid", NOW),
            "sms": ChannelHealth("hard_bounce", NOW),
        },
    )
    decision = engine.evaluate(
        lead,
        [
            Candidate("klyrow:a", 1, "email", 1, 1, "sender"),
            Candidate("klyrow:b", 1, "sms", 2, 1, "sender"),
        ],
        now=NOW,
    )
    assert decision.eligible
    telemetry.decision(mode="read", channel="email", reasons=("CHANNEL_CAP_REACHED",))
    output = generate_latest(telemetry.registry).decode()
    assert 'channel="sms",family="health",reason="CHANNEL_HEALTH_BLOCKED"' in output
    assert 'family="cap",reason="CHANNEL_CAP_REACHED"' in output


@pytest.mark.asyncio
async def test_private_scrape_has_mcr_metrics_and_anonymous_scrape_is_denied(
    runtime, test_settings
):
    import httpx
    from app.main import create_app

    app = create_app(settings=test_settings, runtime=runtime)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            denied = await client.get("/metrics")
            assert denied.status_code in (401, 403)
            response = await client.get(
                "/metrics",
                headers={
                    "Authorization": "Bearer valid-monitoring-readonly-metrics.read"
                },
            )
    assert response.status_code == 200
    assert "codestra_mcr_dead_letter_evidence_available 0.0" in response.text


@pytest.mark.asyncio
async def test_transaction_commit_failure_never_records_applied():
    from tests.test_campaign_recycling_engine import FakeConn, FakePool, delivery_event

    class FailedCommit:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            raise RuntimeError("commit failed")

    conn = FakeConn()
    conn.fetchrow_results = [{"id": 9, "projection_state": "pending"}]
    conn.transaction = FailedCommit
    telemetry = obs.MCRObservability()
    store = PostgresCampaignRecyclingStore(FakePool(conn), telemetry=telemetry)
    with pytest.raises(RuntimeError, match="commit failed"):
        await store.apply_delivery_event(
            delivery_event(exposure_idempotency_key=None),
            policy=PolicyProfile.load("test"),
        )
    output = generate_latest(telemetry.registry).decode()
    assert 'outcome="failed"' in output
    assert 'outcome="applied"' not in output
    assert 'outcome="partial"' not in output


@pytest.mark.asyncio
async def test_partial_replay_records_replay_even_when_still_partial():
    from tests.test_campaign_recycling_engine import FakeConn, FakePool, delivery_event

    event = delivery_event()
    conn = FakeConn()
    conn.fetchrow_results = [
        None,
        {
            "id": 7,
            "source": "klyrow",
            "event_id": "evt-mcr-00000001",
            "payload_hash": event["payload_hash"],
            "origin_inbox": "klyrow_delivery_event_inbox",
            "origin_event_id": "raw-1",
            "projection_state": "partial",
        },
        None,
    ]
    telemetry = obs.MCRObservability()
    result = await PostgresCampaignRecyclingStore(
        FakePool(conn), telemetry=telemetry
    ).apply_delivery_event(event, policy=PolicyProfile.load("test"))
    assert result["projection_state"] == "partial"
    output = generate_latest(telemetry.registry).decode()
    assert 'codestra_mcr_replays_total{channel="email",outcome="partial"} 1.0' in output


def test_partial_and_duplicate_projections_do_not_improve_completion_slo():
    telemetry = obs.MCRObservability()
    for outcome in ("partial", "duplicate", "failed", "rejected"):
        telemetry.delivery(channel="email", outcome=outcome, lag_seconds=1)
    assert (
        telemetry.registry.get_sample_value(
            "codestra_mcr_projection_lag_seconds_count", {"channel": "email"}
        )
        is None
    )


def test_delivery_health_counts_completed_events_once_and_redacts_unknowns(caplog):
    telemetry = obs.MCRObservability()
    with caplog.at_level(logging.INFO, logger="codestra.mcr"):
        for outcome in ("partial", "duplicate", "failed", "applied", "replayed"):
            telemetry.delivery(
                channel="email", outcome=outcome, event_type="hard_bounce"
            )
        telemetry.delivery(channel=SECRET, outcome="applied", event_type=SECRET)
    assert (
        telemetry.registry.get_sample_value(
            "codestra_mcr_delivery_health_total",
            {"channel": "email", "event_type": "hard_bounce"},
        )
        == 2
    )
    assert SECRET not in generate_latest(telemetry.registry).decode() + caplog.text


def test_readback_signals_are_bounded_and_do_not_overwrite_tenant_gauges():
    telemetry = obs.MCRObservability()
    for outcome in ("blocked", "unavailable", SECRET):
        telemetry.readback(outcome=outcome)
    output = generate_latest(telemetry.registry).decode()
    assert 'outcome="blocked"} 1.0' in output
    assert 'outcome="unavailable"} 1.0' in output
    assert SECRET not in output


@pytest.mark.asyncio
async def test_readback_database_failure_is_observed_without_leaking_exception(caplog):
    conn = AsyncMock()
    conn.fetchrow.side_effect = RuntimeError(SECRET)
    pool = MagicMock()
    pool.acquire.return_value.__aenter__.return_value = conn
    telemetry = obs.MCRObservability()
    with caplog.at_level(logging.INFO, logger="codestra.mcr"):
        with pytest.raises(RuntimeError):
            await PostgresCampaignRecyclingStore(
                pool, telemetry=telemetry
            ).delivery_readback(tenant_id="tenant-a", authorized_tenant_id="tenant-a")
    assert (
        telemetry.registry.get_sample_value(
            "codestra_mcr_readback_total", {"outcome": "unavailable"}
        )
        == 1
    )
    assert SECRET not in caplog.text + generate_latest(telemetry.registry).decode()


def test_event_alert_counters_are_absent_before_first_event():
    telemetry = obs.MCRObservability()
    for metric, labels in [
        ("codestra_mcr_delivery_total", {"channel": "email", "outcome": "failed"}),
        ("codestra_mcr_replays_total", {"channel": "sms", "outcome": "partial"}),
        (
            "codestra_mcr_delivery_health_total",
            {"channel": "email", "event_type": "complaint"},
        ),
        ("codestra_mcr_readback_total", {"outcome": "unavailable"}),
    ]:
        assert telemetry.registry.get_sample_value(metric, labels) is None
