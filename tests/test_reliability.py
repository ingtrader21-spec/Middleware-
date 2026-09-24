from datetime import datetime, timedelta, timezone

import pytest

from app.core.reliability import (
    IdempotencyLedger,
    OutboxItem,
    Reconciler,
    RetryPolicy,
    authorize_transfer,
    enforce_dnc,
    redact,
    sanitize_for_storage,
)


NOW = datetime(2026, 7, 21, tzinfo=timezone.utc)


def test_transactional_outbox_retry_dead_letter_replay_and_restart_recovery():
    policy = RetryPolicy(max_attempts=3, base_seconds=5, max_seconds=20)
    item = OutboxItem("event-1", "test", {}, "corr-1")
    item.fail("token=never-log", policy, NOW)
    assert "never-log" not in (item.last_error or "")
    assert (item.status, item.attempts, item.next_attempt_at) == (
        "retry",
        1,
        NOW + timedelta(seconds=5),
    )
    item.fail("dependency unavailable", policy, NOW)
    item.fail("dependency unavailable", policy, NOW)
    assert item.status == "dead_letter"
    item.replay()
    assert (item.status, item.attempts, item.last_error) == ("pending", 0, None)
    item.status, item.next_attempt_at = "processing", NOW - timedelta(seconds=120)
    item.recover(NOW)
    assert item.status == "retry"


def test_idempotency_replay_conflict_and_correlation():
    ledger = IdempotencyLedger()
    assert ledger.register("lead", "raw-key", {"a": 1}, "event-1") == "created"
    assert ledger.register("lead", "raw-key", {"a": 1}, "event-1") == "replay"
    assert ledger.register("lead", "raw-key", {"a": 2}, "event-1") == "conflict"
    assert "raw-key" not in repr(ledger.entries)


def test_reconciliation_and_recursive_redaction():
    reconciler = Reconciler()
    assert reconciler.reconcile({"1", "2"}, {"2", "3"}, "cursor-9") == {
        "missing": {"1"},
        "unexpected": {"3"},
    }
    assert reconciler.checkpoint == "cursor-9"
    value = redact(
        {"nested": [{"Authorization": "Bearer x", "cookie_value": "x"}], "ok": 1}
    )
    assert "Bearer x" not in repr(value) and value["ok"] == 1


def test_durable_event_payload_is_recursively_redacted():
    marker = "TEST_SECRET_MARKER_DO_NOT_PERSIST"
    stored = sanitize_for_storage(
        {
            "password": marker,
            "nested": [{"Authorization": f"Bearer {marker}"}],
            "lead_id": 37,
        }
    )
    assert marker not in repr(stored)
    assert stored["password"] == "[REDACTED]"
    assert stored["nested"][0]["Authorization"] == "[REDACTED]"
    assert stored["lead_id"] == 37


def test_dnc_and_transfer_authorization_fail_closed():
    with pytest.raises(PermissionError):
        enforce_dnc({"do_not_call": True})
    assert authorize_transfer(
        dnc=True,
        authenticated=True,
        role="manager",
        campaign_id="TEST_SYN",
        live_enabled=True,
    ) == (False, "do-not-call")
    assert (
        authorize_transfer(
            dnc=False,
            authenticated=False,
            role="manager",
            campaign_id="TEST_SYN",
            live_enabled=True,
        )[0]
        is False
    )
    assert (
        authorize_transfer(
            dnc=False,
            authenticated=True,
            role="agent",
            campaign_id="TEST_SYN",
            live_enabled=True,
        )[0]
        is False
    )
    assert (
        authorize_transfer(
            dnc=False,
            authenticated=True,
            role="manager",
            campaign_id="LIVE",
            live_enabled=True,
        )[0]
        is False
    )
    assert authorize_transfer(
        dnc=False,
        authenticated=True,
        role="manager",
        campaign_id="TEST_SYN",
        live_enabled=False,
    ) == (False, "live-transfer-disabled")
