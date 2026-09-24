from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from app.core.appointments import (
    FakeTelephonyAdapter,
    IdempotencyLedger,
    local_time,
    may_access,
    reminder_events,
    transition,
)


def test_state_machine_guards_terminal_and_skip():
    assert transition("scheduled", "confirmed") == "confirmed"
    with pytest.raises(ValueError):
        transition("completed", "scheduled")
    with pytest.raises(ValueError):
        transition("cancelled", "in_progress")
    with pytest.raises(ValueError):
        transition("draft", "in_progress")


def test_explicit_reminder_timeline_and_keys():
    rows = reminder_events("A1", datetime(2026, 7, 25, 12, tzinfo=timezone.utc))
    assert len(rows) == 8 and len({x["idempotency_key"] for x in rows}) == 8
    assert rows[0]["scheduled_at"].minute == 45


def test_timezones_and_dst():
    value = datetime(2026, 3, 8, 7, tzinfo=timezone.utc)
    assert local_time(value, "America/New_York").hour == 3
    with pytest.raises(ValueError):
        local_time(datetime(2026, 1, 1), "UTC")


def test_unit_and_campaign_access():
    assert may_access("TL", {"C1"}, "TL", "C1")
    assert not may_access("TL", {"C1"}, "DEV", "C1")
    assert not may_access("TL", {"C1"}, "TL", "C2")


def test_active_call_protection_and_confirmation():
    adapter = FakeTelephonyAdapter()
    pending = adapter.pause("A", active_call=True)
    assert pending.state == "pause_pending" and not pending.confirmed
    paused = adapter.pause("A", active_call=False)
    assert paused.state == "APPT_PREP" and paused.confirmed
    assert not adapter.resume(False).confirmed
    assert adapter.resume(True).confirmed
    with pytest.raises(PermissionError):
        adapter.start_call()


def test_concurrent_idempotency_and_conflict():
    ledger = IdempotencyLedger()
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(
            pool.map(lambda _: ledger.claim("k", "same", {"id": 1}), range(10))
        )
    assert results == [{"id": 1}] * 10
    with pytest.raises(ValueError):
        ledger.claim("k", "changed", {"id": 2})


def test_load_thousand_appointments():
    base = datetime(2026, 7, 25, 12, tzinfo=timezone.utc)
    rows = [reminder_events(str(i), base) for i in range(1000)]
    assert sum(map(len, rows)) == 8000
