from __future__ import annotations

import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.models import EventEnvelope
from app.vicidial_odoo_projection import ProjectionConflict, ProjectionState, project_envelope


def call_event():
    now = datetime.now(timezone.utc)
    envelope = EventEnvelope(
        event_id="vici-evt-concurrent-123456",
        event_type="codestra.vicidial.call.lifecycle.created",
        event_version="1.0",
        occurred_at=now,
        received_at=now,
        source="vicidial-adapter",
        tenant_id="COD",
        correlation_id="vici-call-concurrent",
        causation_id="ami-concurrent",
        idempotency_key="vici-evt-concurrent-123456",
        payload={
            "schema_version": "1.0",
            "business_unit_id": "COD",
            "campaign_id": "TEST_SYN",
            "call_id": "vici-call-concurrent",
            "asterisk_uniqueid": "1710000000.99",
            "linkedid": "1710000000.99",
            "agent_id": "SYN6101",
            "extension": "6101",
            "keycloak_subject": "00000000-0000-0000-0000-000000006101",
            "sequence": 1,
            "direction": "inbound",
            "caller_number": "+18095550100",
        },
        metadata={"transport": "ami"},
    )
    return project_envelope(envelope, synthetic_only=True)


def test_concurrent_registration_is_atomic_and_private(tmp_path: Path) -> None:
    state = ProjectionState(tmp_path / "projection.sqlite3")
    event = call_event()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: state.register(event), range(24)))
    assert results == ["received"] * 24
    assert stat.S_IMODE(state.path.stat().st_mode) == 0o600


def test_delivered_state_cannot_be_downgraded(tmp_path: Path) -> None:
    state = ProjectionState(tmp_path / "projection.sqlite3")
    event = call_event()
    state.register(event)
    state.transition(event.event_id, "delivered")
    assert state.register(event) == "delivered"
    with pytest.raises(ProjectionConflict, match="cannot move"):
        state.transition(event.event_id, "retryable", "late worker")
    assert state.register(event) == "delivered"


def test_failed_state_cannot_be_reopened(tmp_path: Path) -> None:
    state = ProjectionState(tmp_path / "projection.sqlite3")
    event = call_event()
    state.register(event)
    state.transition(event.event_id, "failed", "terminal conflict")
    with pytest.raises(ProjectionConflict, match="cannot move"):
        state.transition(event.event_id, "reconciliation_required")
    assert state.register(event) == "failed"
