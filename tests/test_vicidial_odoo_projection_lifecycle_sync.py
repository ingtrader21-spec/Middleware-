"""Real-database regression proving the projection dispatcher keeps
telephony_call_lifecycle in sync with delivered VICIdial call events.

Runs only when a disposable PostgreSQL is available (see
tests/test_agent_provisioning.py for the same convention).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models import EventEnvelope
from app.vicidial_odoo_projection import (
    OdooCallEventDispatcher,
    ProjectionSettings,
    ProjectionState,
)
from workers.run_vicidial_odoo_projection import handle_message

pytestmark = pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)


class FakeMessage:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.acks = 0
        self.terms = 0
        self.naks: list[float] = []

    async def ack(self) -> None:
        self.acks += 1

    async def term(self) -> None:
        self.terms += 1

    async def nak(self, *, delay: float) -> None:
        self.naks.append(delay)

    async def in_progress(self) -> None:
        pass


class NoOpDispatcher:
    async def submit(self, event) -> None:
        pass

    async def reconcile(self, event, *, reason: str) -> None:
        pass


def _envelope(
    *, event_type: str, correlation_id: str, sequence: int, **payload_overrides
) -> EventEnvelope:
    now = datetime.now(timezone.utc)
    payload = {
        "schema_version": "1.0",
        "business_unit_id": "COD",
        "campaign_id": "TEST_SYN",
        "call_id": correlation_id,
        "asterisk_uniqueid": "1710000100.1",
        "linkedid": "1710000100.1",
        "agent_id": "SYN6101",
        "extension": "6101",
        "keycloak_subject": "00000000-0000-0000-0000-000000006101",
        "sequence": sequence,
        "direction": "inbound",
        "caller_number": "+18095550100",
        **payload_overrides,
    }
    return EventEnvelope(
        event_id=f"vici-evt-lifecycle-{uuid4().hex[:12]}",
        event_type=event_type,
        event_version="1.0",
        occurred_at=now,
        received_at=now,
        source="vicidial-adapter",
        tenant_id="COD",
        correlation_id=correlation_id,
        causation_id=f"ami-{uuid4().hex[:12]}",
        idempotency_key=f"vici-idem-{uuid4().hex[:12]}",
        payload=payload,
        metadata={"transport": "ami"},
    )


@pytest_asyncio.fixture
async def engine():
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_factory(engine):
    # A fresh, function-scoped engine/sessionmaker, never the app.db.session
    # module-level singleton -- that singleton is bound to whichever event
    # loop first uses it, which breaks across pytest-asyncio's per-test loops.
    return async_sessionmaker(engine, expire_on_commit=False)


async def _seed_call(engine, *, correlation_id: str) -> None:
    call_id = uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO telephony_call_lifecycle "
                "(id, correlation_id, primary_unique_id, lifecycle_state, "
                " source_extension, destination, dialplan_context) "
                "VALUES (:id, :correlation_id, :unique_id, 'STARTED', "
                " '6101', '+18095550100', 'codestra-test-syn')"
            ),
            {
                "id": call_id,
                "correlation_id": correlation_id,
                "unique_id": "1710000100.1",
            },
        )


async def _fetch_call(engine, *, correlation_id: str) -> dict:
    async with engine.begin() as connection:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT lifecycle_state, started_at, connected_at, ended_at, "
                        "hangup_cause, disposition, fine_state, fine_state_at, "
                        "last_event_sequence, hangup_leg, last_event_type, last_event_at "
                        "FROM telephony_call_lifecycle "
                        "WHERE correlation_id = :correlation_id"
                    ),
                    {"correlation_id": correlation_id},
                )
            )
            .mappings()
            .one()
        )
        return dict(row)


@pytest.mark.asyncio
async def test_dispatcher_advances_lifecycle_state_on_answered_event(
    engine, session_factory, tmp_path: Path
) -> None:
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)

    message = FakeMessage(
        _envelope(
            event_type="codestra.vicidial.call.lifecycle.answered",
            correlation_id=correlation_id,
            sequence=2,
        )
        .model_dump_json()
        .encode()
    )
    await handle_message(
        message,
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=ProjectionState(tmp_path / "projection.sqlite3"),
        dispatcher=Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher()),
        session_factory=session_factory,
    )

    row = await _fetch_call(engine, correlation_id=correlation_id)
    assert row["lifecycle_state"] == "CONNECTED"
    assert row["connected_at"] is not None
    assert row["ended_at"] is None


@pytest.mark.asyncio
async def test_dispatcher_sets_disposition_and_hangup_cause_on_completion(
    engine, session_factory, tmp_path: Path
) -> None:
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)
    state = ProjectionState(tmp_path / "projection.sqlite3")
    dispatcher = Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher())

    await handle_message(
        FakeMessage(
            _envelope(
                event_type="codestra.vicidial.call.lifecycle.answered",
                correlation_id=correlation_id,
                sequence=2,
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=state,
        dispatcher=dispatcher,
        session_factory=session_factory,
    )
    await handle_message(
        FakeMessage(
            _envelope(
                event_type="codestra.vicidial.call.lifecycle.completed",
                correlation_id=correlation_id,
                sequence=3,
                hangup_cause="NORMAL_CLEARING",
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=state,
        dispatcher=dispatcher,
        session_factory=session_factory,
    )

    row = await _fetch_call(engine, correlation_id=correlation_id)
    assert row["lifecycle_state"] == "ENDED"
    assert row["connected_at"] is not None
    assert row["ended_at"] is not None
    assert row["hangup_cause"] == "NORMAL_CLEARING"
    assert row["disposition"] == "COMPLETED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_type,expected_disposition",
    [
        ("codestra.vicidial.call.lifecycle.busy", "BUSY"),
        ("codestra.vicidial.call.lifecycle.no_answer", "NO_ANSWER"),
        ("codestra.vicidial.call.lifecycle.rejected", "REJECTED"),
        ("codestra.vicidial.call.lifecycle.canceled", "CANCELED"),
    ],
)
async def test_dispatcher_sets_disposition_for_each_pre_answer_terminal_outcome(
    engine, session_factory, tmp_path: Path, event_type: str, expected_disposition: str
) -> None:
    """These four terminal outcomes never reach ANSWERED/CONNECTED --
    each is a distinct pre-answer outcome now that the AMI gateway (see
    Vicidialer-Codestra#55) stopped collapsing them into one "missed"
    bucket. The dispatcher must reach ENDED with the correct disposition
    directly from STARTED, without ever having seen a CONNECTED event."""
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)
    state = ProjectionState(tmp_path / "projection.sqlite3")
    dispatcher = Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher())

    await handle_message(
        FakeMessage(
            _envelope(
                event_type=event_type,
                correlation_id=correlation_id,
                sequence=2,
                hangup_cause=expected_disposition,
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=state,
        dispatcher=dispatcher,
        session_factory=session_factory,
    )

    row = await _fetch_call(engine, correlation_id=correlation_id)
    assert row["lifecycle_state"] == "ENDED"
    assert row["connected_at"] is None
    assert row["ended_at"] is not None
    assert row["disposition"] == expected_disposition


@pytest.mark.asyncio
async def test_out_of_order_redelivery_does_not_regress_state(
    engine, session_factory, tmp_path: Path
) -> None:
    """A stale 'ringing' redelivered after 'answered' must not move ENDED/CONNECTED backward."""
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)
    state = ProjectionState(tmp_path / "projection.sqlite3")
    dispatcher = Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher())

    await handle_message(
        FakeMessage(
            _envelope(
                event_type="codestra.vicidial.call.lifecycle.answered",
                correlation_id=correlation_id,
                sequence=2,
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=state,
        dispatcher=dispatcher,
        session_factory=session_factory,
    )

    # A distinct, never-before-seen "ringing" event for the same call (e.g. a
    # duplicate leg report) arriving after "answered" was already processed.
    await handle_message(
        FakeMessage(
            _envelope(
                event_type="codestra.vicidial.call.lifecycle.ringing",
                correlation_id=correlation_id,
                sequence=1,
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=state,
        dispatcher=dispatcher,
        session_factory=session_factory,
    )

    row = await _fetch_call(engine, correlation_id=correlation_id)
    assert row["lifecycle_state"] == "CONNECTED"
    assert row["fine_state"] == "answered"
    assert row["last_event_sequence"] == 2
    assert row["last_event_type"] == "call.answered"


@pytest.mark.asyncio
async def test_last_event_type_recorded_on_coarse_transition(
    engine, session_factory, tmp_path: Path
) -> None:
    """Every coarse-state-moving event also records its raw event_type/timestamp."""
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)

    await handle_message(
        FakeMessage(
            _envelope(
                event_type="codestra.vicidial.call.lifecycle.ringing",
                correlation_id=correlation_id,
                sequence=1,
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=ProjectionState(tmp_path / "projection.sqlite3"),
        dispatcher=Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher()),
        session_factory=session_factory,
    )

    row = await _fetch_call(engine, correlation_id=correlation_id)
    assert row["lifecycle_state"] == "STARTED"
    assert row["last_event_type"] == "call.ringing"
    assert row["last_event_at"] is not None


@pytest.mark.asyncio
async def test_last_event_type_recorded_for_non_coarse_hold_event(
    engine, session_factory, tmp_path: Path
) -> None:
    """call.held doesn't move STARTED/CONNECTED/ENDED but is still visible
    via last_event_type -- the finer taxonomy Odoo already tracks."""
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)
    state = ProjectionState(tmp_path / "projection.sqlite3")
    dispatcher = Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher())

    await handle_message(
        FakeMessage(
            _envelope(
                event_type="codestra.vicidial.call.lifecycle.answered",
                correlation_id=correlation_id,
                sequence=2,
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=state,
        dispatcher=dispatcher,
        session_factory=session_factory,
    )

    row_before = await _fetch_call(engine, correlation_id=correlation_id)
    assert row_before["lifecycle_state"] == "CONNECTED"

    await handle_message(
        FakeMessage(
            _envelope(
                event_type="codestra.vicidial.call.lifecycle.transfer.started",
                correlation_id=correlation_id,
                sequence=3,
            )
            .model_dump_json()
            .encode()
        ),
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=state,
        dispatcher=dispatcher,
        session_factory=session_factory,
    )

    row_after = await _fetch_call(engine, correlation_id=correlation_id)
    assert row_after["lifecycle_state"] == "CONNECTED"
    assert row_after["last_event_type"] == "call.transfer.started"


@pytest.mark.asyncio
async def test_queue_and_dialing_are_durable_fine_states(
    engine, session_factory, tmp_path: Path
) -> None:
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)
    state = ProjectionState(tmp_path / "projection.sqlite3")
    dispatcher = Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher())

    for sequence, event_type in (
        (1, "codestra.vicidial.call.lifecycle.queued"),
        (2, "codestra.vicidial.call.lifecycle.dialing"),
    ):
        await handle_message(
            FakeMessage(
                _envelope(
                    event_type=event_type,
                    correlation_id=correlation_id,
                    sequence=sequence,
                )
                .model_dump_json()
                .encode()
            ),
            settings=Mock(spec=ProjectionSettings, synthetic_only=True),
            state=state,
            dispatcher=dispatcher,
            session_factory=session_factory,
        )

    row = await _fetch_call(engine, correlation_id=correlation_id)
    assert row["fine_state"] == "dialing"
    assert row["last_event_sequence"] == 2
    assert row["last_event_type"] == "call.dialing"


@pytest.mark.asyncio
async def test_hangup_is_intermediate_until_terminal_outcome(
    engine, session_factory, tmp_path: Path
) -> None:
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)
    state = ProjectionState(tmp_path / "projection.sqlite3")
    dispatcher = Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher())

    async def deliver(event_type: str, sequence: int, **payload) -> None:
        await handle_message(
            FakeMessage(
                _envelope(
                    event_type=event_type,
                    correlation_id=correlation_id,
                    sequence=sequence,
                    **payload,
                )
                .model_dump_json()
                .encode()
            ),
            settings=Mock(spec=ProjectionSettings, synthetic_only=True),
            state=state,
            dispatcher=dispatcher,
            session_factory=session_factory,
        )

    await deliver(
        "codestra.vicidial.call.lifecycle.answered",
        1,
    )
    await deliver(
        "codestra.vicidial.call.lifecycle.hangup",
        2,
        hangup_cause="NORMAL_CLEARING",
        hangup_leg="agent_leg",
    )
    mid = await _fetch_call(engine, correlation_id=correlation_id)
    assert mid["lifecycle_state"] == "CONNECTED"
    assert mid["fine_state"] == "answered"
    assert mid["ended_at"] is None
    assert mid["last_event_type"] == "call.hangup"
    assert mid["hangup_leg"] == "agent_leg"

    await deliver(
        "codestra.vicidial.call.lifecycle.completed",
        3,
        hangup_cause="NORMAL_CLEARING",
    )
    final = await _fetch_call(engine, correlation_id=correlation_id)
    assert final["lifecycle_state"] == "ENDED"
    assert final["fine_state"] == "completed"
    assert final["ended_at"] is not None
    assert final["last_event_sequence"] == 3


@pytest.mark.asyncio
async def test_readback_survives_a_lost_browser_session(
    engine, session_factory, tmp_path: Path
) -> None:
    """The durable projection advances without a websocket/browser present."""
    correlation_id = f"vici-call-sync-{uuid4().hex[:12]}"
    await _seed_call(engine, correlation_id=correlation_id)
    message = FakeMessage(
        _envelope(
            event_type="codestra.vicidial.call.lifecycle.ringing",
            correlation_id=correlation_id,
            sequence=1,
        )
        .model_dump_json()
        .encode()
    )

    await handle_message(
        message,
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=ProjectionState(tmp_path / "projection.sqlite3"),
        dispatcher=Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher()),
        session_factory=session_factory,
    )

    row = await _fetch_call(engine, correlation_id=correlation_id)
    assert message.acks == 1
    assert row["fine_state"] == "ringing"
    assert row["last_event_sequence"] == 1


@pytest.mark.asyncio
async def test_event_for_unknown_correlation_id_is_a_silent_noop(
    session_factory, tmp_path: Path
) -> None:
    """No telephony_call_lifecycle row (e.g. an inbound call Middleware never
    originated) must not raise or block Odoo delivery."""
    message = FakeMessage(
        _envelope(
            event_type="codestra.vicidial.call.lifecycle.answered",
            correlation_id=f"vici-call-unknown-{uuid4().hex[:12]}",
            sequence=1,
        )
        .model_dump_json()
        .encode()
    )
    await handle_message(
        message,
        settings=Mock(spec=ProjectionSettings, synthetic_only=True),
        state=ProjectionState(tmp_path / "projection.sqlite3"),
        dispatcher=Mock(spec=OdooCallEventDispatcher, wraps=NoOpDispatcher()),
        session_factory=session_factory,
    )
    assert message.acks == 1
    assert message.terms == 0
