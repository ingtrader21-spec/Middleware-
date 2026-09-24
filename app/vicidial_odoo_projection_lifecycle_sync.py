"""Keep the durable Odoo/Middleware call read-back aligned with AMI evidence.

The table retains its legacy coarse lifecycle_state for compatibility, while
fine_state exposes the evidence-backed call vocabulary. Raw event_type and
sequence are retained so a browser refresh can read the same durable snapshot
that a live subscriber would have received.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import TelephonyCallLifecycle
from app.vicidial_odoo_projection_models import OdooCallEvent

log = logging.getLogger("codestra.vicidial_odoo_projection.lifecycle_sync")

# The existing API keeps this three-state compatibility field.
_STATE_RANK = {"STARTED": 1, "CONNECTED": 2, "ENDED": 3}

# This is the read-back vocabulary, not a list of invented AMI events. The
# request route writes requested; adapter acceptance/channel creation writes
# accepted; the remaining values are produced only by the adapter's evidence
# mapper.
_FINE_STATE_RANK = {
    "requested": 0,
    "accepted": 1,
    "queued": 2,
    "dialing": 3,
    "ringing": 4,
    "answered": 5,
    "connected": 6,
    "completed": 100,
    "failed": 100,
    "busy": 100,
    "no_answer": 100,
    "canceled": 100,
    "rejected": 100,
}
_TERMINAL_FINE_STATES = frozenset(
    {
        "completed",
        "failed",
        "busy",
        "no_answer",
        "canceled",
        "rejected",
    }
)
_FINE_STATE_BY_TYPE = {
    "call.created": "accepted",
    "call.offered": "accepted",
    "call.queued": "queued",
    "call.dialing": "dialing",
    "call.ringing": "ringing",
    "call.answered": "answered",
    "call.connected": "connected",
    # Hold/resume are real events, but the requested public vocabulary has no
    # separate hold state. Keep the raw event and the durable connected state.
    "call.held": "connected",
    "call.resumed": "connected",
    "call.completed": "completed",
    "call.failed": "failed",
    "call.busy": "busy",
    "call.no_answer": "no_answer",
    "call.canceled": "canceled",
    "call.rejected": "rejected",
}
_STARTED_TYPES = frozenset(
    {
        "call.created",
        "call.offered",
        "call.queued",
        "call.dialing",
        "call.ringing",
    }
)
_CONNECTED_TYPES = frozenset(
    {"call.answered", "call.connected", "call.held", "call.resumed"}
)
# Hangup is an intermediate channel-end signal. The adapter publishes
# completed/failed/etc. after it has enough evidence to classify the outcome.
_ENDED_TYPES = frozenset(
    {
        "call.completed",
        "call.failed",
        "call.busy",
        "call.no_answer",
        "call.rejected",
        "call.canceled",
    }
)
_NON_COARSE_TYPES = frozenset(
    {
        "call.held",
        "call.resumed",
        "call.transfer.started",
        "call.transfer.completed",
        "call.hangup",
    }
)
_DISPOSITION_BY_TYPE = {
    "call.completed": "COMPLETED",
    "call.failed": "FAILED",
    "call.busy": "BUSY",
    "call.no_answer": "NO_ANSWER",
    "call.rejected": "REJECTED",
    "call.canceled": "CANCELED",
}


def _coarse_state(event_type: str) -> str | None:
    if event_type in _STARTED_TYPES:
        return "STARTED"
    if event_type in _CONNECTED_TYPES:
        return "CONNECTED"
    if event_type in _ENDED_TYPES:
        return "ENDED"
    return None


async def sync_call_lifecycle(session: AsyncSession, event: OdooCallEvent) -> None:
    """Apply one canonical event to the durable read-back row.

    The worker remains responsible for event-id idempotency and delivery
    acknowledgement. This side effect independently guards sequence order so
    a delayed event cannot regress the browser-refresh/read API snapshot.
    """

    new_state = _coarse_state(event.event_type)
    is_known_lifecycle = (
        new_state is not None
        or event.event_type in _NON_COARSE_TYPES
        or event.event_type in _FINE_STATE_BY_TYPE
    )
    if not is_known_lifecycle:
        return

    row = (
        await session.execute(
            select(TelephonyCallLifecycle)
            .where(TelephonyCallLifecycle.correlation_id == event.correlation_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        log.info(
            "no telephony_call_lifecycle row for correlation_id=%s "
            "(event_type=%s) -- not originated via /calls/originate, skipping",
            event.correlation_id,
            event.event_type,
        )
        return

    last_sequence = int(row.last_event_sequence or 0)
    if event.sequence <= last_sequence:
        # The canonical worker has already handled this sequence or a newer
        # one. Do not replace last_event_type with a delayed duplicate.
        return

    row.last_event_sequence = event.sequence
    row.last_event_type = event.event_type
    row.last_event_at = event.timestamp

    if event.hangup_cause is not None and row.hangup_cause is None:
        row.hangup_cause = event.hangup_cause
    if event.hangup_leg is not None and row.hangup_leg is None:
        row.hangup_leg = event.hangup_leg

    target_fine_state = _FINE_STATE_BY_TYPE.get(event.event_type)
    current_fine_state = row.fine_state or "requested"
    if target_fine_state is not None:
        current_rank = _FINE_STATE_RANK.get(current_fine_state, 0)
        target_rank = _FINE_STATE_RANK[target_fine_state]
        if current_fine_state in _TERMINAL_FINE_STATES:
            if target_fine_state != current_fine_state:
                log.warning(
                    "ignoring terminal fine-state conflict for correlation_id=%s: "
                    "%s -> %s",
                    event.correlation_id,
                    current_fine_state,
                    target_fine_state,
                )
        elif target_rank >= current_rank:
            row.fine_state = target_fine_state
            row.fine_state_at = event.timestamp

    if new_state == "STARTED" and row.started_at is None:
        row.started_at = event.timestamp
    elif new_state == "CONNECTED" and row.connected_at is None:
        row.connected_at = event.timestamp
    elif new_state == "ENDED" and row.ended_at is None:
        row.ended_at = event.timestamp
        disposition = _DISPOSITION_BY_TYPE.get(event.event_type)
        if disposition is not None:
            row.disposition = disposition

    if new_state is not None and _STATE_RANK[new_state] > _STATE_RANK.get(
        row.lifecycle_state, 0
    ):
        row.lifecycle_state = new_state

    await session.commit()
