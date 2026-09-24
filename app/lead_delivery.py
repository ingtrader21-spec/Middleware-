from __future__ import annotations

import hashlib
import uuid

from .commands import CommandEnvelope
from .models import EventEnvelope


LEAD_SUBMITTED = "codestra.events.lead_submitted"
ODOO_LEAD_UPSERT_COMMAND = "crm.lead.intake.upsert.v1"
ODOO_TARGET = "odoo-19"


def build_odoo_lead_upsert_command(event: EventEnvelope) -> CommandEnvelope:
    """Translate a durable lead-submitted event into the canonical Odoo command.

    This function does not perform network I/O. The existing command/outbox worker
    remains responsible for dispatch and read-back. LIVE/ODOO write capability
    controls therefore remain authoritative.
    """
    if event.event_type != LEAD_SUBMITTED:
        raise ValueError("event is not a lead submission")

    command_id = uuid.UUID(
        hashlib.md5(
            f"codestra-odoo-lead-upsert\0{event.tenant_id}\0{event.event_id}".encode(
                "utf-8"
            ),
            usedforsecurity=False,
        ).hexdigest()
    )
    return CommandEnvelope(
        command_id=command_id,
        command_type=ODOO_LEAD_UPSERT_COMMAND,
        command_version="1.0",
        target=ODOO_TARGET,
        tenant_id=event.tenant_id,
        requested_by="middleware-worker",
        correlation_id=event.correlation_id,
        idempotency_key=f"odoo-lead-{event.event_id}",
        capability="ODOO_WRITE",
        payload={
            "model": "crm.lead",
            "method": "codestra_upsert_intake_lead",
            "args": [event.model_dump(mode="json")],
            "source_event_id": event.event_id,
            "source_event_type": event.event_type,
        },
    )
