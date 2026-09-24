from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.api.v1.agent_realtime import AgentEventEnvelope, transition_allowed


def envelope(**changes):
    value = {
        "schema_version": "1.0",
        "event_id": "event-0001",
        "event_type": "call.ringing",
        "timestamp": datetime.now(UTC),
        "correlation_id": "correlation-0001",
        "idempotency_key": "idempotency-0001",
        "tenant_id": "TST",
        "business_unit_id": "TST",
        "campaign_id": "TEST_SYN",
        "call_id": "call-0001",
        "asterisk_uniqueid": "asterisk-0001",
        "linkedid": "linked-0001",
        "agent_id": "APP-DESKTOP-STAGE-001",
        "extension": "6101",
        "sequence": 1,
        "payload": {},
    }
    value.update(changes)
    return AgentEventEnvelope(**value)


def test_complete_canonical_envelope_is_required():
    assert envelope().extension == "6101"
    with pytest.raises(ValidationError):
        envelope(schema_version="2.0")
    with pytest.raises(ValidationError):
        envelope(extension="6102", unexpected=True)


def test_out_of_order_and_terminal_regression_are_denied():
    assert transition_allowed(None, None, 1)
    assert transition_allowed("call.ringing", 1, 2)
    assert not transition_allowed("call.answered", 2, 1)
    assert not transition_allowed("call.completed", 3, 4)
