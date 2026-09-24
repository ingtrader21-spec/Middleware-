import json
import hashlib
from uuid import uuid4
import pytest
from pydantic import ValidationError

from app.schemas.registry import LifecyclePayload, REGISTRY, parse_event


def event(event_type="vicidial.call.ended", payload=None):
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "event_type": event_type,
        "occurred_at": "2026-07-24T20:00:00Z",
        "correlation_id": "contract-test",
        "client_instance": "vicidial-server-b",
        "payload": payload
        or {
            "call_id": "synthetic-1",
            "ended_at": "2026-07-24T20:00:00Z",
            "duration_seconds": 0,
            "direction": "outbound",
        },
    }


def test_every_registry_entry_has_strict_v1_schema():
    assert len(REGISTRY) == 16
    for definition in REGISTRY.values():
        assert definition["version"] == "1.0"
        assert definition["model"].model_json_schema()["additionalProperties"] is False


def test_call_ended_parses_and_unknown_fields_are_rejected():
    value = event()
    envelope, payload = parse_event(
        json.dumps(value).encode(), frozenset({value["event_type"]})
    )
    assert envelope.event_type == "vicidial.call.ended"
    value["payload"]["telephone_number"] = "+10000000000"
    with pytest.raises(ValidationError):
        parse_event(json.dumps(value).encode(), frozenset({value["event_type"]}))


def test_disabled_and_unsupported_event_types_are_rejected():
    with pytest.raises(ValueError, match="not enabled"):
        parse_event(json.dumps(event()).encode(), frozenset())
    value = event("vicidial.unknown")
    with pytest.raises(ValueError, match="not enabled"):
        parse_event(json.dumps(value).encode(), frozenset({"vicidial.unknown"}))


def lifecycle_event(event_type, state, linked_id="linked-6198"):
    payload = {
        "lifecycle_status": state,
        "disposition": "ANSWERED" if state == "ENDED" else None,
        "hangup_cause": "16" if state == "ENDED" else None,
    }
    value = event(event_type, payload)
    value.update(
        {
            "source_system": "asterisk-ami",
            "producer_instance_id": "server-b",
            "producer_boot_id": "boot-1",
            "payload_sha256": hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "asterisk_unique_id": "unique-6198",
            "asterisk_linked_id": linked_id,
            "channel": "Local/6198@cs-synth-6198",
            "source_extension": "6198",
            "destination": "*43",
            "dialplan_context": "cs-synth-6198",
        }
    )
    return value


def test_lifecycle_schema_and_payload_integrity():
    for event_type, state in (
        ("vicidial.call.started", "STARTED"),
        ("vicidial.call.connected", "CONNECTED"),
        ("vicidial.call.ended", "ENDED"),
    ):
        value = lifecycle_event(event_type, state)
        envelope, payload = parse_event(
            json.dumps(value).encode(), frozenset({event_type})
        )
        assert envelope.event_type == event_type
        assert isinstance(payload, LifecyclePayload)
        assert payload.lifecycle_status == state
    value = lifecycle_event("vicidial.call.started", "STARTED")
    value["payload"]["hangup_cause"] = "changed"
    with pytest.raises(ValueError, match="payload integrity"):
        parse_event(
            json.dumps(value).encode(),
            frozenset({"vicidial.call.started"}),
        )
    value = lifecycle_event("vicidial.call.started", "ENDED")
    with pytest.raises(ValueError, match="event type"):
        parse_event(
            json.dumps(value).encode(),
            frozenset({"vicidial.call.started"}),
        )
