from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models import EventEnvelope


def payload(event_version: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "event_id": "evt-schema",
        "event_type": "codestra.test.event",
        "event_version": event_version,
        "occurred_at": now,
        "received_at": now,
        "source": "test-source",
        "tenant_id": "tenant-test",
        "correlation_id": "corr-1",
        "causation_id": "cause-1",
        "idempotency_key": "idem-schema-1",
        "payload": {},
        "metadata": {},
    }


def test_event_version_one_is_supported() -> None:
    assert EventEnvelope.model_validate(payload("1.0")).event_version == "1.0"


@pytest.mark.parametrize("unsupported", ["0.9", "2.0", "v1"])
def test_unsupported_event_versions_fail_closed(unsupported: str) -> None:
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate(payload(unsupported))


def test_legacy_cloudevent_shape_is_not_a_second_canonical_contract() -> None:
    legacy = {
        "specversion": "1.0",
        "id": "evt-schema",
        "type": "codestra.test.event",
        "source": "urn:codestra:test-source",
        "subject": "subject/1",
        "time": "2026-08-28T12:00:00Z",
        "tenant_id": "tenant-test",
        "correlation_id": "corr-1",
        "causation_id": "cause-1",
        "idempotency_key": "idem-schema-1",
        "schema_version": 1,
        "data": {},
    }
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate(legacy)
