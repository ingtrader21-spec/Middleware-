from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.sdk_events import (
    CALL_DISPOSITION_UPDATED,
    SMS_RECEIVED,
    CallDispositionUpdatedPayload,
    SmsReceivedPayload,
    build_call_disposition_updated_event,
    build_sms_received_event,
    record_sdk_event,
)
from app.storage import verify_event_ledger_records


def test_build_call_disposition_updated_event_matches_sdk_contract() -> None:
    event = build_call_disposition_updated_event(
        tenant_id="tenant-1",
        occurred_at=datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
        received_at=datetime(2026, 8, 29, 12, 0, 1, tzinfo=UTC),
        payload=CallDispositionUpdatedPayload(
            correlation_id="11111111-1111-4111-8111-111111111111",
            causation_id="1745850000.42",
            odoo_contact_id=4301,
            odoo_lead_id=None,
            disposition="sale_completed",
            phone_number="+15551234567",
            duration_seconds=180,
            campaign_id="campaign-alpha",
            provider_call_id="1745850000.42",
            dry_run=False,
        ),
    )

    assert event.event_type == CALL_DISPOSITION_UPDATED
    assert event.source == "middleware-api"
    assert event.event_id.startswith("sdk-call-disposition-")
    assert event.idempotency_key == event.event_id
    assert event.correlation_id == "11111111-1111-4111-8111-111111111111"
    assert event.causation_id == "1745850000.42"
    assert event.payload == {
        "event_type": "call_disposition_updated",
        "correlation_id": "11111111-1111-4111-8111-111111111111",
        "causation_id": "1745850000.42",
        "odoo_contact_id": 4301,
        "odoo_lead_id": None,
        "disposition": "sale_completed",
        "phone_number": "+15551234567",
        "duration_seconds": 180,
        "campaign_id": "campaign-alpha",
        "provider_call_id": "1745850000.42",
        "dry_run": False,
    }


def test_build_sms_received_event_matches_sdk_contract() -> None:
    event = build_sms_received_event(
        tenant_id="tenant-1",
        occurred_at=datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
        payload=SmsReceivedPayload(
            correlation_id="22222222-2222-4222-8222-222222222222",
            causation_id="telnexa-message-123",
            odoo_contact_id=4301,
            odoo_message_id=None,
            from_number="+15557654321",
            body_preview="Reply received",
            provider_event_id="telnexa-message-123",
            dry_run=True,
        ),
    )

    assert event.event_type == SMS_RECEIVED
    assert event.source == "middleware-api"
    assert event.event_id.startswith("sdk-sms-received-")
    assert event.payload == {
        "event_type": "sms_received",
        "correlation_id": "22222222-2222-4222-8222-222222222222",
        "causation_id": "telnexa-message-123",
        "odoo_contact_id": 4301,
        "odoo_message_id": None,
        "from_number": "+15557654321",
        "body_preview": "Reply received",
        "provider_event_id": "telnexa-message-123",
        "dry_run": True,
    }


def test_sdk_payloads_fail_closed_on_unknown_or_invalid_values() -> None:
    with pytest.raises(ValidationError):
        CallDispositionUpdatedPayload.model_validate({
            "correlation_id": "corr-1",
            "causation_id": "call-1",
            "disposition": "SALE",
            "phone_number": "5551234567",
            "provider_call_id": "call-1",
        })
    with pytest.raises(ValidationError):
        SmsReceivedPayload.model_validate({
            "correlation_id": "corr-1",
            "causation_id": "sms-1",
            "from_number": "+15551234567",
            "body_preview": "x" * 121,
            "provider_event_id": "sms-1",
            "extra": True,
        })


@pytest.mark.asyncio
async def test_record_sdk_event_uses_durable_inbox_and_ledger(runtime) -> None:
    event = build_sms_received_event(
        tenant_id="tenant-1",
        occurred_at=datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
        received_at=datetime(2026, 8, 29, 12, 0, 1, tzinfo=UTC),
        payload=SmsReceivedPayload(
            correlation_id="22222222-2222-4222-8222-222222222222",
            causation_id="telnexa-message-123",
            from_number="+15557654321",
            body_preview="Reply received",
            provider_event_id="telnexa-message-123",
        ),
    )

    accepted = await record_sdk_event(runtime, event)
    duplicate = await record_sdk_event(runtime, event)

    assert accepted.status == "accepted"
    assert duplicate.status == "duplicate"
    assert verify_event_ledger_records(runtime.inbox.ledger_records) == {
        "tenant-1": 1
    }
