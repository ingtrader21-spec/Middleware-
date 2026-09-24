import pytest
from pydantic import ValidationError

from fastapi import HTTPException

from app.api.v1.automation import (
    AutomationAuditResult,
    CRMEventEnvelope,
    EventEnvelope,
    IdempotencyReservation,
    enforce_scope,
)
from app.api.v1.integrations import AutomationResult


def test_idempotency_reservation_requires_scoped_identity():
    reservation = IdempotencyReservation(
        environment="staging",
        workflow_code="N8-1000",
        event_id="event-1",
        correlation_id="correlation-1",
        idempotency_key="lead-ingest:test:1",
        payload={"business_unit": "MOY", "campaign_id": "TEST-SYN"},
    )
    assert reservation.environment == "staging"
    assert reservation.workflow_code == "N8-1000"


@pytest.mark.parametrize(
    "field,value",
    (
        ("workflow_code", "unscoped"),
        ("environment", "unknown"),
        ("idempotency_key", ""),
    ),
)
def test_idempotency_reservation_rejects_invalid_identity(field, value):
    values = {
        "environment": "staging",
        "workflow_code": "N8-1000",
        "event_id": "event-1",
        "correlation_id": "correlation-1",
        "idempotency_key": "lead-ingest:test:1",
        "payload": {},
    }
    values[field] = value
    with pytest.raises(ValidationError):
        IdempotencyReservation(**values)


def test_audit_result_rejects_unknown_business_unit():
    values = {
        "workflow_code": "N8-1000",
        "workflow_version": "1",
        "execution_id": "execution-1",
        "event_id": "event-1",
        "correlation_id": "correlation-1",
        "idempotency_key": "lead-ingest:test:1",
        "business_unit": "UNKNOWN",
        "campaign_id": "TEST-SYN",
        "action": "lead-ingest",
        "provider": "synthetic",
        "status": "completed",
    }
    with pytest.raises(ValidationError):
        AutomationAuditResult(**values)


def test_audit_result_accepts_redactable_details():
    result = AutomationAuditResult(
        workflow_code="N8-1000",
        workflow_version="1",
        execution_id="execution-1",
        event_id="event-1",
        correlation_id="correlation-1",
        idempotency_key="lead-ingest:test:1",
        business_unit="MOY",
        campaign_id="TEST-SYN",
        action="lead-ingest",
        provider="synthetic",
        status="completed",
        details={"token": "must-be-redacted-by-the-route"},
    )
    assert result.status == "completed"


def test_policy_rejects_unknown_business_unit():
    envelope = EventEnvelope(
        schema_version="1",
        event_id="event-1",
        event_type="lead.created",
        event_time="2026-07-25T16:00:00Z",
        environment="staging",
        source_system="middleware",
        business_unit="UNKNOWN",
        campaign_id="TEST_SYN",
        entity_type="crm.lead",
        entity_id="synthetic-1",
        correlation_id="correlation-1",
        idempotency_key="lead-ingest:test:1",
        payload={},
    )
    with pytest.raises(HTTPException) as raised:
        enforce_scope(envelope)
    assert raised.value.status_code == 403


def test_standard_campaign_event_requires_trusted_identity_outside_payload():
    event = CRMEventEnvelope(
        schema_version="1", event_id="event-1", event_type="crm.status.changed",
        correlation_id="correlation-1", idempotency_key="crm:test:1",
        tenant_id="codestra", business_unit_id="MBL", campaign_id="TEST_SYN",
        entity_type="crm.lead", entity_id="synthetic-1", actor_type="AI",
        actor_id="synthetic-ai", occurred_at="2026-08-22T16:00:00Z",
        automation_key="moneybee_documents_requested", payload={"campaign_id": "UNTRUSTED"},
    )
    assert event.campaign_id == "TEST_SYN"
    assert event.payload["campaign_id"] == "UNTRUSTED"


def test_standard_result_rejects_unbounded_actions():
    with pytest.raises(ValidationError):
        AutomationResult.model_validate({
            "event_id": "event-1", "correlation_id": "correlation-1",
            "idempotency_key": "crm:test:1", "workflow_key": "moneybee_documents_requested",
            "execution_id": "execution-1", "status": "COMPLETED",
            "actions": [{"action_type": "APPROVE_APPLICATION", "entity_type": "crm.lead", "entity_id": "1", "values": {}}],
            "completed_at": "2026-08-22T16:01:00Z",
        })
