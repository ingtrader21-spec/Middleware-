from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.v1.n8n_transport import (
    AcknowledgementRequest,
    ExecutionRegistrationRequest,
)
from app.core.config import Settings
from app.db.models import N8nTargetAttestation


def test_production_target_is_exactly_allowlisted():
    value = "https://n8n.internal.codestra.agency/webhook/codestra/v1/events"
    assert Settings(n8n_production_target_url=value).n8n_production_target_url == value


@pytest.mark.parametrize(
    "value",
    (
        "https://staging-n8n.internal.codestra.agency/webhook/codestra/v1/events",
        "https://n8n.internal.codestra.agency/legacy",
        "https://n8n.internal.codestra.agency/webhook/codestra/v1/events?next=evil",
        "http://n8n.internal.codestra.agency/webhook/codestra/v1/events",
        "https://example.com/webhook/codestra/v1/events",
    ),
)
def test_arbitrary_staging_legacy_and_insecure_targets_are_rejected(value):
    with pytest.raises(ValidationError):
        Settings(n8n_production_target_url=value)


def test_execution_registration_rejects_non_production_environment():
    with pytest.raises(ValidationError):
        ExecutionRegistrationRequest(
            schema_version="1.0",
            registration_id=uuid4(),
            delivery_id=uuid4(),
            event_id="event-1",
            workflow_id="workflow-1",
            workflow_version="version-1",
            execution_id="execution-1",
            payload_hash="a" * 64,
            request_hash="d" * 64,
            environment="staging",
            idempotency_key="registration-1",
            correlation_id="correlation-1",
            received_at=datetime.now(UTC),
            registered_at=datetime.now(UTC),
        )


def test_acknowledgement_requires_final_status_and_hashes():
    value = AcknowledgementRequest(
        schema_version="1.0",
        acknowledgement_id=uuid4(),
        registration_id=uuid4(),
        delivery_id=uuid4(),
        event_id="event-1",
        workflow_id="workflow-1",
        workflow_version="version-1",
        execution_id="execution-1",
        execution_status="SUCCEEDED",
        result_classification="INTERNAL_RECONCILIATION_COMPLETE",
        result_hash="b" * 64,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        attempt_number=1,
        correlation_id="correlation-1",
        policy_hash="c" * 64,
        metrics={"duration_ms": 0},
    )
    assert value.execution_status == "SUCCEEDED"


def test_acknowledgement_rejects_nonfinal_status():
    with pytest.raises(ValidationError):
        AcknowledgementRequest(
            schema_version="1.0",
            acknowledgement_id=uuid4(),
            registration_id=uuid4(),
            delivery_id=uuid4(),
            event_id="event-1",
            workflow_id="workflow-1",
            workflow_version="version-1",
            execution_id="execution-1",
            execution_status="RUNNING",
            result_classification="INTERNAL",
            result_hash="b" * 64,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            attempt_number=1,
            correlation_id="correlation-1",
            policy_hash="c" * 64,
            metrics={"duration_ms": 0},
        )


def test_target_attestation_is_a_durable_model():
    assert N8nTargetAttestation.__tablename__ == "n8n_target_attestation"
    assert "image_digest" in N8nTargetAttestation.__table__.columns
    assert "expires_at" in N8nTargetAttestation.__table__.columns
    assert "workflow_package_sha256" in N8nTargetAttestation.__table__.columns
    assert "request_nonce" in N8nTargetAttestation.__table__.columns
