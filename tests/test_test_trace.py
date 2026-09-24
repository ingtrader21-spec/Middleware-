from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.core.test_trace import (
    InvalidTestTrace,
    RecordEnvironment,
    TraceKind,
    TraceRecord,
    redacted_response_hash,
    select_test_extension,
    summarize_trace,
)


def trace_record(**overrides):
    started = datetime(2026, 7, 29, 4, tzinfo=timezone.utc)
    values = {
        "test_run_id": "CTR-20260729-0001",
        "record_environment": RecordEnvironment.TEST,
        "organization_id": "CODESTRA-SRL",
        "business_unit_id": "BU-400-COD",
        "campaign_id": "CMP-400-COD",
        "aggregate_type": "AGENT",
        "aggregate_id": "400-AGT-90000001",
        "command_id": "CMD-CTR-0001",
        "command_type": "agent.provision",
        "command_status": "COMPLETED_DISABLED",
        "idempotency_key": "CTR-20260729-0001:agent.provision",
        "correlation_id": "CORR-CTR-20260729-0001",
        "causation_id": "ODOO-OUTBOX-0001",
        "event_id": "EVT-CTR-0001",
        "trace_kind": TraceKind.ACTION,
        "action_service": "codestra-policy-api",
        "action_name": "agent.provision",
        "action_started_at": started,
        "action_completed_at": started + timedelta(milliseconds=20),
        "policy_decision": "ALLOW_TEST_DISABLED",
        "policy_version": "test-agent-v1",
        "policy_hash": "a" * 64,
        "target_system": "middleware",
        "target_object_type": "telephony_provisioning_saga",
        "target_object_id": "SAGA-CTR-0001",
        "attempt_number": 1,
        "response_classification": "ACCEPTED_DISABLED",
        "response_status": "SUCCESS",
        "response_code": "COMPLETED_DISABLED",
        "response_summary": "test-only disabled provisioning recorded",
        "response_hash": redacted_response_hash(
            "test-only disabled provisioning recorded"
        ),
        "response_received_at": started + timedelta(milliseconds=25),
        "latency_ms": 25,
        "reconciliation_status": "PENDING",
        "desired_version": 1,
        "observed_version": 0,
        "drift_classification": "NOT_CHECKED",
        "reconciled_at": None,
        "created_by": "test-harness",
        "approved_by": "test-policy",
        "created_at": started,
        "updated_at": started + timedelta(milliseconds=25),
        "evidence": {"record_id": "SAGA-CTR-0001", "secret_state": "REDACTED"},
    }
    values.update(overrides)
    return TraceRecord(**values)


def test_selects_only_a_verified_free_controlled_test_extension():
    assert select_test_extension({7490}, {7491, 7492}) == 7493


def test_extension_selection_fails_when_every_candidate_conflicts():
    with pytest.raises(InvalidTestTrace):
        select_test_extension({7490, 7491, 7492, 7493, 7494}, set())


@pytest.mark.parametrize(
    "override",
    [
        {"record_environment": "PRODUCTION"},
        {"business_unit_id": "BU-REAL"},
        {"campaign_id": "CMP-OTHER"},
        {"policy_hash": "not-a-hash"},
        {"attempt_number": 0},
        {"evidence": {"sip_password": "must-not-appear"}},
        {"evidence": {"nested": {"access_token": "must-not-appear"}}},
    ],
)
def test_trace_contract_fails_closed(override):
    with pytest.raises(InvalidTestTrace):
        trace_record(**override).validate()


def test_trace_summary_uses_existing_action_reaction_and_reconciliation_records():
    action = trace_record()
    reaction = replace(
        action,
        event_id="EVT-CTR-0002",
        trace_kind=TraceKind.REACTION,
        action_service="codestra-provisioning",
        action_name="extension.reserved_disabled",
        action_started_at=action.action_started_at + timedelta(milliseconds=30),
        action_completed_at=action.action_started_at + timedelta(milliseconds=40),
        response_received_at=action.action_started_at + timedelta(milliseconds=45),
        updated_at=action.action_started_at + timedelta(milliseconds=45),
    )
    reconciliation = replace(
        action,
        event_id="EVT-CTR-0003",
        trace_kind=TraceKind.RECONCILIATION,
        action_service="codestra-reconciliation",
        action_name="desired_equals_observed",
        action_started_at=action.action_started_at + timedelta(milliseconds=50),
        action_completed_at=action.action_started_at + timedelta(milliseconds=60),
        response_received_at=action.action_started_at + timedelta(milliseconds=65),
        latency_ms=15,
        reconciliation_status="COMPLETED",
        observed_version=1,
        drift_classification="NONE",
        reconciled_at=action.action_started_at + timedelta(milliseconds=65),
        updated_at=action.action_started_at + timedelta(milliseconds=65),
    )
    summary = summarize_trace([reconciliation, reaction, action])
    assert summary.action_count == 1
    assert summary.reaction_count == 1
    assert summary.reconciliation_count == 1
    assert summary.duplicate_action_count == 0
    assert summary.failed_action_count == 0
    assert summary.reconciliation_drift_count == 0
    assert summary.end_to_end_latency_ms == 65


def test_trace_summary_rejects_cross_run_or_cross_correlation_records():
    first = trace_record()
    with pytest.raises(InvalidTestTrace):
        summarize_trace([first, replace(first, test_run_id="CTR-OTHER")])
    with pytest.raises(InvalidTestTrace):
        summarize_trace([first, replace(first, correlation_id="CORR-OTHER")])
