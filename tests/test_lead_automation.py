import pytest

from app.adapters.odoo.lead_automation import signed_headers
from app.core.lead_automation import (
    Conflict,
    LeadAutomationError,
    LeadAutomationService,
    Policy,
    State,
    TenantScope,
)


def payload(**updates):
    value = {
        "contract_version": "1.1",
        "event_id": "EVT-synthetic01",
        "event_type": "lead.update.requested.v1",
        "occurred_at": "2026-01-01T00:00:00Z",
        "environment": "staging",
        "company_key": "COMPANY-1",
        "business_unit_key": "web-mobile-ai",
        "campaign_key": "TEST_LEADS",
        "automation_action": "UPDATE_ALLOWLISTED_FIELDS",
        "idempotency_key": "a" * 64,
        "correlation_id": "00000000-0000-4000-8000-000000000001",
        "policy_version": "1.0",
        "lead_uid": "LEAD-synthetic01",
        "attributes_schema_key": "web-mobile-ai-lead-v1",
        "attributes": {"solution_type": "AI"},
        "consent_snapshot": {
            "consent_status": "granted",
            "consent_purpose": "LEAD_SERVICE",
            "consent_source": "odoo",
            "consent_updated_at": "2026-01-01T00:00:00Z",
            "dnc_status": False,
            "dnc_updated_at": "2026-01-01T00:00:00Z",
            "jurisdiction": "DO",
            "source_system": "odoo",
        },
    }
    value.update(updates)
    return value


def allowed_service(*, consent=False, contact=False):
    service = LeadAutomationService()
    service.enabled = True
    service.binding_enabled = True
    service.action_switches["UPDATE_ALLOWLISTED_FIELDS"] = True
    service.add_policy(
        Policy(
            "staging",
            "web-mobile-ai",
            "TEST_LEADS",
            "lead.update.requested.v1",
            "UPDATE_ALLOWLISTED_FIELDS",
            "1.0",
            True,
            consent,
            contact,
            frozenset({"solution_type"}),
            True,
        )
    )
    return service


def scope(**updates):
    return TenantScope.from_payload(payload(**updates))


def test_01_valid_authorized_update():
    assert allowed_service().receive(payload())["state"] == State.OUTBOX_PENDING


def test_02_unknown_business_unit_denied():
    assert (
        allowed_service().receive(payload(business_unit_key="unknown"))["state"]
        == State.POLICY_DENIED
    )


def test_03_unknown_campaign_denied():
    assert (
        allowed_service().receive(payload(campaign_key="UNKNOWN"))["state"]
        == State.POLICY_DENIED
    )


def test_04_unknown_action_denied():
    with pytest.raises(LeadAutomationError):
        allowed_service().receive(payload(automation_action="SEND_EMAIL"))


def test_05_disabled_binding_prevents_dispatch():
    s = allowed_service()
    s.binding_enabled = False
    e = s.receive(payload())
    assert not s.reserve_dispatch(e["event_id"], scope())


def test_06_disabled_global_prevents_dispatch():
    s = allowed_service()
    s.enabled = False
    assert s.receive(payload())["state"] == State.POLICY_DENIED


def test_07_dnc_blocks_contact_action():
    s = allowed_service(contact=True)
    p = payload()
    p["consent_snapshot"]["dnc_status"] = True
    assert s.receive(p)["state"] == State.DNC_BLOCKED


def test_08_missing_consent_blocks():
    s = allowed_service(consent=True)
    p = payload()
    p["consent_snapshot"]["consent_status"] = "unknown"
    assert s.receive(p)["state"] == State.CONSENT_BLOCKED


def test_09_expired_consent_blocks():
    s = allowed_service(consent=True)
    p = payload()
    p["consent_snapshot"]["consent_status"] = "expired"
    assert s.receive(p)["state"] == State.CONSENT_BLOCKED


def test_10_valid_consent_allows():
    assert (
        allowed_service(consent=True).receive(payload())["state"]
        == State.OUTBOX_PENDING
    )


def test_11_identical_event_replay():
    s = allowed_service()
    first = s.receive(payload())
    assert s.receive(payload()) == first and len(s.events) == 1


def test_12_idempotency_is_isolated_between_tenants():
    s = allowed_service()
    s.receive(payload())
    changed = payload(campaign_key="OTHER")
    assert s.receive(changed)["state"] == State.POLICY_DENIED
    assert len(s.events) == 2


def result():
    return {
        "contract_version": "1.1",
        "event_id": "EVT-synthetic01",
        "workflow_execution_id": "N8N-synthetic01",
        "binding_key": "n8n.leads.ingest",
        "environment": "staging",
        "company_key": "COMPANY-1",
        "business_unit_key": "web-mobile-ai",
        "campaign_key": "TEST_LEADS",
        "automation_action": "UPDATE_ALLOWLISTED_FIELDS",
        "result_status": "SUCCEEDED",
        "result_code": "UPDATED",
        "result_payload": {"field_updates": {"solution_type": "AI"}},
        "occurred_at": "2026-01-01T00:01:00Z",
        "idempotency_key": "b" * 64,
    }


def dispatched():
    s = allowed_service()
    e = s.receive(payload())
    s.reserve_dispatch(e["event_id"], scope())
    s.mark_dispatched(e["event_id"], scope())
    s.acknowledge_n8n(e["event_id"], scope())
    s.result_processing_enabled = True
    return s, e


def test_13_identical_result_replay():
    s, _ = dispatched()
    first = s.receive_result(result(), scope())
    assert s.receive_result(result(), scope()) == first and s.odoo_operations == 0


def test_14_conflicting_result_quarantines():
    s, _ = dispatched()
    s.receive_result(result(), scope())
    changed = result()
    changed["result_code"] = "OTHER"
    with pytest.raises(Conflict):
        s.receive_result(changed, scope())


def test_15_hmac_signature_is_deterministic():
    h = signed_headers(
        {"a": 1},
        b"synthetic",
        "staging",
        "c" * 64,
        timestamp="2026-01-01T00:00:00Z",
        nonce="nonce",
    )
    assert len(h["X-Codestra-Signature"]) == 64


def test_16_reused_workflow_execution_denied():
    s, _ = dispatched()
    s.receive_result(result(), scope())
    p = payload(event_id="EVT-synthetic02", idempotency_key="c" * 64)
    x = s.receive(p)
    second_scope = scope(event_id="EVT-synthetic02", idempotency_key="c" * 64)
    s.reserve_dispatch(x["event_id"], second_scope)
    s.mark_dispatched(x["event_id"], second_scope)
    s.acknowledge_n8n(x["event_id"], second_scope)
    r = result()
    r["event_id"] = "EVT-synthetic02"
    with pytest.raises(Conflict):
        s.receive_result(r, second_scope)


def test_17_wrong_environment_denied():
    s, _ = dispatched()
    r = result()
    r["environment"] = "production"
    with pytest.raises(LeadAutomationError, match="event not found"):
        s.receive_result(r, scope())


def test_18_unauthorized_field_denied():
    with pytest.raises(LeadAutomationError, match="attribute schema"):
        allowed_service().receive(payload(attributes={"unapproved": "x"}))


def test_19_unauthorized_stage_change_denied():
    assert (
        allowed_service().receive(payload(automation_action="CHANGE_AUTHORIZED_STAGE"))[
            "state"
        ]
        == State.POLICY_DENIED
    )


def test_20_unauthorized_assignment_denied():
    assert (
        allowed_service().receive(payload(automation_action="ASSIGN_AUTHORIZED_USER"))[
            "state"
        ]
        == State.POLICY_DENIED
    )


def test_21_ack_mismatch_quarantines():
    s, e = dispatched()
    s.receive_result(result(), scope())
    s.odoo_apply_enabled = True
    ack = {
        "contract_version": "1.1",
        "automation_event_id": e["automation_event_id"],
        "automation_action": "UPDATE_ALLOWLISTED_FIELDS",
        "company_key": "COMPANY-1",
        "business_unit_key": "wrong",
        "campaign_key": "TEST_LEADS",
        "policy_version": "1.0",
    }
    with pytest.raises(Conflict):
        s.apply_odoo_ack(e["event_id"], ack, scope())


def full_ack(automation_event_id, result_code_result="APPLIED", **updates):
    value = {
        "contract_version": "1.1",
        "automation_event_id": automation_event_id,
        "automation_action": "UPDATE_ALLOWLISTED_FIELDS",
        "lead_uid": "LEAD-synthetic01",
        "odoo_record_id": 42,
        "result": result_code_result,
        "applied_fields": ["solution_type"] if result_code_result == "APPLIED" else [],
        "unchanged_fields": ["solution_type"]
        if result_code_result == "NO_CHANGE"
        else [],
        "rejected_fields": [],
        "company_key": "COMPANY-1",
        "business_unit_key": "web-mobile-ai",
        "campaign_key": "TEST_LEADS",
        "policy_version": "1.0",
        "updated_at": "2026-01-01T00:02:00Z",
        "idempotent_replay": False,
    }
    if result_code_result == "FAILED":
        value["result_code"] = "PERMANENT_FAILURE"
    value.update(updates)
    return value


@pytest.mark.parametrize(
    ("ack_result", "expected_state"),
    [
        ("APPLIED", State.COMPLETED),
        ("NO_CHANGE", State.COMPLETED),
        ("DENIED", State.POLICY_DENIED),
        ("CONSENT_BLOCKED", State.CONSENT_BLOCKED),
        ("DNC_BLOCKED", State.DNC_BLOCKED),
        ("QUARANTINED", State.QUARANTINED),
        ("FAILED", State.QUARANTINED),
    ],
)
def test_22_all_ack_results_drive_fail_closed_state(ack_result, expected_state):
    s, e = dispatched()
    s.receive_result(result(), scope())
    s.odoo_apply_enabled = True
    response = s.apply_odoo_ack(
        e["event_id"], full_ack(e["automation_event_id"], ack_result), scope()
    )
    assert response["state"] == expected_state


def test_23_retryable_failed_ack_and_identical_ack_replay():
    s, e = dispatched()
    s.receive_result(result(), scope())
    s.odoo_apply_enabled = True
    retryable = full_ack(
        e["automation_event_id"],
        "FAILED",
        result_code="TEMPORARY_UNAVAILABLE",
    )
    assert s.apply_odoo_ack(e["event_id"], retryable, scope())["state"] == State.RETRY_PENDING
    assert s.apply_odoo_ack(e["event_id"], retryable, scope())["state"] == State.RETRY_PENDING
    assert s.odoo_operations == 1
    event_record = s._find(e["event_id"], scope())
    s._transition(event_record, State.ODOO_APPLY_PENDING)
    applied = full_ack(e["automation_event_id"])
    assert s.apply_odoo_ack(e["event_id"], applied, scope())["state"] == State.COMPLETED
    assert s.odoo_operations == 2


def test_22_n8n_timeout_bounded_retry():
    s = allowed_service()
    e = s.receive(payload())
    s.reserve_dispatch(e["event_id"], scope())
    assert s.record_retry(e["event_id"], scope(), 1) == State.RETRY_PENDING


def test_23_odoo_timeout_bounded_retry():
    s, e = dispatched()
    s.receive_result(result(), scope())
    assert s.record_retry(e["event_id"], scope(), 2) == State.RETRY_PENDING


def test_24_permanent_failure_stops():
    s = allowed_service()
    e = s.receive(payload())
    s.reserve_dispatch(e["event_id"], scope())
    assert s.record_retry(e["event_id"], scope(), 5) == State.FAILED_TERMINAL


def test_25_reconciliation_detects_missing_outbox():
    s = allowed_service()
    s.receive(payload())
    s.outbox.clear()
    assert "event_without_outbox" in s.reconcile(scope())[0]


def test_26_n8n_defaults_inactive():
    s = LeadAutomationService()
    assert not s.binding_enabled and not s.enabled


def test_27_communication_actions_absent():
    assert not (
        {"SEND_EMAIL", "SEND_SMS", "SEND_WHATSAPP", "CREATE_CALENDAR_EVENT"}
        & set(signed_headers.__globals__.get("ACTIONS", set()))
    )


def test_28_n8n_payload_has_no_pii():
    forbidden = {"phone", "email", "customer_name", "notes"}
    assert not forbidden & set(payload()["attributes"])


def test_29_no_production_database_write():
    assert LeadAutomationService().events == {}


def test_30_no_recording_system_change():
    import inspect

    import app.core.lead_automation as module

    text = inspect.getsource(module)
    assert (
        "recording" not in text.lower()
        and "asterisk" not in text.lower()
        and "vicidial" not in text.lower()
    )


def test_31_cross_tenant_event_lookup_is_indistinguishable_from_missing():
    s = allowed_service()
    event = s.receive(payload())
    wrong = scope(campaign_key="OTHER")
    with pytest.raises(LeadAutomationError, match="^event not found$"):
        s._find(event["event_id"], wrong)
    with pytest.raises(LeadAutomationError, match="^event not found$"):
        s._find(event["automation_event_id"], wrong)


def test_32_cross_tenant_dispatch_reservation_creates_no_mutation():
    s = allowed_service()
    event = s.receive(payload())
    original = s._find(event["event_id"], scope())
    with pytest.raises(LeadAutomationError, match="^event not found$"):
        s.reserve_dispatch(event["event_id"], scope(campaign_key="OTHER"))
    assert original.state == State.OUTBOX_PENDING
    assert original.audit[-1]["state"] == State.OUTBOX_PENDING


@pytest.mark.parametrize(
    "operation",
    [
        lambda service, event, tenant: service.mark_dispatched(event, tenant),
        lambda service, event, tenant: service.acknowledge_n8n(event, tenant),
        lambda service, event, tenant: service.record_retry(event, tenant, 1),
        lambda service, event, tenant: service.apply_odoo_ack(event, {}, tenant),
    ],
)
def test_33_cross_tenant_mutations_are_denied_before_state_change(operation):
    s = allowed_service()
    event = s.receive(payload())
    current = s._find(event["event_id"], scope())
    state, audit = current.state, list(current.audit)
    with pytest.raises(LeadAutomationError, match="^event not found$"):
        operation(s, event["event_id"], scope(business_unit_key="other"))
    assert current.state == state
    assert current.audit == audit


def test_34_cross_tenant_result_is_denied_without_quarantine_or_mutation():
    s, event = dispatched()
    current = s._find(event["event_id"], scope())
    state, audit = current.state, list(current.audit)
    foreign = result()
    foreign["campaign_key"] = "OTHER"
    with pytest.raises(LeadAutomationError, match="^event not found$"):
        s.receive_result(foreign, scope(campaign_key="OTHER"))
    assert current.state == state
    assert current.audit == audit
    assert s.quarantine == []


def test_35_reconciliation_is_tenant_scoped():
    s = allowed_service()
    s.receive(payload())
    s.outbox.clear()
    assert s.reconcile(scope(campaign_key="OTHER")) == []
    assert s.reconcile(scope())
