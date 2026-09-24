from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from workflow_contract import (
    ConflictingReplay,
    ContractRejected,
    SyntheticMiddlewareStub,
    WorkflowHarness,
    mutate,
    sign_result,
    validate_event,
    validate_result,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "lead-automation-generic-v1.json"
BINDING = ROOT / "binding-registration-v1.json"
MANIFEST = ROOT / "workflow-manifest-v1.json"
PROVENANCE = ROOT / "schemas" / "provenance-manifest-v1.json"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: UP017 -- Python 3.10 CI


def event(
    event_type: str = "lead.update.requested.v1",
    action: str = "UPDATE_ALLOWLISTED_FIELDS",
) -> dict:
    value = {
        "contract_version": "1.0",
        "event_id": "EVT-SYNTHETIC0001",
        "event_type": event_type,
        "occurred_at": NOW.isoformat(),
        "environment": "staging",
        "business_unit_key": "web-mobile-ai",
        "campaign_key": "SYNTHETIC_CAMPAIGN",
        "automation_action": action,
        "idempotency_key": "a" * 64,
        "correlation_id": "00000000-0000-4000-8000-000000000001",
        "policy_version": "synthetic-v1",
        "lead_uid": "LEAD-SYNTHETIC0001",
        "attributes_schema_key": "web-mobile-ai-lead-v1",
        "attributes": {
            "contact_reference": "CONTACT-SYNTHETIC0001",
            "solution_type": "AI",
            "company_size_band": "SMALL",
        },
        "consent_snapshot": {
            "consent_status": "granted",
            "consent_purpose": "LEAD_SERVICE",
            "consent_source": "odoo",
            "consent_updated_at": NOW.isoformat(),
            "dnc_status": False,
            "dnc_updated_at": NOW.isoformat(),
            "jurisdiction": "DO",
            "source_system": "odoo",
        },
    }
    if event_type == "lead.creation.requested.v1":
        value.pop("lead_uid")
        value["source_reference"] = "SRC-SYNTHETIC0001"
    return value


def prepared_callback():
    harness = WorkflowHarness()
    value = event()
    harness.process(value)
    body, headers = harness.callback(value)
    return harness, value, body, headers


def test_01_workflow_json_import_shape():
    workflow = json.loads(WORKFLOW.read_text())
    assert workflow["name"] == "lead-automation-generic-v1"
    assert workflow["connections"] and workflow["nodes"]


def test_02_workflow_inactive_default():
    workflow = json.loads(WORKFLOW.read_text())
    assert workflow["active"] is False
    assert all(node["disabled"] is True for node in workflow["nodes"])


def test_03_binding_and_global_switch_disabled():
    binding = json.loads(BINDING.read_text())
    assert binding["enabled"] is False
    assert binding["lead_automation_enabled"] is False


@pytest.mark.parametrize(
    ("event_type", "action"),
    [
        ("lead.creation.requested.v1", "CREATE_LEAD"),
        ("lead.update.requested.v1", "UPDATE_ALLOWLISTED_FIELDS"),
        ("lead.assignment.requested.v1", "ASSIGN_AUTHORIZED_TEAM"),
        ("lead.assignment.requested.v1", "ASSIGN_AUTHORIZED_USER"),
        ("lead.status_change.requested.v1", "CHANGE_AUTHORIZED_STAGE"),
        ("lead.callback_requested.v1", "CREATE_INTERNAL_CALLBACK_ACTIVITY"),
    ],
)
def test_04_to_09_valid_supported_events(event_type, action):
    value = event(event_type, action)
    validate_event(value)
    ack = WorkflowHarness().process(value)
    assert ack["accepted"] is True and "lead_uid" not in ack


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.__setitem__("contract_version", "2.0"),
        lambda e: e.__setitem__("environment", "production"),
        lambda e: e.__setitem__("event_type", "lead.email.requested.v1"),
        lambda e: e.__setitem__("automation_action", "CREATE_LEAD"),
        lambda e: e.__setitem__("business_unit_key", "UNKNOWN_UNIT"),
        lambda e: e.__setitem__("campaign_key", "bad campaign"),
        lambda e: e.__setitem__("occurred_at", "not-a-time"),
        lambda e: e.__setitem__("event_id", "bad"),
        lambda e: e.__setitem__("idempotency_key", "bad"),
        lambda e: e.__setitem__("policy_version", "x" * 33),
        lambda e: e.__setitem__("attributes_schema_key", "unknown-lead-v1"),
        lambda e: e.__setitem__("unknown", True),
        lambda e: e.pop("campaign_key"),
        lambda e: e["attributes"].__setitem__("unknown_field", "x"),
        lambda e: e["attributes"].__setitem__("solution_type", "UNKNOWN"),
        lambda e: e["attributes"].__setitem__("contact_reference", "x" * 200),
        lambda e: e["consent_snapshot"].__setitem__("consent_status", "invalid"),
        lambda e: e["consent_snapshot"].__setitem__("extra", True),
    ],
)
def test_10_to_27_invalid_contract_inputs_rejected(change):
    with pytest.raises(ContractRejected):
        validate_event(mutate(event(), change))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("phone_number", "synthetic-prohibited"),
        ("email_address", "synthetic-prohibited"),
        ("customer_name", "synthetic-prohibited"),
        ("unrestricted_notes", "synthetic-prohibited"),
        ("credential", "synthetic-prohibited"),
        ("recording_url", "synthetic-prohibited"),
        ("object_key", "synthetic-prohibited"),
        ("presigned_url", "synthetic-prohibited"),
    ],
)
def test_28_to_35_nested_prohibited_fields_rejected(key, value):
    candidate = event()
    candidate["attributes"]["nested"] = {key: value}
    with pytest.raises(ContractRejected, match="prohibited"):
        validate_event(candidate)


@pytest.mark.parametrize("value", ["synthetic@example.invalid", "+19995550123"])
def test_36_to_37_raw_contact_values_rejected(value):
    candidate = event()
    candidate["attributes"]["contact_reference"] = value
    with pytest.raises(ContractRejected):
        validate_event(candidate)


def test_38_identical_ingress_replay_is_deterministic_without_callback():
    harness = WorkflowHarness()
    value = event()
    first = harness.process(value)
    second = harness.process(deepcopy(value))
    assert first == second and harness.callback_count == 1


def test_39_conflicting_ingress_replay_rejected():
    harness = WorkflowHarness()
    value = event()
    harness.process(value)
    conflicting = deepcopy(value)
    conflicting["attributes"]["solution_type"] = "WEB"
    with pytest.raises(ConflictingReplay):
        harness.process(conflicting)


def test_40_valid_callback_authentication_and_result_schema():
    harness, value, body, headers = prepared_callback()
    stub = SyntheticMiddlewareStub(harness.secret)
    assert stub.accept(body, headers, now=NOW)["accepted"] is True
    result = json.loads(body)
    assert result["business_unit_key"] == value["business_unit_key"]
    assert result["campaign_key"] == value["campaign_key"]
    assert result["automation_action"] == value["automation_action"]


@pytest.mark.parametrize(
    ("kind", "replacement"),
    [
        ("method", "GET"),
        ("path", "/api/v1/lead-automation/other"),
        ("query", "next=other"),
        ("body", b'{"environment":"staging","changed":true}'),
        ("Idempotency-Key", "b" * 64),
        ("X-Service-Identity", "wrong"),
        ("X-Service-Audience", "wrong"),
        ("X-Codestra-Environment", "production"),
        ("X-Codestra-Signature-Version", "HMAC-V1"),
        ("X-Codestra-Scope", "lead-automation.odoo-apply.write"),
        ("X-Codestra-Signature", "0" * 64),
    ],
)
def test_41_to_49_callback_tampering_denied(kind, replacement):
    harness, _value, body, headers = prepared_callback()
    stub = SyntheticMiddlewareStub(harness.secret)
    kwargs = {"now": NOW}
    if kind in {"method", "path", "query"}:
        kwargs[kind] = replacement
    elif kind == "body":
        body = replacement
    else:
        headers[kind] = replacement
    with pytest.raises(ContractRejected):
        stub.accept(body, headers, **kwargs)
    assert stub.transitions == 0


def test_50_expired_timestamp_denied():
    harness, _value, body, headers = prepared_callback()
    with pytest.raises(ContractRejected, match="timestamp"):
        SyntheticMiddlewareStub(harness.secret).accept(
            body, headers, now=NOW + timedelta(seconds=301)
        )


def test_51_reused_nonce_denied():
    harness, _value, body, headers = prepared_callback()
    stub = SyntheticMiddlewareStub(harness.secret)
    stub.accept(body, headers, now=NOW)
    with pytest.raises(ContractRejected, match="nonce"):
        stub.accept(body, headers, now=NOW)


def test_52_identical_result_replay_uses_new_nonce_and_no_transition():
    harness, value, body, headers = prepared_callback()
    stub = SyntheticMiddlewareStub(harness.secret)
    stub.accept(body, headers, now=NOW)
    replay_headers = sign_result(
        body,
        secret=harness.secret,
        timestamp=NOW.isoformat(),
        nonce="synthetic-distinct-replay-nonce",
        idempotency_key=value["idempotency_key"],
    )
    assert stub.accept(body, replay_headers, now=NOW)["idempotent_replay"] is True
    assert stub.transitions == 1


def test_53_conflicting_result_replay_quarantinable():
    harness, value, body, headers = prepared_callback()
    stub = SyntheticMiddlewareStub(harness.secret)
    stub.accept(body, headers, now=NOW)
    changed = json.loads(body)
    changed["result_code"] = "OTHER"
    changed_body = json.dumps(changed, separators=(",", ":")).encode()
    changed_headers = sign_result(
        changed_body,
        secret=harness.secret,
        timestamp=NOW.isoformat(),
        nonce="synthetic-conflict-nonce",
        idempotency_key=value["idempotency_key"],
    )
    with pytest.raises(ConflictingReplay):
        stub.accept(changed_body, changed_headers, now=NOW)
    assert stub.transitions == 1


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([429, 200], 2),
        ([503, 503, 200], 3),
        ([401, 200], 1),
        ([422, 200], 1),
        ([503, 503, 503, 503, 503, 200], 5),
    ],
)
def test_54_to_58_bounded_retry_classification(statuses, expected):
    assert WorkflowHarness.attempts(statuses) == expected


def test_59_node_allowlist_and_prohibited_counts():
    workflow = json.loads(WORKFLOW.read_text())
    manifest = json.loads(MANIFEST.read_text())
    allowed = set(manifest["node_type_allowlist"])
    types = [node["type"] for node in workflow["nodes"]]
    assert set(types) <= allowed
    prohibited = ("odoo", "postgres", "mysql", "email", "twilio", "whatsapp", "calendar")
    assert not [node for node in workflow["nodes"] if any(x in node["type"].lower() for x in prohibited)]


def test_60_only_fixed_middleware_callback_target():
    workflow = json.loads(WORKFLOW.read_text())
    http_nodes = [node for node in workflow["nodes"] if node["type"] == "n8n-nodes-base.httpRequest"]
    assert len(http_nodes) == 1
    assert http_nodes[0]["parameters"]["url"] == (
        "={{ $env.MIDDLEWARE_INTERNAL_URL + '/api/v1/lead-automation/results' }}"
    )


def test_61_no_real_workflow_or_credential_id():
    manifest = json.loads(MANIFEST.read_text())
    assert manifest["workflow_id"] is None and manifest["credential_id"] is None


def test_62_schema_provenance_hashes_match_bytes():
    provenance = json.loads(PROVENANCE.read_text())
    assert provenance["source_head_sha"] == "da215762375614aa617bf838f9e4974ac2ad7c68"
    for item in provenance["schema_files"]:
        actual = hashlib.sha256((ROOT / "schemas" / item["schema_filename"]).read_bytes()).hexdigest()
        assert actual == item["schema_sha256"]


def test_63_acknowledgement_does_not_claim_odoo_application():
    ack = WorkflowHarness().process(event())
    assert set(ack) == {
        "contract_version",
        "event_id",
        "accepted",
        "result_code",
        "correlation_id",
        "occurred_at",
    }
    assert "odoo" not in json.dumps(ack).lower()


def test_64_result_cannot_modify_scope_consent_or_dnc():
    harness = WorkflowHarness()
    value = event()
    harness.process(value)
    body, _headers = harness.callback(value)
    result = json.loads(body)
    assert result["business_unit_key"] == value["business_unit_key"]
    assert result["campaign_key"] == value["campaign_key"]
    assert result["automation_action"] == value["automation_action"]
    assert not ({"consent_snapshot", "dnc_status", "company", "policy_version"} & set(result))


def test_65_unauthorized_result_payload_field_rejected():
    harness = WorkflowHarness()
    value = event()
    harness.process(value)
    body, _headers = harness.callback(value)
    result = json.loads(body)
    result["result_payload"]["unauthorized"] = True
    with pytest.raises(ContractRejected, match="allowlist"):
        validate_result(result)
