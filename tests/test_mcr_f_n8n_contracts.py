"""Offline conformance; these tests do not claim deployed enforcement."""
from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator

from scripts import validate_mcr_f_n8n_contracts as mcr


def test_contract_and_openapi_are_valid():
    assert mcr.validate() == []


@pytest.mark.parametrize("operation", ["trigger", "result", "readback", "replay"])
def test_canonical_examples(operation):
    case = mcr.examples()[operation]
    assert mcr.evaluate(operation, **case) == "ACCEPTED"


@pytest.mark.parametrize("operation", ["trigger", "result", "readback", "replay"])
@pytest.mark.parametrize("field,value,reason", [
    ("tenant_id", "other", "UNAUTHORIZED"),
    ("correlation_id", "other", "BINDING_MISMATCH"),
    ("command_id", "other", "BINDING_MISMATCH"),
    ("acceptance_id", "other", "BINDING_MISMATCH"),
    ("workflow_key", "other", "BINDING_MISMATCH"),
    ("workflow_version", "other", "BINDING_MISMATCH"),
])
def test_identity_cannot_be_rebound(operation, field, value, reason):
    case = mcr.examples()[operation]
    case["request"][field] = value
    assert mcr.evaluate(operation, **case) == reason


@pytest.mark.parametrize("operation", ["trigger", "result", "readback", "replay"])
@pytest.mark.parametrize("mutation", ["anonymous", "wrong_client", "wrong_scope", "wrong_tenant", "expired", "wrong_audience", "wrong_issuer"])
def test_authentication_and_scope_fail_closed(operation, mutation):
    case = mcr.examples()[operation]
    changes = {
        "anonymous": {"verified": False}, "wrong_client": {"client_id": "provider"},
        "wrong_scope": {"scopes": ["automation.execute"]},
        "wrong_tenant": {"tenant_id": "other"}, "expired": {"expired": True},
        "wrong_audience": {"audience": "n8n"}, "wrong_issuer": {"issuer": "untrusted"},
    }
    case["principal"].update(changes[mutation])
    assert mcr.evaluate(operation, **case) == "UNAUTHORIZED"


@pytest.mark.parametrize("state", ["NEW", "VALIDATED", "COOLING", "CONVERTED", "SUPPRESSED"])
def test_unaccepted_lifecycle_cannot_trigger(state):
    case = mcr.examples()["trigger"]
    case["record"]["lifecycle_state"] = state
    assert mcr.evaluate("trigger", **case) == "PRECONDITION_FAILED"


@pytest.mark.parametrize("field,value", [
    ("status", "PLANNED"), ("durable", False), ("suppressed", True),
    ("policy_current", False), ("lifecycle_version", 2),
])
def test_persisted_acceptance_is_required(field, value):
    case = mcr.examples()["trigger"]
    case["record"][field] = value
    assert mcr.evaluate("trigger", **case) == "PRECONDITION_FAILED"


@pytest.mark.parametrize("operation", ["trigger", "result", "replay"])
def test_exact_duplicate_and_conflicting_reuse(operation):
    case = mcr.examples()[operation]
    case["previous"] = deepcopy(case["request"])
    assert mcr.evaluate(operation, **case) == "DUPLICATE"
    case["request"]["causation_id"] = "changed"
    assert mcr.evaluate(operation, **case) == "IDEMPOTENCY_CONFLICT"


@pytest.mark.parametrize("state", ["UNKNOWN", "RUNNING", "COMPLETED", "RETRY_SCHEDULED"])
def test_replay_only_for_safe_dead_letters(state):
    case = mcr.examples()["replay"]
    case["record"]["job_state"] = state
    assert mcr.evaluate("replay", **case) == "REPLAY_DENIED"


@pytest.mark.parametrize("field,value", [
    ("outcome_known", False), ("reconciled", False), ("operator_approved", False),
    ("retry_budget_remaining", 0), ("suppressed", True),
])
def test_replay_rechecks_current_authority(field, value):
    case = mcr.examples()["replay"]
    case["record"][field] = value
    assert mcr.evaluate("replay", **case) in {"REPLAY_DENIED", "PRECONDITION_FAILED"}


def test_result_lease_and_terminal_conflict():
    case = mcr.examples()["result"]
    case["record"]["lease_valid"] = False
    assert mcr.evaluate("result", **case) == "RESULT_CONFLICT"
    case = mcr.examples()["result"]
    case["record"]["job_state"] = "COMPLETED"
    assert mcr.evaluate("result", **case) == "RESULT_CONFLICT"


@pytest.mark.parametrize("operation", ["trigger", "result", "readback", "replay"])
def test_no_client_provider_or_acceptance_override(operation):
    case = mcr.examples()[operation]
    for field in ("provider_url", "credentials", "accepted", "suppression_override", "actions"):
        malicious = deepcopy(case)
        malicious["request"][field] = True
        assert mcr.evaluate(operation, **malicious) == "INVALID_REQUEST"


def test_schema_and_api_mutations_are_detected():
    document = mcr.load_contract()
    document["release_safety"]["workflows_active"] = True
    assert mcr.validate(contract=document)
    api = mcr.load_api()
    api["paths"][mcr.PREFIX + "/triggers"]["post"]["security"] = []
    assert mcr.validate(api=api)


def test_all_wire_schemas_are_closed():
    for schema in mcr.load_api()["components"]["schemas"].values():
        Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False


@pytest.mark.parametrize("category,attempt,state,delay", [
    ("TRANSIENT_BEFORE_EFFECT", 1, "RETRY_SCHEDULED", 30),
    ("TRANSIENT_BEFORE_EFFECT", 2, "RETRY_SCHEDULED", 120),
    ("TRANSIENT_BEFORE_EFFECT", 3, "DEAD_LETTER", None),
    ("UNKNOWN", 1, "UNKNOWN", None),
    ("UNKNOWN", 3, "UNKNOWN", None),
    ("PERMANENT", 1, "DEAD_LETTER", None),
    ("unrecognized", 1, "DEAD_LETTER", None),
    ("TRANSIENT_BEFORE_EFFECT", 0, "DEAD_LETTER", None),
])
def test_retry_and_dead_letter_policy(category, attempt, state, delay):
    assert mcr.retry_decision(category, attempt) == {"state": state, "delay_seconds": delay}


@pytest.mark.parametrize("operation", ["trigger", "result", "readback", "replay"])
def test_absent_authority_fails_closed(operation):
    case = mcr.examples()[operation]
    case["record"] = None
    assert mcr.evaluate(operation, **case) in {"PRECONDITION_FAILED", "NOT_FOUND"}
    case = mcr.examples()[operation]
    case["principal"] = {}
    assert mcr.evaluate(operation, **case) == "UNAUTHORIZED"


@pytest.mark.parametrize("field", mcr.BINDINGS + ["lifecycle_version", "causation_id"])
def test_missing_trigger_identity_is_invalid(field):
    case = mcr.examples()["trigger"]
    del case["request"][field]
    assert mcr.evaluate("trigger", **case) == "INVALID_REQUEST"


@pytest.mark.parametrize("field", ["execution_id", "lease_id", "attempt"])
def test_result_cannot_change_execution_or_lease(field):
    case = mcr.examples()["result"]
    case["request"][field] = 2 if field == "attempt" else "other"
    assert mcr.evaluate("result", **case) == "RESULT_CONFLICT"


def test_exact_result_retry_after_completion_returns_original():
    case = mcr.examples()["result"]
    case["previous"] = deepcopy(case["request"])
    case["record"].update(job_state="COMPLETED", lease_valid=False)
    assert mcr.evaluate("result", **case) == "DUPLICATE"
    case["request"]["result_hash"] = "b" * 64
    assert mcr.evaluate("result", **case) == "IDEMPOTENCY_CONFLICT"


def test_no_effect_staging_profile_has_no_network_or_fixture_mutation(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("network access forbidden in offline staging evidence")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    cases = mcr.examples()
    original = deepcopy(cases)
    for operation, case in cases.items():
        assert mcr.evaluate(operation, **case) == "ACCEPTED"
    assert cases == original


@pytest.mark.parametrize("section,field,value", [
    ("preconditions", "suppression_blocks", False),
    ("preconditions", "durable_acceptance_required", False),
    ("no_bypass", "provider_calls", True),
    ("retry", "automatic_n8n_retry", True),
    ("retry", "unknown_outcome", "RETRY"),
    ("result", "terminal_immutable", False),
    ("readback", "cross_tenant_http_status", 200),
    ("idempotency", "conflict_http_status", 200),
])
def test_safety_contract_mutations_fail_validation(section, field, value):
    contract = mcr.load_contract()
    contract[section][field] = value
    assert mcr.validate(contract=contract)
