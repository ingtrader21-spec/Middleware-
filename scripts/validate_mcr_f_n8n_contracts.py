#!/usr/bin/env python3
"""Offline MCR-F contract conformance, never a runtime authorization service.

Principal and record are trusted test fixtures, not wire inputs. Production must
obtain them from JWT verification and a locked Middleware ledger transaction.
No persistence, JWT verification, dispatch or provider client is implemented here.
"""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "contracts/campaign-recycling"
PREFIX = "/platform/v1/automation/post-acceptance"
OPERATIONS = {
    "trigger": ("post", "/triggers", "TriggerRequest", "middleware-api", "workflow.trigger"),
    "result": ("post", "/results", "ResultRequest", "n8n-automation", "workflow.result.publish"),
    "readback": ("get", "/executions/{execution_id}", "ReadbackRequest", "middleware-api", "workflow.status.read"),
    "replay": ("post", "/dead-letters/{dead_letter_id}/replay", "ReplayRequest", "middleware-api", "automation.replay.request"),
}
BINDINGS = ["tenant_id", "correlation_id", "acceptance_id", "command_id", "lead_id", "campaign_id", "campaign_version", "workflow_key", "workflow_version"]


def load_contract():
    return json.loads((DIRECTORY / "post-acceptance-automation.v1.json").read_text())


def load_api():
    return json.loads((DIRECTORY / "post-acceptance-automation.openapi.json").read_text())


def examples():
    return json.loads((DIRECTORY / "post-acceptance-automation.examples.json").read_text())


def evaluate(operation, request, principal, record, previous=None):
    """Return the conformance outcome for an offline, synthetic ledger snapshot."""
    if operation not in OPERATIONS:
        return "INVALID_REQUEST"
    contract = load_contract()
    _, _, model, client, scope = OPERATIONS[operation]
    if not Draft202012Validator(load_api()["components"]["schemas"][model]).is_valid(request):
        return "INVALID_REQUEST"
    if not (
        principal.get("verified") is True
        and principal.get("expired") is False
        and principal.get("client_id") == client
        and scope in principal.get("scopes", [])
        and principal.get("tenant_id") == request["tenant_id"]
        and principal.get("issuer") == contract["authorization"]["issuer"]
        and principal.get("audience") == contract["authorization"]["audience"]
        and principal.get("environment") == "staging"
        and 0 < principal.get("token_lifetime_seconds", 0) <= 300
    ):
        return "UNAUTHORIZED"
    if record is None:
        return "NOT_FOUND" if operation == "readback" else "PRECONDITION_FAILED"
    if any(request.get(field) != record.get(field) for field in BINDINGS):
        return "BINDING_MISMATCH"
    if operation == "readback":
        return "ACCEPTED" if request["execution_id"] == record.get("execution_id") else "NOT_FOUND"
    # The fixture represents an existing reservation in the same tenant/operation.
    if previous is not None and previous.get("idempotency_key") == request["idempotency_key"]:
        return "DUPLICATE" if previous == request else "IDEMPOTENCY_CONFLICT"
    if operation in {"trigger", "replay"} and not (
        record.get("durable") is True
        and record.get("status") == "ACCEPTED"
        and record.get("lifecycle_state") in contract["preconditions"]["lifecycle_states"]
        and record.get("lifecycle_version") == request["lifecycle_version"]
        and record.get("suppressed") is False
        and record.get("policy_current") is True
    ):
        return "PRECONDITION_FAILED"
    if operation == "result" and not (
        record.get("durable") is True
        and record.get("status") == "ACCEPTED"
        and record.get("lease_valid") is True
        and record.get("job_state") in {"CLAIMED", "RUNNING"}
        and all(request[k] == record.get(k) for k in ("execution_id", "lease_id", "attempt", "lifecycle_version"))
    ):
        return "RESULT_CONFLICT"
    if operation == "replay" and not (
        record.get("job_state") == "DEAD_LETTER"
        and record.get("outcome_known") is True
        and record.get("reconciled") is True
        and record.get("operator_approved") is True
        and record.get("retry_budget_remaining", 0) > 0
        and all(request[k] == record.get(k) for k in ("dead_letter_id", "approval_id"))
    ):
        return "REPLAY_DENIED"
    return "ACCEPTED"


def retry_decision(category, attempt):
    """Middleware retry policy oracle, not a scheduler."""
    if type(attempt) is not int or not 1 <= attempt <= 3:
        return {"state": "DEAD_LETTER", "delay_seconds": None}
    if category == "UNKNOWN":
        return {"state": "UNKNOWN", "delay_seconds": None}
    if category != "TRANSIENT_BEFORE_EFFECT" or attempt >= 3:
        return {"state": "DEAD_LETTER", "delay_seconds": None}
    return {"state": "RETRY_SCHEDULED", "delay_seconds": [30, 120][attempt - 1]}


def validate(contract=None, api=None):
    contract = load_contract() if contract is None else contract
    api = load_api() if api is None else api
    errors = []

    def check(condition, message):
        if not condition:
            errors.append(message)

    check(contract.get("runtime_status") == "contract_only", "runtime must remain contract-only")
    safety = contract.get("release_safety", {})
    check(set(safety) == {"workflows_active", "external_effects_enabled", "runtime_deployment_authorized", "production_promotion_authorized"} and all(value is False for value in safety.values()), "release gate must remain closed")
    check(contract.get("binding_fields") == BINDINGS, "immutable binding fields drifted")
    for field in ("authority", "lifecycle", "ledger", "operation_policy"):
        check((ROOT / contract.get(field, "missing")).is_file(), f"missing authority: {field}")
    lifecycle = json.loads((DIRECTORY / "lifecycle.v1.schema.json").read_text())
    check(contract["preconditions"]["lifecycle_states"] == lifecycle["x-lifecycle"]["engine_contactable"], "lifecycle states drifted")
    for field in ("durable_acceptance_required", "current_policy_required", "suppression_blocks", "lifecycle_version_must_match"):
        check(contract["preconditions"].get(field) is True, f"unsafe precondition: {field}")
    check(contract["preconditions"].get("acceptance_status") == "ACCEPTED", "acceptance required")
    for field in ("provider_calls", "direct_database_writes", "eligibility_override", "suppression_override", "sender_identity_selection"):
        check(contract["no_bypass"].get(field) is False, f"bypass permitted: {field}")
    retry = contract["retry"]
    check(retry["owner"] == "middleware" and retry["automatic_n8n_retry"] is False, "retry ownership drift")
    check(retry["max_attempts"] == 3 and retry["backoff_seconds"] == [30, 120] and retry["retryable"] == ["TRANSIENT_BEFORE_EFFECT"], "retry budget drift")
    check(retry["unknown_outcome"] == "WAIT_FOR_RECONCILIATION_NO_RETRY", "unknown outcomes cannot retry")
    check(contract.get("result", {}).get("terminal_immutable") is True, "terminal results must remain immutable")
    check(contract.get("readback", {}).get("cross_tenant_http_status") == 404, "cross-tenant readback must be 404")
    check(contract.get("idempotency", {}).get("conflict_http_status") == 409, "idempotency conflicts must be 409")
    check(api.get("openapi") == "3.1.0" and api.get("x-runtime-status") == "contract_only", "OpenAPI version/status")
    check({(method, path) for path, item in api["paths"].items() for method in item} == {(v[0], PREFIX + v[1]) for v in OPERATIONS.values()}, "endpoint set drift")
    for operation, (method, suffix, model, client, scope) in OPERATIONS.items():
        entry = api["paths"].get(PREFIX + suffix, {}).get(method, {})
        check(entry.get("security") == [{"codestraOAuth": [scope]}], f"{operation}: scopes")
        check(entry.get("x-authorized-client") == client, f"{operation}: client")
        check(contract["authorization"]["operations"].get(operation) == {"client": client, "scope": scope}, f"{operation}: auth contract drift")
        check(entry.get("x-effects") == "none", f"{operation}: effect bypass")
        check(entry.get("x-request-schema") == model, f"{operation}: schema")
        refs = {v.get("$ref") for v in entry.get("parameters", [])}
        for name in ["TenantId", "CorrelationId", "CausationId"] + (["IdempotencyKey"] if method == "post" else []):
            check("#/components/parameters/" + name in refs, f"{operation}: missing {name}")
        check({"200", "401", "403", "404", "409", "422", "503"} <= set(entry.get("responses", {})), f"{operation}: responses")
    for name, schema in api["components"]["schemas"].items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
        check(schema.get("additionalProperties") is False, f"{name}: open input")
        check(set(schema.get("required", [])) == set(schema.get("properties", {})), f"{name}: optional binding")
    # Resolve every internal OpenAPI reference offline.
    def walk(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                target = api
                try:
                    if not ref.startswith("#/"):
                        raise KeyError(ref)
                    for part in ref[2:].split("/"):
                        target = target[part]
                except (KeyError, TypeError):
                    errors.append(f"unresolved reference: {ref}")
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(api)
    return errors


if __name__ == "__main__":
    failures = validate()
    for failure in failures:
        print(f"MCR_F_ERROR={failure}")
    if failures:
        raise SystemExit(1)
    for operation, case in examples().items():
        outcome = evaluate(operation, **case)
        if outcome != "ACCEPTED":
            raise SystemExit(f"MCR_F_EXAMPLE_ERROR={operation}:{outcome}")
    print("MCR_F_CONTRACTS=PASS")
    print("MCR_F_LOCAL_STAGING_PROFILE=PASS; PROTECTED_STAGING=NOT_RUN; EXTERNAL_EFFECTS=NONE; RELEASE=NO_GO")
