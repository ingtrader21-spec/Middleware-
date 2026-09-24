from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/security/validate-security-owner-decision.py"
SPEC = importlib.util.spec_from_file_location("security_decision", MODULE_PATH)
assert SPEC and SPEC.loader
security_decision = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_decision)
ValidationError = security_decision.ValidationError

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)  # noqa: UP017
SHA_A = "a" * 40
SHA_B = "b" * 40
HASH_A = "a" * 64
DIGEST_A = "sha256:" + "a" * 64


def manifest() -> dict:
    return {"image_digests": {"middleware": DIGEST_A}, "findings": []}


def request() -> dict:
    image_manifest = manifest()
    return {
        "schema_version": "1.0.0",
        "request_type": "security_owner_staging_preparation",
        "repository": "ingtrader21-spec/Middleware-",
        "pr_number": 68,
        "pr_head_sha": SHA_A,
        "middleware_main_sha": SHA_B,
        "odoo_main_sha": SHA_A,
        "created_at_utc": "2026-08-01T12:00:00Z",
        "requested_expiration_utc": "2026-08-15T12:00:00Z",
        "approved_scope": "server_a_isolated_staging",
        "image_manifest_sha256": security_decision.sha256_bytes(
            security_decision.canonical_bytes(image_manifest)
        ),
        "image_digests": {"middleware": DIGEST_A},
        "vulnerability_findings": [],
        "compensating_controls": ["private network"],
        "odoo_isolation_evidence": {"gate": "PASS", "sha256": HASH_A},
        "middleware_isolation_evidence": {"gate": "PASS", "sha256": HASH_A},
        "limitations": [],
        "negative_authorizations": {
            key: "blocked" for key in security_decision.NEGATIVE_KEYS
        },
        "revocation_conditions": ["digest change"],
    }


def validate(value: dict | None = None, image_manifest: dict | None = None) -> None:
    security_decision.validate_request(
        value or request(),
        image_manifest or manifest(),
        repository="ingtrader21-spec/Middleware-",
        pr_number=68,
        pr_head=SHA_A,
        now=NOW,
    )


def test_valid_request() -> None:
    validate()


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "wrong/repository"),
        ("pr_number", 69),
        ("pr_head_sha", SHA_B),
        ("approved_scope", "production"),
    ],
)
def test_identity_claims_rejected(field: str, value: object) -> None:
    candidate = request()
    candidate[field] = value
    with pytest.raises(ValidationError):
        validate(candidate)


def test_closed_pr_is_workflow_api_gate() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-decision-sign.yml").read_text()
    assert 'test "$(jq -r .state pull-request.json)" = open' in workflow


def test_pending_ci_is_workflow_api_gate() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-decision-sign.yml").read_text()
    assert '"codestra/required-ci" and .state == "success"' in workflow


def test_wrong_request_hash_rejected() -> None:
    candidate = request()
    candidate["image_manifest_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        validate(candidate)


def test_wrong_manifest_digest_rejected() -> None:
    candidate_manifest = manifest()
    candidate_manifest["image_digests"]["middleware"] = "sha256:" + "b" * 64
    with pytest.raises(ValidationError):
        validate(image_manifest=candidate_manifest)


@pytest.mark.parametrize(
    "field", ["odoo_isolation_evidence", "middleware_isolation_evidence"]
)
def test_missing_isolation_evidence_rejected(field: str) -> None:
    candidate = request()
    candidate[field]["gate"] = "PENDING"
    with pytest.raises(ValidationError):
        validate(candidate)


def test_missing_environment_approval_rejected() -> None:
    audit = {"approver": "kazan555", "self_review": True, "bypass_used": False}
    with pytest.raises(ValidationError):
        security_decision.validate_decision(decision(), request(), audit)


def test_workflow_requires_exact_environment_review_history() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-decision-sign.yml").read_text()
    assert 'actions/runs/${GITHUB_RUN_ID}/approvals' in workflow
    assert '.user.login == "kazan555"' in workflow
    assert 'any(.environments[]?; .name == "security-owner-signing")' in workflow
    assert 'if length == 1' in workflow


def test_unallowlisted_approver_rejected() -> None:
    candidate = decision()
    candidate["security_owner_approver_login"] = "other"
    with pytest.raises(ValidationError):
        security_decision.validate_decision(candidate, request(), audit())


def test_bypass_rejected() -> None:
    candidate_audit = audit()
    candidate_audit["bypass_used"] = True
    with pytest.raises(ValidationError):
        security_decision.validate_decision(decision(), request(), candidate_audit)


@pytest.mark.parametrize(
    "created,expires",
    [
        ("2026-08-01T12:00:00Z", "2026-07-31T12:00:00Z"),
        ("2026-08-01T12:00:00Z", "2026-09-01T12:00:01Z"),
    ],
)
def test_invalid_expiry_rejected(created: str, expires: str) -> None:
    candidate = request()
    candidate["created_at_utc"] = created
    candidate["requested_expiration_utc"] = expires
    with pytest.raises(ValidationError):
        validate(candidate)


@pytest.mark.parametrize(
    "gate", ["production_deployment_gate", "server_b_access_gate", "customer_data_gate"]
)
def test_negative_authorization_cannot_be_allowed(gate: str) -> None:
    candidate = request()
    candidate["negative_authorizations"][gate] = "allowed"
    with pytest.raises(ValidationError):
        validate(candidate)


def test_unknown_property_rejected() -> None:
    candidate = request()
    candidate["unexpected"] = True
    with pytest.raises(ValidationError):
        validate(candidate)


def test_pr_controlled_code_is_not_executed() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-decision-sign.yml").read_text()
    assert "ref: ${{ github.sha }}" in workflow
    assert "python scripts/security/validate-security-owner-decision.py" in workflow
    assert "source " not in workflow
    assert "pull_request_target" not in workflow


def test_workflow_identity_is_exact() -> None:
    script = (ROOT / "scripts/security/verify-security-owner-decision.sh").read_text()
    assert "security-owner-decision-sign.yml@refs/heads/main" in script
    assert "certificate-identity-regexp" not in script


def test_oidc_issuer_is_exact() -> None:
    script = (ROOT / "scripts/security/verify-security-owner-decision.sh").read_text()
    assert any(
        line == "issuer='https://token.actions.githubusercontent.com'"
        for line in script.splitlines()
    )
    assert "certificate-oidc-issuer-regexp" not in script


def test_altered_request_invalidates_decision() -> None:
    altered = request()
    altered["limitations"] = ["changed"]
    with pytest.raises(ValidationError):
        security_decision.validate_decision(decision(), altered, audit())


def audit() -> dict:
    return {"approver": "kazan555", "self_review": False, "bypass_used": False}


def decision() -> dict:
    req = request()
    return {
        "schema_version": "1.0.0",
        "decision_status": "approved_for_staging_preparation",
        "decision_request_sha256": security_decision.sha256_bytes(
            security_decision.canonical_bytes(req)
        ),
        "repository": req["repository"],
        "pr_number": req["pr_number"],
        "pr_head_sha": req["pr_head_sha"],
        "middleware_main_sha": req["middleware_main_sha"],
        "odoo_main_sha": req["odoo_main_sha"],
        "approved_scope": req["approved_scope"],
        "approved_image_digests": req["image_digests"],
        "accepted_vulnerability_findings": req["vulnerability_findings"],
        "compensating_controls_sha256": security_decision.sha256_bytes(
            security_decision.canonical_bytes(req["compensating_controls"])
        ),
        "odoo_isolation_evidence_sha256": HASH_A,
        "middleware_isolation_evidence_sha256": HASH_A,
        "security_owner_approver_login": "kazan555",
        "security_owner_authority_reference": "SECURITY.md#isolated-staging-security-owner",
        "environment_name": "security-owner-signing",
        "environment_approval_record_id": "deployment:1",
        "workflow_repository": "ingtrader21-spec/Middleware-",
        "workflow_path": ".github/workflows/security-owner-decision-sign.yml",
        "workflow_ref": "refs/heads/main",
        "workflow_sha": SHA_B,
        "workflow_run_id": "1",
        "workflow_run_attempt": "1",
        "signed_at_utc": "2026-08-01T12:00:00Z",
        "expires_at_utc": "2026-08-15T12:00:00Z",
        "negative_authorizations": req["negative_authorizations"],
        "revocation_conditions": req["revocation_conditions"],
        "image_manifest_sha256": req["image_manifest_sha256"],
    }
