from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/validate_production_security_owner_authority.py"
SPEC = importlib.util.spec_from_file_location("production_authority", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
ValidationError = module.ValidationError
SHA = "4db1c245c1733e4abc7ea695d76862ffdc3fd698"
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)  # noqa: UP017


def authority() -> dict:
    value = {
        "schema_version": "codestra.security-owner.production-authority.v1",
        "company": "Codestra LLC",
        "authority_id": "production-test",
        "role": "Security Owner",
        "authorized_identity": "https://github.com/kazan555",
        "github_identity": "kazan555",
        "authority_reference": "github-environment-review:1",
        "approved_scopes": ["server_a_production_release", "production_deployment", "external_delivery_synthetic_only"],
        "prohibited_scopes": ["production_activation", "external_delivery_general"],
        "source_sha": SHA,
        "communications": {"calls": False, "sms": False, "email": False, "callbacks": False},
        "issued_utc": "2026-08-14T11:00:00Z",
        "not_before_utc": "2026-08-14T11:00:00Z",
        "expires_utc": "2026-08-20T11:00:00Z",
        "approving_authority": "Codestra LLC protected environment security-owner-authority",
        "signature_method": "sigstore-keyless-oidc",
        "signature_key_id": "https://token.actions.githubusercontent.com",
        "detached_signature_path": "security-owner-authority.sigstore.json",
    }
    value["document_sha256"] = hashlib.sha256(module.canonical_payload(value)).hexdigest()
    return value


def validate(value: dict) -> None:
    module.validate(value, source_sha=SHA, now=NOW)


def test_production_authority_is_accepted() -> None:
    validate(authority())


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_sha", "b" * 40),
        ("expires_utc", "2026-08-13T00:00:00Z"),
        ("not_before_utc", "2026-08-15T00:00:00Z"),
        ("company", "Wrong LLC"),
        ("role", "Release Owner"),
        ("prohibited_scopes", ["production_deployment"]),
    ],
)
def test_invalid_authority_is_rejected(field: str, value: object) -> None:
    candidate = authority()
    candidate[field] = value
    candidate["document_sha256"] = hashlib.sha256(module.canonical_payload(candidate)).hexdigest()
    with pytest.raises(ValidationError):
        validate(candidate)


def test_altered_authority_is_rejected() -> None:
    candidate = authority()
    candidate["communications"]["calls"] = True
    with pytest.raises(ValidationError):
        validate(candidate)


def test_staging_authority_fails_production() -> None:
    staging = json.loads((ROOT / "security/governance/security-owner-authority.json").read_text())
    with pytest.raises(ValidationError):
        validate(staging)


def test_workflow_preserves_staging_and_adds_production_contract() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-authority-sign.yml").read_text()
    assert "inputs.authority_kind == 'staging'" in workflow
    assert "inputs.authority_kind == 'production'" in workflow
    assert "scripts/validate_security_owner_authority.py" in workflow
    assert "scripts/validate_production_security_owner_authority.py" in workflow
    assert "security-owner-authority.sigstore.json" in workflow


def test_workflow_uses_fields_returned_by_environment_approvals_api() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-authority-sign.yml").read_text()
    assert "approver_user_id=\"$(jq -er '.user.id | tostring' approval.json)\"" in workflow
    assert "run:${GITHUB_RUN_ID}:environment:security-owner-authority" in workflow
    assert "jq -er .id approval.json" not in workflow
