from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "security/governance/security-owner-authority.json"
VALIDATOR = ROOT / "scripts/validate_security_owner_authority.py"


def validate(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), "--authority", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_authority_document_is_current_finite_and_staging_only() -> None:
    assert validate(AUTHORITY).returncode == 0
    document = json.loads(AUTHORITY.read_text())
    assert document["approved_scopes"] == ["server_a_isolated_staging"]
    assert set(document["prohibited_scopes"]) == {
        "production_deployment", "production_activation", "canary_activation",
        "server_b_access", "customer_data", "unrestricted_n8n_activation",
        "external_delivery",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("company", "Other LLC"),
        ("authorized_identity", "<PENDING>"),
        ("approved_scopes", ["server_a_isolated_staging", "production_deployment"]),
        ("expires_utc", "2026-01-01T00:00:00Z"),
        ("not_before_utc", "2030-01-01T00:00:00Z"),
        ("document_sha256", "0" * 64),
    ],
)
def test_authority_tampering_fails(tmp_path: Path, field: str, value: object) -> None:
    document = json.loads(AUTHORITY.read_text())
    document[field] = value
    path = tmp_path / "authority.json"
    path.write_text(json.dumps(document))
    assert validate(path).returncode != 0


def test_authority_workflow_is_protected_and_keyless() -> None:
    workflow = (ROOT / ".github/workflows/security-owner-authority-sign.yml").read_text()
    assert "environment: security-owner-authority" in workflow
    assert workflow.count("id-token: write") == 2
    assert "packages: write" not in workflow
    assert "deployments: write" not in workflow
    assert "security-owner-authority-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "cosign\" verify-blob" in workflow
    assert hashlib.sha256(AUTHORITY.read_bytes()).hexdigest() != "0" * 64
