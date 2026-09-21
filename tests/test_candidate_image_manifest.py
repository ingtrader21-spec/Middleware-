from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_candidate_image_manifest.py"
SCHEMA = ROOT / "schemas/candidate-image-manifest.v1.schema.json"
HEAD = "a" * 40
DIGEST = "sha256:" + "b" * 64


def valid_manifest() -> dict[str, object]:
    checksum = "c" * 64
    return {
        "$schema": "https://codestra.internal/schemas/candidate-image-manifest.v1.json",
        "manifest_version": 1,
        "company": "Codestra LLC",
        "repository": "ingtrader21-spec/Middleware-",
        "pr_number": 68,
        "head_sha": HEAD,
        "image_repository": "ghcr.io/ingtrader21-spec/codestra-middleware",
        "image_digest": DIGEST,
        "candidate_scope": "server_a_isolated_staging_candidate",
        "production_release_provenance_assigned": False,
        "sbom_sha256": checksum,
        "trivy_sha256": checksum,
        "grype_sha256": checksum,
        "vulnerability_matrix_sha256": checksum,
        "vulnerability_summary_sha256": checksum,
        "provenance_sha256": checksum,
        "build_run_id": "12345",
        "build_run_attempt": "1",
        "created_utc": "2026-08-01T20:00:00Z",
    }


def validate(tmp_path: Path, manifest: dict[str, object]) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--manifest",
            str(path),
            "--schema",
            str(SCHEMA),
            "--expected-company",
            "Codestra LLC",
            "--expected-repository",
            "ingtrader21-spec/Middleware-",
            "--expected-pr-number",
            "68",
            "--expected-head-sha",
            HEAD,
            "--expected-image-repository",
            "ghcr.io/ingtrader21-spec/codestra-middleware",
            "--expected-image-digest",
            DIGEST,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_valid_repository_pr_head_and_digest_bindings_pass(tmp_path: Path) -> None:
    assert validate(tmp_path, valid_manifest()).returncode == 0


def test_schema_accepts_non_historical_positive_pr_number(tmp_path: Path) -> None:
    manifest = valid_manifest()
    manifest["pr_number"] = 214
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable, str(VALIDATOR), "--manifest", str(path), "--schema", str(SCHEMA),
            "--expected-company", "Codestra LLC", "--expected-repository",
            "ingtrader21-spec/Middleware-", "--expected-pr-number", "214",
            "--expected-head-sha", HEAD, "--expected-image-repository",
            "ghcr.io/ingtrader21-spec/codestra-middleware", "--expected-image-digest", DIGEST,
        ],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 0


@pytest.mark.parametrize("field", ["repository", "pr_number"])
def test_missing_identity_field_fails(tmp_path: Path, field: str) -> None:
    manifest = valid_manifest()
    del manifest[field]
    assert validate(tmp_path, manifest).returncode != 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository", "someone/else"),
        ("pr_number", 69),
        ("head_sha", "d" * 40),
        ("image_repository", "ghcr.io/codestra-srl/other"),
        ("image_digest", "sha256:" + "d" * 64),
    ],
)
def test_wrong_exact_binding_fails(tmp_path: Path, field: str, value: object) -> None:
    manifest = valid_manifest()
    manifest[field] = value
    assert validate(tmp_path, manifest).returncode != 0


def test_mutable_tag_only_identity_fails(tmp_path: Path) -> None:
    manifest = valid_manifest()
    manifest["image_repository"] = "ghcr.io/ingtrader21-spec/codestra-middleware:latest"
    assert validate(tmp_path, manifest).returncode != 0


def test_pre_transfer_package_is_not_a_candidate_repository(tmp_path: Path) -> None:
    """Candidate images can only be published to the repository owner's package."""
    manifest = valid_manifest()
    manifest["image_repository"] = "ghcr.io/appolon1908-hue/codestra-middleware"
    assert validate(tmp_path, manifest).returncode != 0


@pytest.mark.parametrize("field", ["head_sha", "image_digest", "build_run_id"])
def test_placeholder_value_fails(tmp_path: Path, field: str) -> None:
    manifest = valid_manifest()
    manifest[field] = "<PLACEHOLDER>"
    assert validate(tmp_path, manifest).returncode != 0


def test_additional_property_fails(tmp_path: Path) -> None:
    manifest = valid_manifest()
    manifest["mutable_tag"] = "latest"
    assert validate(tmp_path, manifest).returncode != 0


def test_security_decision_path_validates_manifest_first() -> None:
    workflow = (ROOT / ".github/workflows/staging-candidate-build-sign.yml").read_text()
    sign = workflow.index("- name: Verify Security Owner decision binding")
    validator = workflow.index("python3 scripts/validate_candidate_image_manifest.py", sign)
    decision_validator = workflow.index("python3 scripts/validate_security_owner_decision.py", validator)
    assert validator < decision_validator
