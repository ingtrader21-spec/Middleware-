from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_three_component_release_decision.py"
WORKFLOW = ROOT / ".github/workflows/three-component-release-decision.yml"
SCHEMA = ROOT / "schemas/three-component-production-release-decision.v1.schema.json"
SOURCE = "a" * 40
WORKFLOW_SHA = "b" * 40
DIGESTS = {
    "middleware": "sha256:" + "1" * 64,
    "agent-desktop": "sha256:" + "2" * 64,
    "websocket-gateway": "sha256:" + "3" * 64,
}
IMAGES = {
    "middleware": "ghcr.io/ingtrader21-spec/codestra-middleware",
    "agent-desktop": "ghcr.io/codestra-srl/codestra-agent-desktop",
    "websocket-gateway": "ghcr.io/codestra-srl/codestra-websocket-gateway",
}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def checksums(directory: Path, name: str, files: list[str]) -> None:
    lines = [f"{hashlib.sha256((directory / item).read_bytes()).hexdigest()}  {item}" for item in files]
    (directory / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_fixture(tmp_path: Path) -> tuple[list[str], Path]:
    authority = tmp_path / "authority"
    candidates = tmp_path / "candidates"
    signing = tmp_path / "signing"
    authority.mkdir()
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat().replace("+00:00", "Z")
    authority_document = {
        "source_sha": SOURCE,
        "github_identity": "kazan555",
        "authorized_identity": "https://github.com/kazan555",
        "expires_utc": expires,
        "approved_scopes": ["server_a_production_release", "production_deployment", "external_delivery_synthetic_only"],
        "communications": {"calls": False, "sms": False, "email": False},
    }
    write_json(authority / "security-owner-authority.json", authority_document)
    write_json(authority / "security-owner-authority.sigstore.json", {"verified": True})
    checksums(authority, "authority-signing-SHA256SUMS", ["security-owner-authority.json", "security-owner-authority.sigstore.json"])
    authority_sha = hashlib.sha256((authority / "security-owner-authority.json").read_bytes()).hexdigest()
    for component, digest in DIGESTS.items():
        candidate = candidates / component
        signed = signing / component
        candidate.mkdir(parents=True)
        signed.mkdir(parents=True)
        manifest = {
            "head_sha": SOURCE, "build_run_id": "100", "build_run_attempt": "1",
            "image_repository": IMAGES[component], "image_digest": digest,
            "candidate_scope": "server_a_isolated_staging_candidate",
        }
        decision = {
            "pr_head_sha": SOURCE, "image_repository": IMAGES[component], "image_digest": digest,
            "build_run_id": "100", "build_run_attempt": "1",
            "decision_status": "pending_security_owner_environment_approval",
            "accepted_vulnerabilities": [],
        }
        provenance = {
            "subject": [{"name": IMAGES[component], "digest": {"sha256": digest.split(":", 1)[1]}}],
            "predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"gitCommit": SOURCE}}]}},
        }
        write_json(candidate / "candidate-image-manifest.json", manifest)
        write_json(candidate / "vulnerability-summary.json", {"critical_count": 0, "high_count": 0})
        write_json(candidate / "security-owner-decision.json", decision)
        write_json(candidate / "provenance.json", provenance)
        write_json(candidate / "candidate.cdx.json", {"bomFormat": "CycloneDX"})
        (candidate / "image-digest.txt").write_text(digest + "\n", encoding="utf-8")
        files = ["candidate-image-manifest.json", "vulnerability-summary.json", "provenance.json", "candidate.cdx.json", "image-digest.txt"]
        checksums(candidate, "SHA256SUMS", files)
        checksums(candidate, "decision-SHA256SUMS", ["security-owner-decision.json"])
        signed_files = [
            "image-signature.sigstore.json", "sbom-attestation.sigstore.json",
            "provenance-attestation.sigstore.json", "security-owner-decision.sigstore.json",
            "signature-verification.json", "sbom-verification.json", "provenance-verification.json",
        ]
        for name in signed_files:
            write_json(signed / name, {"verified": True})
        checksums(signed, "signing-SHA256SUMS", signed_files)
    output = tmp_path / "decision.json"
    command = [
        sys.executable, str(SCRIPT), "--artifact-source-sha", SOURCE,
        "--m05-workflow-sha", WORKFLOW_SHA, "--production-authority-run-id", "90",
        "--production-authority-sha256", authority_sha, "--candidate-run-id", "100",
        "--candidate-run-attempt", "1", "--signing-run-id", "110",
        "--signing-run-attempt", "1", "--middleware-digest", DIGESTS["middleware"],
        "--agent-desktop-digest", DIGESTS["agent-desktop"],
        "--websocket-gateway-digest", DIGESTS["websocket-gateway"],
        "--authority-dir", str(authority), "--candidate-root", str(candidates),
        "--signing-root", str(signing), "--expires-at", expires, "--output", str(output),
    ]
    return command, output


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_current_three_component_tuple_passes(tmp_path: Path) -> None:
    command, output = make_fixture(tmp_path)
    result = run(command)
    assert result.returncode == 0, result.stderr
    decision = json.loads(output.read_text())
    assert decision["decision"] == "PASS"
    assert set(decision["components"]) == set(DIGESTS)
    assert decision["synthetic_only"] is True
    assert decision["pstn_calls_allowed"] is False
    schema = json.loads(SCHEMA.read_text())
    assert set(schema["required"]).issubset(decision)
    assert schema["properties"]["decision"]["const"] == decision["decision"]
    assert schema["properties"]["synthetic_only"]["const"] is decision["synthetic_only"]


@pytest.mark.parametrize("option", ["--artifact-source-sha", "--middleware-digest", "--agent-desktop-digest", "--websocket-gateway-digest"])
def test_wrong_source_or_digest_fails(tmp_path: Path, option: str) -> None:
    command, _ = make_fixture(tmp_path)
    command[command.index(option) + 1] = ("c" * 40 if option.endswith("sha") else "sha256:" + "f" * 64)
    assert run(command).returncode != 0


def test_missing_component_fails(tmp_path: Path) -> None:
    command, _ = make_fixture(tmp_path)
    signing_root = Path(command[command.index("--signing-root") + 1])
    (signing_root / "agent-desktop" / "image-signature.sigstore.json").unlink()
    assert run(command).returncode != 0


@pytest.mark.parametrize("field,value", [("critical_count", 1), ("high_count", 1)])
def test_critical_fails_but_high_requires_exception_reconciliation(tmp_path: Path, field: str, value: int) -> None:
    command, _ = make_fixture(tmp_path)
    candidate_root = Path(command[command.index("--candidate-root") + 1])
    summary_path = candidate_root / "middleware/vulnerability-summary.json"
    summary = json.loads(summary_path.read_text())
    summary[field] = value
    write_json(summary_path, summary)
    checksums(candidate_root / "middleware", "SHA256SUMS", ["candidate-image-manifest.json", "vulnerability-summary.json", "provenance.json", "candidate.cdx.json", "image-digest.txt"])
    result = run(command)
    assert result.returncode != 0


def test_expired_or_cross_digest_exception_fails(tmp_path: Path) -> None:
    command, _ = make_fixture(tmp_path)
    candidate_root = Path(command[command.index("--candidate-root") + 1])
    decision_path = candidate_root / "websocket-gateway/security-owner-decision.json"
    decision = json.loads(decision_path.read_text())
    decision["accepted_vulnerabilities"] = [{
        "source_sha": SOURCE, "image_digest": DIGESTS["middleware"],
        "exception_expires_utc": "2020-01-01T00:00:00Z",
    }]
    write_json(decision_path, decision)
    checksums(candidate_root / "websocket-gateway", "decision-SHA256SUMS", ["security-owner-decision.json"])
    assert run(command).returncode != 0


def test_expired_or_wrong_authority_fails(tmp_path: Path) -> None:
    command, _ = make_fixture(tmp_path)
    authority_dir = Path(command[command.index("--authority-dir") + 1])
    document_path = authority_dir / "security-owner-authority.json"
    document = json.loads(document_path.read_text())
    document["source_sha"] = "d" * 40
    document["expires_utc"] = "2020-01-01T00:00:00Z"
    write_json(document_path, document)
    checksums(authority_dir, "authority-signing-SHA256SUMS", ["security-owner-authority.json", "security-owner-authority.sigstore.json"])
    command[command.index("--production-authority-sha256") + 1] = hashlib.sha256(document_path.read_bytes()).hexdigest()
    assert run(command).returncode != 0


def test_mutable_identity_is_rejected(tmp_path: Path) -> None:
    command, _ = make_fixture(tmp_path)
    command[command.index("--middleware-digest") + 1] = "latest"
    assert run(command).returncode != 0


@pytest.mark.parametrize("option", ["--candidate-run-id", "--candidate-run-attempt"])
def test_wrong_candidate_run_or_attempt_fails(tmp_path: Path, option: str) -> None:
    command, _ = make_fixture(tmp_path)
    command[command.index(option) + 1] = "999"
    assert run(command).returncode != 0


@pytest.mark.parametrize("missing", ["candidate.cdx.json", "provenance.json"])
def test_missing_sbom_or_provenance_fails(tmp_path: Path, missing: str) -> None:
    command, _ = make_fixture(tmp_path)
    candidate_root = Path(command[command.index("--candidate-root") + 1])
    (candidate_root / "middleware" / missing).unlink()
    assert run(command).returncode != 0


def test_unauthorized_reviewer_fails(tmp_path: Path) -> None:
    command, _ = make_fixture(tmp_path)
    command.extend(["--authorized-reviewer", "unauthorized-user"])
    assert run(command).returncode != 0


def test_pstn_or_customer_scope_fails(tmp_path: Path) -> None:
    command, _ = make_fixture(tmp_path)
    authority_dir = Path(command[command.index("--authority-dir") + 1])
    document_path = authority_dir / "security-owner-authority.json"
    document = json.loads(document_path.read_text())
    document["communications"]["calls"] = True
    write_json(document_path, document)
    checksums(authority_dir, "authority-signing-SHA256SUMS", ["security-owner-authority.json", "security-owner-authority.sigstore.json"])
    command[command.index("--production-authority-sha256") + 1] = hashlib.sha256(document_path.read_bytes()).hexdigest()
    assert run(command).returncode != 0


def test_workflow_is_protected_fail_closed_and_non_deploying() -> None:
    value = WORKFLOW.read_text(encoding="utf-8")
    assert "environment: production-release-decision" in value
    assert "contents: write" not in value and "packages: write" not in value
    assert "id-token: write" in value and "actions: read" in value and "checks: read" in value
    assert "docker compose" not in value and "docker run" not in value and "ssh " not in value
    assert "TEST_SYN/6101" in value
    assert "cosign\" verify-blob" in value
    assert "verify-attestation --type cyclonedx" in value
    assert "verify-attestation --type slsaprovenance" in value
    assert "release-${component}-candidate-${{ inputs.artifact_source_sha }}-${{ inputs.candidate_run_id }}-${{ inputs.candidate_run_attempt }}" in value
    assert "release-${component}-signing-${{ inputs.artifact_source_sha }}-${{ inputs.signing_run_id }}-${{ inputs.signing_run_attempt }}" in value


def test_wrong_signing_run_and_invalid_cosign_signature_fail_closed_in_workflow() -> None:
    value = WORKFLOW.read_text(encoding="utf-8")
    assert 'test "$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${SIGNING_RUN}" --jq .conclusion)" = success' in value
    assert '--name "release-${component}-signing-${{ inputs.artifact_source_sha }}-${{ inputs.signing_run_id }}-${{ inputs.signing_run_attempt }}"' in value
    assert "--bundle evidence/authority/security-owner-authority.sigstore.json" in value
    assert "--certificate-identity \"${SIGNING_IDENTITY}\"" in value
