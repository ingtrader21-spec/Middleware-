from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import pytest

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts/generate_security_owner_decision.py"
VALIDATOR = ROOT / "scripts/validate_security_owner_decision.py"
SCHEMA = ROOT / "schemas/security-owner-decision-request.v1.schema.json"
AUTHORITY = ROOT / "security/governance/security-owner-authority.json"
HEAD = "a" * 40
DIGEST = "sha256:" + "b" * 64
PYTHON_312_RUNTIME_PATHS: tuple[str, ...] = (
    "/usr/local/bin/python3.12",
    "/usr/local/lib/libpython3.12.so.1.0",
)
VULNERABILITY_MATRIX_FIELDS: tuple[str, ...] = (
    "vulnerability_id",
    "package",
    "installed_version",
    "package_path",
    "severity",
    "fixed_versions",
    "scanners",
)


def write_test_vulnerability_matrix(
    stream: TextIO,
    *,
    vulnerability_id: str = "CVE-2026-1",
    package: str = "python",
    installed_version: str = "3.12.13",
    severity: str = "HIGH",
    fixed_versions: str = "3.13.14",
    scanners: str = "Grype",
    paths: Sequence[str] | None = None,
) -> None:
    """Write a deterministic vulnerability matrix fixture."""
    runtime_paths = PYTHON_312_RUNTIME_PATHS if paths is None else tuple(paths)
    if not runtime_paths:
        raise ValueError("at least one runtime path is required")

    writer = csv.DictWriter(stream, fieldnames=VULNERABILITY_MATRIX_FIELDS)
    writer.writeheader()
    for runtime_path in runtime_paths:
        writer.writerow(
            {
                "vulnerability_id": vulnerability_id,
                "package": package,
                "installed_version": installed_version,
                "package_path": runtime_path,
                "severity": severity,
                "fixed_versions": fixed_versions,
                "scanners": scanners,
            }
        )


def fixture(tmp_path: Path) -> dict[str, Path]:
    files = {name: tmp_path / name for name in ["manifest.json", "matrix.csv", "sbom.json", "trivy.json", "grype.json", "provenance.json"]}
    for name, path in files.items():
        if name != "matrix.csv":
            path.write_text(json.dumps({"name": name}), encoding="utf-8")
    files["manifest.json"].write_text(
        json.dumps({"pr_number": 214, "head_sha": HEAD, "image_digest": DIGEST}),
        encoding="utf-8",
    )
    with files["matrix.csv"].open("w", newline="", encoding="utf-8") as stream:
        write_test_vulnerability_matrix(stream)
    return files


def command(tmp_path: Path) -> tuple[list[str], dict[str, Path], Path, str]:
    files = fixture(tmp_path)
    output = tmp_path / "decision.json"
    authority_sha = hashlib.sha256(AUTHORITY.read_bytes()).hexdigest()
    common = [
        "--source-sha", HEAD, "--image-digest", DIGEST, "--run-id", "12345",
        "--run-attempt", "2", "--authority", str(AUTHORITY),
        "--authority-sha256", authority_sha, "--authority-run-id", "9876",
        "--authority-artifact", "security-owner-authority-9876-1",
        "--manifest", str(files["manifest.json"]), "--matrix", str(files["matrix.csv"]),
        "--sbom", str(files["sbom.json"]), "--trivy", str(files["trivy.json"]),
        "--grype", str(files["grype.json"]), "--provenance", str(files["provenance.json"]),
    ]
    subprocess.run([sys.executable, str(GENERATOR), *common, "--output", str(output)], check=True)
    return common, files, output, authority_sha


def validate(common: list[str], output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(VALIDATOR), "--decision", str(output), "--schema", str(SCHEMA), *common], check=False, capture_output=True, text=True)


def test_exact_same_run_decision_passes(tmp_path: Path) -> None:
    common, files, output, _ = command(tmp_path)
    assert validate(common, output).returncode == 0
    decision = json.loads(output.read_text(encoding="utf-8"))
    assert decision["pr_number"] == 214
    assert decision["matrix_sha256"] == hashlib.sha256(files["matrix.csv"].read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "manifest_update,error",
    [
        ({"pr_number": 0}, "PR number"),
        ({"head_sha": "c" * 40}, "source SHA"),
        ({"image_digest": "sha256:" + "d" * 64}, "image digest"),
    ],
)
def test_generator_rejects_invalid_manifest_binding(
    tmp_path: Path, manifest_update: dict[str, object], error: str
) -> None:
    files = fixture(tmp_path)
    manifest = json.loads(files["manifest.json"].read_text(encoding="utf-8"))
    manifest.update(manifest_update)
    files["manifest.json"].write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "decision.json"
    authority_sha = hashlib.sha256(AUTHORITY.read_bytes()).hexdigest()
    result = subprocess.run(
        [
            sys.executable, str(GENERATOR), "--source-sha", HEAD,
            "--image-digest", DIGEST, "--run-id", "12345", "--run-attempt", "1",
            "--authority", str(AUTHORITY), "--authority-sha256", authority_sha,
            "--authority-run-id", "9876", "--authority-artifact",
            "security-owner-authority-9876-1", "--manifest", str(files["manifest.json"]),
            "--matrix", str(files["matrix.csv"]), "--sbom", str(files["sbom.json"]),
            "--trivy", str(files["trivy.json"]), "--grype", str(files["grype.json"]),
            "--provenance", str(files["provenance.json"]), "--output", str(output),
        ],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert error in result.stderr


def test_default_vulnerability_matrix_has_two_unique_runtime_rows(tmp_path: Path) -> None:
    files = fixture(tmp_path)
    with files["matrix.csv"].open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    unique_rows = {
        (
            row["vulnerability_id"],
            row["package"],
            row["installed_version"],
            row["package_path"],
        )
        for row in rows
    }
    assert len(rows) == 2
    assert len(unique_rows) == 2
    assert {row["package_path"] for row in rows} == set(PYTHON_312_RUNTIME_PATHS)
    assert len({row["vulnerability_id"] for row in rows}) == 1


def test_vulnerability_matrix_writer_supports_custom_critical_finding(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.csv"
    paths = ("/runtime/python", "/runtime/libpython.so")
    with matrix.open("w", newline="", encoding="utf-8") as stream:
        write_test_vulnerability_matrix(
            stream,
            vulnerability_id="CVE-2026-9999",
            severity="CRITICAL",
            paths=paths,
        )

    with matrix.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    assert [row["package_path"] for row in rows] == list(paths)
    assert {row["vulnerability_id"] for row in rows} == {"CVE-2026-9999"}
    assert {row["severity"] for row in rows} == {"CRITICAL"}


def test_vulnerability_matrix_writer_rejects_empty_paths(tmp_path: Path) -> None:
    with (
        (tmp_path / "matrix.csv").open("w", newline="", encoding="utf-8") as stream,
        pytest.raises(ValueError, match="at least one runtime path is required"),
    ):
        write_test_vulnerability_matrix(stream, paths=())


def test_vulnerability_matrix_writer_preserves_field_order_and_utf8(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.csv"
    with matrix.open("w", newline="", encoding="utf-8") as stream:
        write_test_vulnerability_matrix(
            stream,
            package="pythön",
            paths=("/runtime/pythön",),
        )

    with matrix.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)

    assert tuple(reader.fieldnames or ()) == VULNERABILITY_MATRIX_FIELDS
    assert rows[0]["package"] == "pythön"
    assert rows[0]["package_path"] == "/runtime/pythön"


@pytest.mark.parametrize("field", ["repository", "pr_number", "pr_head_sha", "image_digest", "build_run_id", "build_run_attempt", "matrix_sha256", "sbom_sha256", "provenance_sha256", "authority_reference"])
def test_missing_or_wrong_binding_fails(tmp_path: Path, field: str) -> None:
    common, _, output, _ = command(tmp_path)
    document = json.loads(output.read_text())
    if field in {"repository", "pr_number"}:
        document.pop(field)
    else:
        document[field] = "wrong"
    output.write_text(json.dumps(document))
    assert validate(common, output).returncode != 0


def test_cross_run_and_local_only_substitution_fail(tmp_path: Path) -> None:
    common, _, output, _ = command(tmp_path)
    wrong = common.copy()
    wrong[wrong.index("--run-id") + 1] = "12346"
    assert validate(wrong, output).returncode != 0
    wrong = common.copy()
    wrong[wrong.index("--authority-artifact") + 1] = "local-only-decision"
    assert validate(wrong, output).returncode != 0


def test_decision_generation_and_validation_precede_both_uploads() -> None:
    workflow = (ROOT / ".github/workflows/staging-candidate-build-sign.yml").read_text()
    evidence_validation = workflow.index("- name: Validate complete candidate evidence")
    decision_generation = workflow.index("- name: Generate and validate exact run-scoped Security Owner decision")
    evidence_upload = workflow.index("- name: Upload exact run-scoped candidate evidence")
    decision_upload = workflow.index("- name: Upload exact run-scoped Security Owner decision")
    assert evidence_validation < decision_generation < evidence_upload < decision_upload
    assert "decision-SHA256SUMS" in workflow[decision_generation:decision_upload]
    assert "test \"${EVIDENCE_RUN_ID}\" = \"${DECISION_RUN_ID}\"" in workflow
    assert "pr${{ inputs.pr_number }}-security-owner-decision-${{ inputs.source_sha }}-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
