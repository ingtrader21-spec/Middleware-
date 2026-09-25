from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from scripts import release_gate
from scripts.release_gate import (
    EXPECTED_SCHEMA_HEAD,
    FAIL,
    PASS,
    PENDING,
    ROOT,
    check_alembic_single_head,
    check_sbom,
    check_vulnerability_policy,
    check_workflow_schema_binding,
    evaluate,
    provenance_predicate,
)
from scripts.release_manifest import FIXED_ARTIFACTS, build_manifest, canonical_json


IMAGE_DIGEST = "sha256:" + ("c" * 64)
SCHEMA = json.loads(
    (ROOT / "contracts/release-gate.v1.schema.json").read_text(encoding="utf-8")
)
GIT = [
    "git",
    "-c",
    "user.name=gate",
    "-c",
    "user.email=gate@example.invalid",
    "-c",
    "commit.gpgsign=false",
]


def validate_report(report: dict) -> None:
    Draft202012Validator(SCHEMA, format_checker=FormatChecker()).validate(report)


def by_id(report: dict) -> dict[str, dict]:
    return {check["id"]: check for check in report["checks"]}


def write_migration(directory: Path, revision: str, down_revision: object) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{revision}.py").write_text(
        f"revision = {revision!r}\ndown_revision = {down_revision!r}\n",
        encoding="utf-8",
    )


def release_source(tmp_path: Path) -> Path:
    """A committed copy of every path the manifest and gate bind to."""
    source = tmp_path / "source"
    for _, relative in FIXED_ARTIFACTS.values():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if (ROOT / relative).is_dir():
            shutil.copytree(
                ROOT / relative, target, ignore=shutil.ignore_patterns("__pycache__")
            )
        else:
            shutil.copyfile(ROOT / relative, target)
    workflow = source / ".github/workflows/release.yml"
    workflow.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / ".github/workflows/release.yml", workflow)
    subprocess.run([*GIT, "init", "-q", str(source)], check=True)
    subprocess.run([*GIT, "-C", str(source), "add", "-A"], check=True)
    subprocess.run(
        [*GIT, "-C", str(source), "commit", "-q", "-m", "release source"], check=True
    )
    return source


def git_identity(root: Path) -> tuple[str, str]:
    def rev(spec: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", spec],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    return rev("HEAD"), rev("HEAD^{tree}")


def release_evidence(
    directory: Path, *, matches: list | None = None
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    sbom = directory / "middleware.spdx.json"
    scan = directory / "middleware.grype.json"
    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": f"ghcr.io/ingtrader21-spec/codestra-middleware@{IMAGE_DIGEST}",
                "documentNamespace": "https://anchore.com/syft/image/example",
                "packages": [{"SPDXID": "SPDXRef-Package-fastapi", "name": "fastapi"}],
            }
        ),
        encoding="utf-8",
    )
    scan.write_text(json.dumps({"matches": matches or []}), encoding="utf-8")
    return sbom, scan


def signed_inputs(tmp_path: Path) -> tuple[Path, str, Path, Path, Path]:
    source = release_source(tmp_path)
    source_sha, tree_id = git_identity(source)
    evidence = tmp_path / "evidence"
    sbom, scan = release_evidence(evidence)
    manifest = build_manifest(
        root=source,
        source_sha=source_sha,
        git_tree_id=tree_id,
        image_digest=IMAGE_DIGEST,
        built_at="2026-09-25T12:00:00Z",
        run_id=35602170321,
        run_attempt=2,
        sbom_path=sbom,
        vulnerability_report_path=scan,
    )
    manifest_path = evidence / "release-manifest.v1.json"
    manifest_path.write_bytes(canonical_json(manifest))
    return source, source_sha, sbom, scan, manifest_path


# ---------------------------------------------------------------- repository truth


def test_repository_has_exactly_one_alembic_head_and_it_is_schema_0067() -> None:
    check = check_alembic_single_head(ROOT, EXPECTED_SCHEMA_HEAD)
    assert check["status"] == PASS, check
    assert check["evidence"]["heads"] == ["0067_service_catalog_monitoring_state"]


def test_release_workflow_probes_and_annotates_the_gated_schema_head() -> None:
    check = check_workflow_schema_binding(ROOT, EXPECTED_SCHEMA_HEAD)
    assert check["status"] == PASS, check


def test_provenance_predicate_is_byte_identical_to_the_release_job(
    tmp_path: Path,
) -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    start = workflow.index("python3 - <<'PY'\n") + len("python3 - <<'PY'\n")
    end = workflow.index("\n          PY\n", start)
    program = textwrap.dedent(workflow[start:end])
    source_sha = "d" * 40
    subprocess.run(
        [sys.executable, "-c", program],
        check=True,
        env={
            **os.environ,
            "RELEASE_SOURCE_SHA": source_sha,
            "RUNNER_TEMP": str(tmp_path),
        },
    )
    job_bytes = (tmp_path / "middleware-slsa-v1-predicate.json").read_bytes()
    assert job_bytes == canonical_json(provenance_predicate(source_sha))


# ---------------------------------------------------------------- decisions


def test_clean_source_without_external_evidence_is_blocked_not_ready(
    tmp_path: Path,
) -> None:
    source = release_source(tmp_path)
    source_sha, tree_id = git_identity(source)
    report = evaluate(root=source, expected_source_sha=source_sha)
    validate_report(report)
    assert report["decision"] == "BLOCKED"
    assert report["failed_checks"] == []
    assert report["pending_external"] == [
        "source_binding",
        "sbom",
        "vulnerability_policy",
        "cosign_inputs",
        "release_manifest",
    ]
    assert report["source"] == {
        "git_sha": source_sha,
        "git_tree_id": tree_id,
        "protected_main_sha": None,
    }
    assert report["image"]["digest"] == "PENDING_OWNER_PACKAGE_ACCESS"
    assert report["effects"]["signing_performed"] is False
    assert report["effects"]["production_go"] == "NO"


def test_fully_bound_evidence_is_ready_for_signing(tmp_path: Path) -> None:
    source, source_sha, sbom, scan, manifest = signed_inputs(tmp_path)
    report = evaluate(
        root=source,
        expected_source_sha=source_sha,
        protected_main_sha=source_sha,
        image_digest=IMAGE_DIGEST,
        sbom_path=sbom,
        vulnerability_report_path=scan,
        manifest_path=manifest,
    )
    validate_report(report)
    assert report["decision"] == "READY_FOR_SIGNING", report
    assert all(check["status"] == PASS for check in report["checks"])
    assert by_id(report)["cosign_inputs"]["evidence"]["image_reference"] == (
        f"ghcr.io/ingtrader21-spec/codestra-middleware@{IMAGE_DIGEST}"
    )


def test_stale_protected_main_fails_source_binding(tmp_path: Path) -> None:
    source = release_source(tmp_path)
    report = evaluate(root=source, protected_main_sha="e" * 40)
    assert report["decision"] == "FAIL"
    assert (
        by_id(report)["source_binding"]["detail"]
        == "HEAD is not the current protected main head"
    )


def test_dirty_source_fails_even_when_it_matches_main(tmp_path: Path) -> None:
    source = release_source(tmp_path)
    source_sha, _ = git_identity(source)
    (source / "requirements-runtime.in").write_text("tampered\n", encoding="utf-8")
    report = evaluate(root=source, protected_main_sha=source_sha)
    assert by_id(report)["source_binding"]["status"] == FAIL
    assert by_id(report)["source_binding"]["evidence"]["worktree_clean"] is False


def test_manifest_for_another_digest_fails(tmp_path: Path) -> None:
    source, source_sha, sbom, scan, manifest = signed_inputs(tmp_path)
    report = evaluate(
        root=source,
        protected_main_sha=source_sha,
        image_digest="sha256:" + ("f" * 64),
        sbom_path=sbom,
        vulnerability_report_path=scan,
        manifest_path=manifest,
    )
    assert report["decision"] == "FAIL"
    assert report["failed_checks"] == ["release_manifest"]


def test_manifest_rejects_a_substituted_scan(tmp_path: Path) -> None:
    source, source_sha, sbom, _, manifest = signed_inputs(tmp_path)
    _, other_scan = release_evidence(tmp_path / "other")
    report = evaluate(
        root=source,
        protected_main_sha=source_sha,
        image_digest=IMAGE_DIGEST,
        sbom_path=sbom,
        vulnerability_report_path=other_scan,
        manifest_path=manifest,
    )
    assert report["failed_checks"] == ["release_manifest"]


def test_manifest_rejects_scan_bytes_changed_after_manifest(tmp_path: Path) -> None:
    source, source_sha, sbom, scan, manifest = signed_inputs(tmp_path)
    scan.write_text(json.dumps({"matches": [], "tampered": True}), encoding="utf-8")
    report = evaluate(
        root=source,
        protected_main_sha=source_sha,
        image_digest=IMAGE_DIGEST,
        sbom_path=sbom,
        vulnerability_report_path=scan,
        manifest_path=manifest,
    )
    assert report["failed_checks"] == ["release_manifest"]


def test_malformed_digest_fails_cosign_inputs(tmp_path: Path) -> None:
    source = release_source(tmp_path)
    report = evaluate(root=source, image_digest="latest")
    assert "cosign_inputs" in report["failed_checks"]


# ---------------------------------------------------------------- alembic graph


@pytest.mark.parametrize(
    ("migrations", "detail"),
    [
        (
            [("0001_base", None), ("0002_a", "0001_base"), ("0002_b", "0001_base")],
            "expected exactly one Alembic head, found 2",
        ),
        (
            [("0001_base", None), ("0002_next", "0001_missing")],
            "missing parent 0001_missing of 0002_next",
        ),
        (
            [("0001_base", None), ("0002_next", "0001_base")],
            "Alembic head 0002_next is not 0067_service_catalog_monitoring_state",
        ),
        (
            [("0001_a", "0002_b"), ("0002_b", "0001_a")],
            "expected exactly one base revision, found []",
        ),
    ],
)
def test_alembic_graph_defects_fail(
    tmp_path: Path, migrations: list, detail: str
) -> None:
    for revision, down in migrations:
        write_migration(tmp_path / "migrations/versions", revision, down)
    check = check_alembic_single_head(tmp_path, EXPECTED_SCHEMA_HEAD)
    assert check["status"] == FAIL
    assert detail in check["detail"]


def test_alembic_cycle_with_a_valid_base_is_detected(tmp_path: Path) -> None:
    directory = tmp_path / "migrations/versions"
    write_migration(directory, "0001_base", None)
    write_migration(directory, "0002_a", ("0001_base", "0003_b"))
    write_migration(directory, "0003_b", "0002_a")
    write_migration(directory, "0004_head", "0003_b")
    check = check_alembic_single_head(tmp_path, "0004_head")
    assert check["status"] == FAIL
    assert "cycle through" in check["detail"]


def test_merge_revision_resolving_to_one_head_passes(tmp_path: Path) -> None:
    directory = tmp_path / "migrations/versions"
    write_migration(directory, "0001_base", None)
    write_migration(directory, "0002_a", "0001_base")
    write_migration(directory, "0002_b", "0001_base")
    write_migration(directory, "0003_merge", ("0002_a", "0002_b"))
    check = check_alembic_single_head(tmp_path, "0003_merge")
    assert check["status"] == PASS
    assert check["evidence"]["revision_count"] == 4


def test_workflow_that_probes_a_stale_head_fails(tmp_path: Path) -> None:
    workflow = tmp_path / ".github/workflows/release.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        (ROOT / ".github/workflows/release.yml")
        .read_text(encoding="utf-8")
        .replace(
            "EXPECTED_SCHEMA_HEAD: 0067_service_catalog_monitoring_state",
            "EXPECTED_SCHEMA_HEAD: 0066_reconcile_odoo_campaign_scope",
        ),
        encoding="utf-8",
    )
    check = check_workflow_schema_binding(tmp_path, EXPECTED_SCHEMA_HEAD)
    assert check["status"] == FAIL
    assert check["evidence"]["probe_expected_heads"] == [
        "0066_reconcile_odoo_campaign_scope"
    ]


# ---------------------------------------------------------------- SBOM and scan


def test_sbom_must_be_spdx_with_packages(tmp_path: Path) -> None:
    assert check_sbom(None)["status"] == PENDING
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            {"spdxVersion": "SPDX-2.3", "documentNamespace": "urn:x", "packages": []}
        ),
        encoding="utf-8",
    )
    assert check_sbom(path)["detail"] == "SBOM lists no packages"
    path.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    assert check_sbom(path)["status"] == FAIL
    path.write_text("not json", encoding="utf-8")
    assert check_sbom(path)["status"] == FAIL


def grype_match(
    severity: str, fix_state: str, identifier: str = "CVE-2026-0001"
) -> dict:
    return {
        "vulnerability": {
            "id": identifier,
            "severity": severity,
            "fix": {"state": fix_state, "versions": []},
        },
        "artifact": {"name": "openssl", "version": "3.0.0"},
    }


def test_fixable_high_or_critical_finding_fails_the_gate(tmp_path: Path) -> None:
    path = tmp_path / "grype.json"
    path.write_text(
        json.dumps(
            {
                "matches": [
                    grype_match("Critical", "fixed", "CVE-2026-0002"),
                    grype_match("High", "not-fixed"),
                    grype_match("Medium", "fixed"),
                ]
            }
        ),
        encoding="utf-8",
    )
    check = check_vulnerability_policy(path)
    assert check["status"] == FAIL
    assert check["evidence"]["blocking_findings"] == [
        {
            "id": "CVE-2026-0002",
            "severity": "critical",
            "package": "openssl",
            "version": "3.0.0",
        }
    ]
    assert check["evidence"]["severity_counts"]["high"] == 1


def test_unfixed_high_findings_do_not_block(tmp_path: Path) -> None:
    path = tmp_path / "grype.json"
    path.write_text(
        json.dumps(
            {"matches": [grype_match("High", "wont-fix"), grype_match("Low", "fixed")]}
        ),
        encoding="utf-8",
    )
    check = check_vulnerability_policy(path)
    assert check["status"] == PASS
    assert check["evidence"]["blocking_findings"] == []


def test_scan_without_matches_list_fails(tmp_path: Path) -> None:
    path = tmp_path / "grype.json"
    path.write_text(json.dumps({"descriptor": {}}), encoding="utf-8")
    assert check_vulnerability_policy(path)["status"] == FAIL


# ---------------------------------------------------------------- CLI


def test_cli_writes_canonical_report_and_predicate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = release_source(tmp_path)
    source_sha, _ = git_identity(source)
    output = tmp_path / "out/release-gate.v1.json"
    predicate = tmp_path / "out/predicate.json"
    code = release_gate.main(
        [
            "--root",
            str(source),
            "--protected-main-sha",
            source_sha,
            "--output",
            str(output),
            "--provenance-predicate-output",
            str(predicate),
        ]
    )
    assert code == 2
    report = json.loads(output.read_bytes())
    validate_report(report)
    assert output.read_bytes() == canonical_json(report)
    assert predicate.read_bytes() == canonical_json(provenance_predicate(source_sha))
    stdout = capsys.readouterr().out
    assert f"RELEASE_GATE=BLOCKED SOURCE_SHA={source_sha}" in stdout
    assert "SIGNING_PERFORMED=NO" in stdout
