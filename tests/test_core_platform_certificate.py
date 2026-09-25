"""PAS-251 CORE-CERT-01: the certificate candidate is internally consistent and fail-closed."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_core_platform_certificate.py"
EVIDENCE = ROOT / "docs" / "evidence" / "pas251-core-cert-20260924"

_spec = importlib.util.spec_from_file_location(
    "validate_core_platform_certificate", SCRIPT
)
assert _spec is not None and _spec.loader is not None
cert = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cert
_spec.loader.exec_module(cert)


def _load() -> tuple[dict[str, Any], dict[str, Any], str]:
    return (
        json.loads((EVIDENCE / cert.CERTIFICATE_FILE).read_text(encoding="utf-8")),
        json.loads((EVIDENCE / cert.BLOCKER_FILE).read_text(encoding="utf-8")),
        (EVIDENCE / cert.README_FILE).read_text(encoding="utf-8"),
    )


def _rebind(certificate: dict[str, Any], matrix: dict[str, Any]) -> None:
    certificate["blocker_matrix_sha256"] = cert.canonical_sha256(matrix)


def _component(certificate: dict[str, Any], cid: str) -> dict[str, Any]:
    return next(c for c in certificate["components"] if c["id"] == cid)


def test_committed_candidate_is_consistent_and_blocked() -> None:
    certificate, matrix, readme = _load()
    errors, derived = cert.validate(certificate, matrix, readme)
    assert errors == []
    assert derived == "BLOCKED"
    assert certificate["certificate"] == "BLOCKED"
    assert certificate["production_go"] is False
    assert certificate["production_mutation"] is False


def test_cli_reports_blocked_and_exits_zero_when_consistent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cert.main(["--dir", str(EVIDENCE)]) == 0
    out = capsys.readouterr().out
    assert "CERTIFICATE=BLOCKED" in out
    assert "CONSISTENT=yes" in out


def test_every_core_component_and_gate_is_recorded() -> None:
    certificate, _, _ = _load()
    assert sorted(c["id"] for c in certificate["components"]) == sorted(
        cert.REQUIRED_COMPONENTS
    )
    for component in certificate["components"]:
        assert set(component["gates"]) == set(cert.MANDATORY_GATES)


def test_declaring_ready_over_open_blockers_is_rejected() -> None:
    certificate, matrix, readme = _load()
    certificate["certificate"] = "READY"
    certificate["production_go"] = True
    errors, derived = cert.validate(certificate, matrix, None)
    assert derived == "BLOCKED"
    assert any("declares READY but the evidence derives BLOCKED" in e for e in errors)
    assert any("production_go" in e for e in errors)


def test_pass_without_citation_is_rejected() -> None:
    certificate, matrix, _ = _load()
    gate = _component(certificate, "middleware")["gates"]["protected_main"]
    assert gate["status"] == "PASS"
    gate["evidence"] = ["observed:someone said so"]
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("PASS requires at least one repo: or url: citation" in e for e in errors)


def test_non_pass_gate_without_blocker_is_rejected() -> None:
    certificate, matrix, _ = _load()
    gate = _component(certificate, "openbao")["gates"]["secret_binding"]
    assert gate["status"] != "PASS"
    gate["blockers"] = []
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("requires at least one blocker" in e for e in errors)


def test_orphan_open_blocker_is_rejected() -> None:
    certificate, matrix, _ = _load()
    orphan = copy.deepcopy(matrix["blockers"][0])
    orphan["id"] = "PAS251-B999"
    matrix["blockers"].append(orphan)
    _rebind(certificate, matrix)
    errors, _ = cert.validate(certificate, matrix, None)
    assert any(
        "open blockers not cited by any gate: ['PAS251-B999']" in e for e in errors
    )


def test_blocker_matrix_drift_is_rejected() -> None:
    certificate, matrix, _ = _load()
    matrix["blockers"][0]["observed"] += " (edited after binding)"
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("blocker_matrix_sha256 drift" in e for e in errors)


def test_malformed_sha_and_digest_are_rejected() -> None:
    certificate, matrix, _ = _load()
    middleware = _component(certificate, "middleware")
    middleware["protected_main_sha"] = "0606b0d"
    middleware["artifact"]["base_image_digests"].append(
        {"image": "x", "digest": "sha256:abc"}
    )
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("protected_main_sha" in e for e in errors)
    assert any("malformed digest" in e for e in errors)


def test_missing_component_is_rejected() -> None:
    certificate, matrix, _ = _load()
    certificate["components"] = [
        c for c in certificate["components"] if c["id"] != "openbao"
    ]
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("components must be exactly" in e for e in errors)


def test_readme_hash_and_verdict_are_bound() -> None:
    certificate, matrix, readme = _load()
    errors, _ = cert.validate(
        certificate, matrix, readme.replace("CERTIFICATE=BLOCKED", "CERTIFICATE=READY")
    )
    assert any("CERTIFICATE=BLOCKED line" in e for e in errors)
    certificate["observed_at"] = "2099-01-01T00:00:00Z"
    errors, _ = cert.validate(certificate, matrix, readme)
    assert any("CERTIFICATE_CANDIDATE_SHA256" in e for e in errors)


def test_secret_shaped_values_are_rejected() -> None:
    certificate, matrix, _ = _load()
    certificate["notes"] = "token hvs." + "A" * 30
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("secret-shaped" in e for e in errors)


def test_cited_repository_paths_exist_and_cannot_escape(tmp_path: Path) -> None:
    certificate, matrix, _ = _load()
    gate = _component(certificate, "middleware")["gates"]["protected_main"]
    gate["evidence"] = ["repo:../outside.txt"]
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("escapes the repository" in e for e in errors)
    gate["evidence"] = ["repo:docs/evidence/does-not-exist.md"]
    errors, _ = cert.validate(certificate, matrix, None)
    assert any("does not exist" in e for e in errors)


def test_ready_is_admissible_only_when_every_gate_passes_with_digests(
    tmp_path: Path,
) -> None:
    """The rule is not hard-wired to BLOCKED: an all-PASS synthetic record derives READY."""
    (tmp_path / "evidence.md").write_text("synthetic\n", encoding="utf-8")
    certificate, matrix, _ = _load()
    for blocker in matrix["blockers"]:
        blocker["status"] = "CLEARED"
        blocker["evidence"] = ["repo:evidence.md"]
    for component in certificate["components"]:
        component["artifact"]["base_image_digests"] = []
        component["artifact"]["release_digests"] = [
            {"image": "synthetic", "digest": "sha256:" + "a" * 64}
        ]
        for gate in component["gates"].values():
            gate.update(status="PASS", blockers=[], evidence=["repo:evidence.md"])
    certificate["certificate"] = "READY"
    certificate["production_go"] = True
    _rebind(certificate, matrix)
    errors, derived = cert.validate(certificate, matrix, None, repo_root=tmp_path)
    assert errors == []
    assert derived == "READY"

    component = _component(certificate, "caddy")
    component["artifact"]["release_digests"] = []
    errors, derived = cert.validate(certificate, matrix, None, repo_root=tmp_path)
    assert any("PASS requires a recorded release digest" in e for e in errors)
