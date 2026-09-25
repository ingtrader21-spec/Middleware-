"""Rejection tests for the release evidence trust boundary."""

import io
import json
import zipfile

import pytest

from scripts import certify_mcr_release as cert

SHA = "a" * 40


def bundle():
    cases = cert.SCENARIOS
    xml = (
        "<testsuite>"
        + "".join(f'<testcase classname="mcr" name="{name}"/>' for name in cases)
        + "</testsuite>"
    ).encode()
    manifest = {
        "source_sha": SHA,
        "dependencies": {key: SHA for key in cert.DEPENDENCIES},
        "scenarios": {
            name: {"test": f"mcr::{name}", "evidence": f"{name}.json"} for name in cases
        },
    }
    files = {"manifest.json": json.dumps(manifest).encode(), "results.xml": xml}
    for name in cases:
        files[f"{name}.json"] = json.dumps(
            {
                "source_sha": SHA,
                "scenario": name,
                "result": "pass",
                "observations": ["synthetic test evidence"],
            }
        ).encode()
    return files


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        for name, data in files.items():
            output.writestr(name, data)
    return stream.getvalue()


def test_complete_bound_evidence_passes_validation():
    assert cert.validate_bundle(archive(bundle()), SHA)["source_sha"] == SHA


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "dependency",
        "scenario",
        "skip",
        "failure",
        "empty",
        "observation",
        "duplicate",
    ],
)
def test_incomplete_or_unbound_evidence_is_rejected(mutation):
    files = bundle()
    manifest = json.loads(files["manifest.json"])
    if mutation == "stale":
        manifest["source_sha"] = "b" * 40
    elif mutation == "dependency":
        del manifest["dependencies"]["L"]
    elif mutation == "scenario":
        del manifest["scenarios"]["ui_states"]
    elif mutation in ("skip", "failure"):
        tag = "skipped" if mutation == "skip" else "failure"
        files["results.xml"] = files["results.xml"].replace(
            b"/>", f"><{tag}/></testcase>".encode(), 1
        )
    elif mutation == "empty":
        files["results.xml"] = b"<testsuite/>"
    elif mutation == "observation":
        files["ui_states.json"] = b"{}"
    elif mutation == "duplicate":
        manifest["scenarios"]["ui_states"]["test"] = "mcr::api_openapi"
    files["manifest.json"] = json.dumps(manifest).encode()
    with pytest.raises(ValueError):
        cert.validate_bundle(archive(files), SHA)


def test_no_evidence_is_never_success():
    with pytest.raises(ValueError):
        cert.validate_bundle(archive({}), SHA)


def test_artifact_digest_mismatch_is_rejected():
    with pytest.raises(ValueError):
        cert.verify_digest(b"changed", "sha256:" + "0" * 64)


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "b" * 40),
        ("conclusion", "skipped"),
        ("status", "in_progress"),
        ("event", "pull_request_target"),
        ("path", ".github/workflows/untrusted.yml"),
    ],
)
def test_wrong_or_incomplete_actions_run_is_rejected(field, value):
    run = {
        "head_sha": SHA,
        "conclusion": "success",
        "status": "completed",
        "event": "pull_request",
        "path": cert.WORKFLOW,
        "head_repository": {"full_name": cert.REPOSITORY},
    }
    run[field] = value
    with pytest.raises(ValueError):
        cert.validate_run(run, SHA)


def test_suite_failure_counters_cannot_hide_missing_failure_elements():
    files = bundle()
    files["results.xml"] = files["results.xml"].replace(
        b"<testsuite>", b'<testsuite failures="1">'
    )
    with pytest.raises(ValueError):
        cert.validate_bundle(archive(files), SHA)


def test_path_traversal_is_rejected_without_extracting():
    files = bundle()
    files["../outside"] = b"unsafe"
    with pytest.raises(ValueError):
        cert.validate_bundle(archive(files), SHA)


def test_missing_main_protection_is_not_certified(monkeypatch):
    monkeypatch.setattr(cert, "api", lambda path: [])
    with pytest.raises(ValueError, match="protection"):
        cert.protected_ci(SHA)


def test_dirty_checkout_stops_before_network(monkeypatch):
    def local(*args):
        if args[1] == "branch":
            return cert.BRANCH
        if args[1] == "rev-parse":
            return SHA
        if args[1] == "status":
            return "?? evidence.json"
        raise AssertionError("must stop before contacting network")

    monkeypatch.setattr(cert, "command", local)
    with pytest.raises(ValueError, match="clean"):
        cert.certify(SHA, 123)


def test_generic_pass_claim_cannot_replace_specific_scenario_assertions():
    files = bundle()
    observed = json.loads(files["ui_states.json"])
    observed["observations"] = ["everything passed"]
    files["ui_states.json"] = json.dumps(observed).encode()
    with pytest.raises(ValueError):
        cert.validate_bundle(archive(files), SHA)
