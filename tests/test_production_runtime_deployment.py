from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/validate_production_runtime_deployment.py"
spec = importlib.util.spec_from_file_location(
    "production_runtime_validator", MODULE_PATH
)
assert spec and spec.loader
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

SOURCE_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
IMAGE_REFERENCE = "ghcr.io/ingtrader21-spec/codestra-middleware@" + IMAGE_DIGEST
RELEASE_RUN_ID = "33774790093"
RELEASE_ID = "a" * 12 + "-" + "b" * 12


def valid_response() -> dict[str, str]:
    contract = json.loads(
        (ROOT / "deploy/production/server-command-contract.v1.json").read_text()
    )
    values = {key: "placeholder" for key in contract["response"]["required_keys"]}
    values.update(
        {key: str(value) for key, value in contract["response"]["fixed_values"].items()}
    )
    values.update(
        {
            "SOURCE_SHA": SOURCE_SHA,
            "IMAGE_REFERENCE": IMAGE_REFERENCE,
            "IMAGE_DIGEST": IMAGE_DIGEST,
            "RELEASE_RUN_ID": RELEASE_RUN_ID,
            "RELEASE_ID": RELEASE_ID,
            "VERSION_SOURCE_SHA": SOURCE_SHA,
            "VERSION_IMAGE_DIGEST": IMAGE_DIGEST,
            "VERSION_SCHEMA_HEAD": "0069_progressive_tenant_rls",
            "BACKUP_SHA256": "sha256:" + "c" * 64,
            "CONFIGURATION_CHECKSUM": "d" * 64,
            "ROLLBACK_RTO_SECONDS": "4",
            "OBSERVATION_SECONDS": "30",
            "EVIDENCE_BUNDLE_PATH": f"/home/middleware-deploy/incoming/{RELEASE_ID}.tar.gz",
            "EVIDENCE_BUNDLE_SHA256": "sha256:" + "e" * 64,
        }
    )
    return values


def write_response(path: Path, values: dict[str, str]) -> None:
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))


def test_source_contract_is_fail_closed() -> None:
    validator.validate_source(ROOT)


def test_runtime_workflow_rejects_reenabled_certification_job() -> None:
    workflow = validator.WORKFLOW_PATH.read_text(encoding="utf-8").replace(
        "    if: ${{ false }}",
        "    if: ${{ true }}",
        1,
    )
    with pytest.raises(validator.ValidationError, match="unconditionally disabled"):
        validator.validate_runtime_workflow(workflow)


def test_runtime_workflow_rejects_an_enabled_second_job() -> None:
    workflow = validator.WORKFLOW_PATH.read_text(encoding="utf-8")
    workflow += "\n  deploy:\n    runs-on: ubuntu-24.04\n    steps: []\n"
    with pytest.raises(
        validator.ValidationError, match="only the disabled certify job"
    ):
        validator.validate_runtime_workflow(workflow)


def test_runtime_workflow_requires_authority_marker() -> None:
    workflow = validator.WORKFLOW_PATH.read_text(encoding="utf-8").replace(
        "RUNTIME_MUTATION_DISABLED=true",
        "RUNTIME_MUTATION_DISABLED=false",
        1,
    )
    with pytest.raises(validator.ValidationError, match="RUNTIME_MUTATION_DISABLED"):
        validator.validate_runtime_workflow(workflow)


def test_response_accepts_exact_contract(tmp_path: Path) -> None:
    path = tmp_path / "response.txt"
    write_response(path, valid_response())
    observed = validator.validate_response(
        path,
        source_sha=SOURCE_SHA,
        image_reference=IMAGE_REFERENCE,
        release_run_id=RELEASE_RUN_ID,
        release_id=RELEASE_ID,
    )
    assert observed["DEPLOYMENT_STATUS"] == "PASS"


def test_response_rejects_enabled_effect(tmp_path: Path) -> None:
    values = valid_response()
    values["EXTERNAL_EFFECTS_ENABLED"] = "EMAIL"
    path = tmp_path / "response.txt"
    write_response(path, values)
    with pytest.raises(validator.ValidationError, match="EXTERNAL_EFFECTS_ENABLED"):
        validator.validate_response(
            path,
            source_sha=SOURCE_SHA,
            image_reference=IMAGE_REFERENCE,
            release_run_id=RELEASE_RUN_ID,
            release_id=RELEASE_ID,
        )


def test_response_rejects_unsafe_evidence_path(tmp_path: Path) -> None:
    values = valid_response()
    values["EVIDENCE_BUNDLE_PATH"] = "/tmp/../../root/evidence.tar.gz"
    path = tmp_path / "response.txt"
    write_response(path, values)
    with pytest.raises(validator.ValidationError, match="unsafe evidence"):
        validator.validate_response(
            path,
            source_sha=SOURCE_SHA,
            image_reference=IMAGE_REFERENCE,
            release_run_id=RELEASE_RUN_ID,
            release_id=RELEASE_ID,
        )


def test_evidence_accepts_complete_pass_bundle(tmp_path: Path) -> None:
    result = {
        "schema_version": "1.0",
        "result": "PASS",
        "source_sha": SOURCE_SHA,
        "image_reference": IMAGE_REFERENCE,
        "release_run_id": int(RELEASE_RUN_ID),
        "release_id": RELEASE_ID,
        "runtime": {
            "health": "PASS",
            "readiness": "PASS",
            "version": "PASS",
            "capabilities": "PASS",
            "external_effects_enabled": "NONE",
            "business_writes_enabled": False,
            "calls_placed": 0,
            "gateway_exposure": "NONE",
        },
        "backup": {"status": "PASS", "restore_rehearsal": "PASS"},
        "rollback": {"status": "PASS"},
        "data_integrity": "PASS",
    }
    archive_path = tmp_path / "evidence.tar.gz"
    raw = json.dumps(result).encode()
    info = tarfile.TarInfo("./result.json")
    info.size = len(raw)
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.addfile(info, io.BytesIO(raw))
    digest = "sha256:" + hashlib.sha256(archive_path.read_bytes()).hexdigest()
    validator.validate_evidence(
        archive_path,
        expected_sha256=digest,
        source_sha=SOURCE_SHA,
        image_reference=IMAGE_REFERENCE,
        release_run_id=RELEASE_RUN_ID,
        release_id=RELEASE_ID,
    )
