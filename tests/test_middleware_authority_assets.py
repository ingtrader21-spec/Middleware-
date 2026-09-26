from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_middleware_authority_assets.py"

spec = importlib.util.spec_from_file_location(
    "middleware_authority_asset_validator",
    VALIDATOR,
)
assert spec is not None and spec.loader is not None
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

ASSETS = (
    validator.CATALOG_PATH,
    validator.CURRENT_AUTHORITY_PATH,
    validator.WORKFLOW_PATH,
    validator.BACKUP_SCRIPT_PATH,
    validator.DOCKERFILE_PATH,
    validator.DOCKERIGNORE_PATH,
    validator.DOC_PATH,
)


def _copy_assets(destination: Path) -> None:
    for relative in ASSETS:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


def test_authority_implementation_assets_are_fail_closed() -> None:
    assert validator.validate_assets(ROOT) == []


def test_current_authority_must_require_schema_0010(tmp_path: Path) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.CURRENT_AUTHORITY_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    value["artifactAuthority"]["requiredSchemaHead"] = "0009_observability_incidents"
    path.write_text(json.dumps(value), encoding="utf-8")
    errors = validator.validate_assets(tmp_path)
    assert any(
        "must require schema 0069_agent_provisioning_rls" in error for error in errors
    )


def test_current_candidate_must_remain_pending_and_null(tmp_path: Path) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.CURRENT_AUTHORITY_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    artifacts = value["artifactAuthority"]
    artifacts["candidateStatus"] = "VERIFIED"
    artifacts["currentSignedCandidate"] = dict(artifacts["historicalSignedPredecessor"])
    path.write_text(json.dumps(value), encoding="utf-8")
    errors = validator.validate_assets(tmp_path)
    assert any("exact-main-build pending" in error for error in errors)
    assert any("must be null" in error for error in errors)


def test_observed_signed_evidence_must_use_current_schema_and_remain_non_authoritative(
    tmp_path: Path,
) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.CURRENT_AUTHORITY_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    evidence = value["artifactAuthority"]["latestVerifiedSignedEvidence"]
    evidence["schemaHead"] = "0056_klyrow_delivery_events"
    evidence["promotionAuthorized"] = True
    path.write_text(json.dumps(value), encoding="utf-8")
    errors = validator.validate_assets(tmp_path)
    assert any(
        "schema head must be 0057_platform_service_catalog" in error for error in errors
    )
    assert any("promotion must be forbidden" in error for error in errors)


def test_historical_predecessor_cannot_authorize_promotion(
    tmp_path: Path,
) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.CURRENT_AUTHORITY_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    value["artifactAuthority"]["historicalSignedPredecessor"]["promotionAuthorized"] = (
        True
    )
    path.write_text(json.dumps(value), encoding="utf-8")
    errors = validator.validate_assets(tmp_path)
    assert any("promotion must be forbidden" in error for error in errors)


def test_mirror_workflow_must_require_protected_main(tmp_path: Path) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.WORKFLOW_PATH
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'test "$GITHUB_REF" = "refs/heads/main"',
            'test "$GITHUB_REF" = "refs/heads/staging"',
        ),
        encoding="utf-8",
    )
    errors = validator.validate_assets(tmp_path)
    assert any("protected-main guard" in error for error in errors)


def test_backup_script_must_fail_on_missing_workloads(tmp_path: Path) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.BACKUP_SCRIPT_PATH
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "MISSING_EXPECTED_WORKLOADS",
            "WORKLOADS_OPTIONAL",
        ),
        encoding="utf-8",
    )
    errors = validator.validate_assets(tmp_path)
    assert any("missing workload failure" in error for error in errors)


def test_authority_assets_must_remain_out_of_runtime_stage(
    tmp_path: Path,
) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.DOCKERFILE_PATH
    text = path.read_text(encoding="utf-8")
    marker = "FROM ${TEST_BASE} AS test"
    text = text.replace(
        marker,
        (
            "COPY MIDDLEWARE-AUTHORITY-RECONCILIATION.yaml "
            "./MIDDLEWARE-AUTHORITY-RECONCILIATION.yaml\n" + marker
        ),
        1,
    )
    path.write_text(text, encoding="utf-8")
    errors = validator.validate_assets(tmp_path)
    assert any("leaked into production runtime stage" in error for error in errors)


def test_workflow_must_not_rebuild_legacy_images(tmp_path: Path) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / validator.WORKFLOW_PATH
    path.write_text(
        path.read_text(encoding="utf-8") + "\n# forbidden example\ndocker build .\n",
        encoding="utf-8",
    )
    errors = validator.validate_assets(tmp_path)
    assert any("must copy, not rebuild" in error for error in errors)
