from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "middleware-authority-convergence.v1.json"
CURRENT_AUTHORITY = ROOT / "config" / "middleware-forward-release-authority.v1.json"
VALIDATOR = ROOT / "scripts" / "validate_middleware_authority_convergence.py"

spec = importlib.util.spec_from_file_location(
    "middleware_authority_validator",
    VALIDATOR,
)
assert spec is not None and spec.loader is not None
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def _document() -> dict[str, Any]:
    value = json.loads(CATALOG.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _current_authority() -> dict[str, Any]:
    value = json.loads(CURRENT_AUTHORITY.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_reviewed_authority_convergence_record_is_fail_closed() -> None:
    assert validator.validate_document(_document(), root=ROOT) == []
    assert validator.validate_forward_authority(_current_authority()) == []


def test_current_authority_requires_schema_0010_and_new_exact_main_build() -> None:
    value = _current_authority()
    artifacts = value["artifactAuthority"]
    assert artifacts["requiredSchemaHead"] == "0067_service_catalog_monitoring_state"
    assert artifacts["candidateStatus"] == "PENDING_EXACT_PROTECTED_MERGE_BUILD"
    assert artifacts["currentSignedCandidate"] is None


def test_pre_0010_signed_image_is_historical_and_not_promotable() -> None:
    value = _current_authority()
    predecessor = value["artifactAuthority"]["historicalSignedPredecessor"]
    snapshot = _document()["forwardAuthority"]["image"]["currentSignedCandidate"]

    assert predecessor["role"] == "historical-predecessor-only"
    assert predecessor["promotionAuthorized"] is False
    assert predecessor["schemaHead"] == "0009_observability_incidents"
    for key in (
        "sourceSha",
        "gitTreeId",
        "imageDigest",
        "imageReference",
        "releaseId",
        "schemaHead",
        "workflowRunId",
        "artifactId",
    ):
        assert predecessor[key] == snapshot[key]


def test_current_candidate_cannot_be_filled_with_historical_predecessor() -> None:
    value = copy.deepcopy(_current_authority())
    artifacts = value["artifactAuthority"]
    artifacts["currentSignedCandidate"] = copy.deepcopy(
        artifacts["historicalSignedPredecessor"]
    )
    errors = validator.validate_forward_authority(value)
    assert any("current signed candidate must be null" in error for error in errors)


def test_required_schema_head_cannot_regress_to_0009() -> None:
    value = copy.deepcopy(_current_authority())
    value["artifactAuthority"]["requiredSchemaHead"] = "0009_observability_incidents"
    errors = validator.validate_forward_authority(value)
    assert any("current required schema head" in error for error in errors)


def test_historical_predecessor_cannot_become_promotable() -> None:
    value = copy.deepcopy(_current_authority())
    value["artifactAuthority"]["historicalSignedPredecessor"]["promotionAuthorized"] = (
        True
    )
    errors = validator.validate_forward_authority(value)
    assert any("promotion must be forbidden" in error for error in errors)


def test_legacy_family_cannot_become_forward_authority() -> None:
    value = copy.deepcopy(_document())
    family = value["runtimeImageFamilies"][1]
    family["role"] = "forward"
    errors = validator.validate_document(value, root=ROOT)
    assert any("legacy family must be rollback-only" in error for error in errors)


def test_snapshot_predecessor_reference_must_bind_exact_digest() -> None:
    value = copy.deepcopy(_document())
    candidate = value["forwardAuthority"]["image"]["currentSignedCandidate"]
    candidate["imageReference"] = (
        "ghcr.io/appolon1908-hue/codestra-middleware@"
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    )
    errors = validator.validate_document(value, root=ROOT)
    assert any("snapshot candidate image reference" in error for error in errors)


def test_snapshot_must_match_historical_predecessor_evidence() -> None:
    value = copy.deepcopy(_document())
    value["forwardAuthority"]["image"]["currentSignedCandidate"]["schemaHead"] = (
        "0059_integrated_monitoring"
    )
    errors = validator.validate_document(value, root=ROOT)
    assert any("snapshot predecessor" in error for error in errors)


def test_workload_cannot_appear_in_multiple_image_families() -> None:
    value = copy.deepcopy(_document())
    duplicate = value["runtimeImageFamilies"][0]["workloads"][0]
    value["runtimeImageFamilies"][1]["workloads"].append(duplicate)
    value["serverA"]["runtimeWorkloadsCatalogued"] += 1
    errors = validator.validate_document(value, root=ROOT)
    assert any(
        "workload appears in multiple image families" in error for error in errors
    )


def test_server_a_mutation_cannot_be_claimed_by_repository_metadata() -> None:
    value = copy.deepcopy(_document())
    value["serverA"]["runtimeMutationStatus"] = "PASS"
    value["serverA"]["productionChanged"] = True
    errors = validator.validate_document(value, root=ROOT)
    assert any("must not claim a Server A mutation" in error for error in errors)
    assert any("productionChanged must be false" in error for error in errors)
