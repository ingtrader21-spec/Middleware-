from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = ROOT / "config" / "runtime-source-state.json"


def _load_authority() -> dict[str, object]:
    value = json.loads(AUTHORITY_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_runtime_source_authority_resolves_protected_main_dynamically() -> None:
    authority = _load_authority()
    assert authority["schemaVersion"] == 2
    assert authority["kind"] == "middleware-runtime-source-authority"

    repository = authority["repositoryAuthority"]
    assert isinstance(repository, dict)
    assert repository["repository"] == "ingtrader21-spec/Middleware-"
    assert repository["protectedSourceRef"] == "refs/heads/main"
    assert repository["staticSourceShaAllowed"] is False
    assert repository["ruleset"] == "middleware-main-production-authority"

    raw = json.dumps(authority, sort_keys=True)
    assert "feature/intake-runtime-v1" not in raw
    assert "f3437709c06747249586598590145234ea2c7327" not in raw


def test_runtime_source_authority_declares_release_controls() -> None:
    authority = _load_authority()
    artifacts = authority["artifactAuthority"]
    assert isinstance(artifacts, dict)

    expected = {
        "releaseManifestSchema": "contracts/release-manifest.v1.schema.json",
        "releaseWorkflow": ".github/workflows/release.yml",
        "productionAdmissionWorkflow": (
            ".github/workflows/automated-production-promotion.yml"
        ),
        "runtimeCertificationWorkflow": (
            ".github/workflows/production-runtime-certification.yml"
        ),
        "runtimeProfileRegistry": "config/runtime-profiles.v1.json",
    }
    assert artifacts == expected

    # The Docker test target deliberately packages only runtime-relevant source,
    # contracts, configuration, documentation, and the certification workflow.
    # Repository-only release/admission workflow paths are still protected by the
    # exact dictionary comparison above and by repository governance validation.
    packaged_paths = (
        expected["releaseManifestSchema"],
        expected["runtimeCertificationWorkflow"],
        expected["runtimeProfileRegistry"],
    )
    for path in packaged_paths:
        assert (ROOT / path).is_file(), path


def test_runtime_state_requires_execution_evidence_and_authorizes_nothing() -> None:
    authority = _load_authority()
    runtime = authority["runtimeAuthority"]
    assert isinstance(runtime, dict)
    assert runtime["runtimeState"] == "must_be_proven_at_execution"
    assert runtime["repositoryMetadataClaimsDeployment"] is False
    assert runtime["certificationIssue"] == 118
    assert len(runtime["requiredEvidence"]) >= 6

    safety = authority["safetyBoundary"]
    assert isinstance(safety, dict)
    assert safety["callsPlacedExpected"] == 0
    assert all(
        value is False
        for key, value in safety.items()
        if key != "callsPlacedExpected"
    )


def test_historical_snapshots_are_explicitly_non_authoritative() -> None:
    authority = _load_authority()
    snapshots = authority["historicalSnapshots"]
    assert isinstance(snapshots, list)
    assert {item["path"] for item in snapshots} == {
        "MIDDLEWARE-AUTHORITY-RECONCILIATION.yaml",
        "docs/SERVER-RUNTIME-RECONCILIATION-MAP.md",
    }
    for item in snapshots:
        assert item["deploymentAuthority"] is False

    # Documentation is packaged in the Docker test target; the root historical
    # reconciliation YAML is intentionally not part of the test/runtime image.
    assert (ROOT / "docs/SERVER-RUNTIME-RECONCILIATION-MAP.md").is_file()
