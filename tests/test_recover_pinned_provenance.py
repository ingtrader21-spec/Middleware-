import base64
import json
from pathlib import Path

import pytest

from scripts.recover_pinned_provenance import (
    DIGEST,
    REPOSITORY,
    SOURCE,
    check_attestation,
    recover,
)
from scripts.release_manifest import (
    HISTORICAL_CERTIFICATE_IDENTITY,
    HISTORICAL_IMAGE_REPOSITORY,
    HISTORICAL_REPOSITORY,
    ROOT,
    ReleaseManifestError,
    build_manifest,
    canonical_json,
    validate_manifest,
)


def envelope(path: Path, predicate: dict, kind="https://spdx.dev/Document") -> dict:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": kind,
        "subject": [{"name": REPOSITORY, "digest": {"sha256": DIGEST[7:]}}],
        "predicate": predicate,
    }
    write_envelope(path, statement)
    return statement


def write_envelope(path: Path, statement: dict) -> None:
    path.write_text(json.dumps({"payload": base64.b64encode(
        json.dumps(statement).encode()
    ).decode()}))


@pytest.fixture
def original(tmp_path):
    sbom = tmp_path / "middleware.spdx.json"
    report = tmp_path / "middleware.grype.json"
    sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n')
    report.write_text('{"matches":[]}\n')
    # Build a current-format manifest first, then explicitly project the exact
    # pinned pre-transfer identity. build_manifest() intentionally creates only
    # current releases; recovery tests must not add a production path for minting
    # new historical manifests.
    fixture_source = "f" * 40
    manifest = build_manifest(
        root=ROOT, source_sha=fixture_source, git_tree_id="b" * 40,
        image_digest=DIGEST, built_at="2026-09-04T21:43:24Z",
        run_id=33922375053, run_attempt=1, sbom_path=sbom,
        vulnerability_report_path=report,
    )
    manifest["repository"] = HISTORICAL_REPOSITORY
    manifest["source"]["git_sha"] = SOURCE
    manifest["image"]["repository"] = HISTORICAL_IMAGE_REPOSITORY
    manifest["image"]["reference"] = f"{HISTORICAL_IMAGE_REPOSITORY}@{DIGEST}"
    manifest["build"]["workflow_identity"] = HISTORICAL_CERTIFICATE_IDENTITY
    manifest["verification"]["certificate_identity"] = HISTORICAL_CERTIFICATE_IDENTITY
    manifest["release_id"] = f"{SOURCE[:12]}-{DIGEST[7:19]}"
    validate_manifest(
        manifest,
        expected_source_sha=SOURCE,
        expected_image_digest=DIGEST,
    )
    (tmp_path / "release-manifest.v1.json").write_bytes(canonical_json(manifest))
    verification = tmp_path / "verified.json"
    envelope(verification, json.loads(sbom.read_text()))
    return tmp_path, verification


def test_recovers_original_source_and_checks_published_provenance(original):
    evidence, verification = original
    predicate = recover(evidence, verification)
    assert predicate["buildDefinition"]["externalParameters"]["sourceSha"] == SOURCE
    published = evidence / "provenance.json"
    envelope(published, predicate, "https://slsa.dev/provenance/v1")
    check_attestation(published, "https://slsa.dev/provenance/v1", predicate)


@pytest.mark.parametrize("filename", ["middleware.spdx.json", "middleware.grype.json"])
def test_rejects_changed_evidence(original, filename):
    evidence, verification = original
    (evidence / filename).write_text("{}")
    with pytest.raises(ValueError, match="hash mismatch"):
        recover(evidence, verification)


@pytest.mark.parametrize("field", ["source", "image", "run"])
def test_rejects_different_release(original, field):
    evidence, verification = original
    path = evidence / "release-manifest.v1.json"
    value = json.loads(path.read_text())
    if field == "source":
        value["source"]["git_sha"] = "a" * 40
    elif field == "image":
        value["image"]["digest"] = "sha256:" + "f" * 64
    else:
        value["build"]["run_id"] += 1
    path.write_bytes(canonical_json(value))
    with pytest.raises((ValueError, ReleaseManifestError)):
        recover(evidence, verification)


@pytest.mark.parametrize("field", ["subject", "predicate", "predicateType", "_type"])
def test_rejects_mismatched_attestation(tmp_path, field):
    path = tmp_path / "verified.json"
    predicate = {"spdxVersion": "SPDX-2.3"}
    statement = envelope(path, predicate)
    statement[field] = [] if field == "subject" else "wrong"
    write_envelope(path, statement)
    with pytest.raises(ValueError, match="differs"):
        check_attestation(path, "https://spdx.dev/Document", predicate)


def test_rejects_empty_attestations(tmp_path):
    path = tmp_path / "verified.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="empty"):
        check_attestation(path, "https://spdx.dev/Document", {})
