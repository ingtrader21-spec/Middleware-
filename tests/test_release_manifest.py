from __future__ import annotations

import json
import os
import subprocess
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from scripts.release_manifest import (
    ROOT,
    ReleaseManifestError,
    build_manifest,
    canonical_json,
    load_manifest,
    validate_manifest,
    verify_workspace,
)


SOURCE_SHA = "a" * 40
TREE_ID = "b" * 40
IMAGE_DIGEST = "sha256:" + ("c" * 64)


def evidence(tmp_path: Path) -> tuple[Path, Path]:
    sbom = tmp_path / "middleware.spdx.json"
    report = tmp_path / "middleware.grype.json"
    sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
    report.write_text('{"matches":[]}\n', encoding="utf-8")
    return sbom, report


def manifest(tmp_path: Path) -> dict:
    sbom, report = evidence(tmp_path)
    return build_manifest(
        root=ROOT,
        source_sha=SOURCE_SHA,
        git_tree_id=TREE_ID,
        image_digest=IMAGE_DIGEST,
        built_at="2026-08-28T12:00:00Z",
        run_id=12345,
        run_attempt=1,
        sbom_path=sbom,
        vulnerability_report_path=report,
    )


def test_generated_release_manifest_matches_json_schema(tmp_path: Path) -> None:
    value = manifest(tmp_path)
    schema = json.loads(
        (ROOT / "contracts/release-manifest.v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    assert value["image"]["reference"].endswith(IMAGE_DIGEST)
    assert value["promotion"]["staging_and_production_same_digest"] is True
    assert (
        value["runtime"]["schema_or_migration_head"] == "0070_agent_provisioning_lifecycle"
    )


def test_manifest_is_canonical_and_binds_workspace_evidence(tmp_path: Path) -> None:
    source_sha = (
        os.environ.get("CODESTRA_TEST_SOURCE_SHA")
        or subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    tree_id = (
        os.environ.get("CODESTRA_TEST_GIT_TREE_ID")
        or subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    sbom, report = evidence(tmp_path)
    value = build_manifest(
        root=ROOT,
        source_sha=source_sha,
        git_tree_id=tree_id,
        image_digest=IMAGE_DIGEST,
        built_at="2026-08-28T12:00:00Z",
        run_id=12345,
        run_attempt=1,
        sbom_path=sbom,
        vulnerability_report_path=report,
    )
    path = tmp_path / "release-manifest.json"
    path.write_bytes(canonical_json(value))

    loaded = load_manifest(path)
    if os.environ.get("CODESTRA_TEST_SOURCE_SHA"):
        with patch(
            "scripts.release_manifest._git_identity",
            return_value=(source_sha, tree_id),
        ):
            verify_workspace(loaded, root=ROOT, evidence_dir=tmp_path)
    else:
        verify_workspace(loaded, root=ROOT, evidence_dir=tmp_path)

    sbom_path = tmp_path / loaded["artifacts"]["sbom"]["path"]
    sbom_path.write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(ReleaseManifestError, match="evidence digest mismatch"):
        if os.environ.get("CODESTRA_TEST_SOURCE_SHA"):
            with patch(
                "scripts.release_manifest._git_identity",
                return_value=(source_sha, tree_id),
            ):
                verify_workspace(loaded, root=ROOT, evidence_dir=tmp_path)
        else:
            verify_workspace(loaded, root=ROOT, evidence_dir=tmp_path)


def test_manifest_rejects_substitution_and_unknown_fields(tmp_path: Path) -> None:
    value = manifest(tmp_path)
    replaced = deepcopy(value)
    replaced["image"]["digest"] = "sha256:" + ("d" * 64)
    with pytest.raises(ReleaseManifestError, match="image.reference"):
        validate_manifest(replaced)

    extended = deepcopy(value)
    extended["signature"] = "untrusted-inline-value"
    with pytest.raises(ReleaseManifestError, match="fields"):
        validate_manifest(extended)

    with pytest.raises(ReleaseManifestError, match="expected release"):
        validate_manifest(value, expected_source_sha="f" * 40)


def test_manifest_rejects_noncanonical_serialization(tmp_path: Path) -> None:
    value = manifest(tmp_path)
    path = tmp_path / "release-manifest.json"
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    with pytest.raises(ReleaseManifestError, match="not canonical"):
        load_manifest(path)


def test_manifest_names_the_current_repository_and_keeps_pinned_historical_releases(
    tmp_path: Path,
) -> None:
    """New releases must name ingtrader21-spec/Middleware- and live in the
    ghcr.io/ingtrader21-spec package. Releases signed before the repository transfer
    keep appolon1908-hue/Middleware- and the ghcr.io/appolon1908-hue package, but only
    for the exact source SHA / image digest pairs pinned in HISTORICAL_RELEASES; the
    same rule is expressed by the JSON schema so both verifiers agree."""
    from scripts.release_manifest import (
        CERTIFICATE_IDENTITY,
        HISTORICAL_CERTIFICATE_IDENTITY,
        HISTORICAL_IMAGE_REPOSITORY,
        HISTORICAL_RELEASES,
        HISTORICAL_REPOSITORY,
        IMAGE_REPOSITORY,
        REPOSITORY,
        expected_certificate_identity,
    )

    assert REPOSITORY == "ingtrader21-spec/Middleware-"
    assert HISTORICAL_REPOSITORY == "appolon1908-hue/Middleware-"
    assert IMAGE_REPOSITORY == "ghcr.io/ingtrader21-spec/codestra-middleware"
    assert HISTORICAL_IMAGE_REPOSITORY == "ghcr.io/appolon1908-hue/codestra-middleware"
    assert CERTIFICATE_IDENTITY.startswith("https://github.com/ingtrader21-spec/Middleware-/")
    assert HISTORICAL_CERTIFICATE_IDENTITY.startswith("https://github.com/appolon1908-hue/Middleware-/")
    assert HISTORICAL_RELEASES, "the pinned pre-transfer releases must stay recorded"
    schema = json.loads(
        (ROOT / "contracts/release-manifest.v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    value = manifest(tmp_path)
    assert value["repository"] == REPOSITORY
    assert value["image"]["repository"] == IMAGE_REPOSITORY
    assert value["image"]["reference"] == f"{IMAGE_REPOSITORY}@{value['image']['digest']}"
    assert value["build"]["workflow_identity"] == CERTIFICATE_IDENTITY
    assert value["verification"]["certificate_identity"] == CERTIFICATE_IDENTITY
    assert expected_certificate_identity(value) == CERTIFICATE_IDENTITY
    validate_manifest(value)
    validator.validate(value)

    # A new release published to the pre-transfer package is rejected by both: the
    # transferred repository's Actions token cannot write that namespace, so such a
    # manifest could only come from a bypass.
    old_package = deepcopy(value)
    old_package["image"]["repository"] = HISTORICAL_IMAGE_REPOSITORY
    old_package["image"]["reference"] = f"{HISTORICAL_IMAGE_REPOSITORY}@{value['image']['digest']}"
    with pytest.raises(ReleaseManifestError, match="image.repository"):
        validate_manifest(old_package)
    assert list(validator.iter_errors(old_package))

    # A reference that does not bind the declared package is rejected by both.
    detached = deepcopy(value)
    detached["image"]["reference"] = f"{HISTORICAL_IMAGE_REPOSITORY}@{value['image']['digest']}"
    with pytest.raises(ReleaseManifestError, match="image.reference"):
        validate_manifest(detached)
    assert list(validator.iter_errors(detached))

    # Any other package is rejected outright by both.
    foreign_package = deepcopy(value)
    foreign_package["image"]["repository"] = "ghcr.io/someone-else/codestra-middleware"
    foreign_package["image"]["reference"] = (
        "ghcr.io/someone-else/codestra-middleware@" + value["image"]["digest"]
    )
    with pytest.raises(ReleaseManifestError, match="image.repository"):
        validate_manifest(foreign_package)
    assert list(validator.iter_errors(foreign_package))

    # A new release signed under the historical identity is rejected by both.
    old_signer = deepcopy(value)
    old_signer["build"]["workflow_identity"] = HISTORICAL_CERTIFICATE_IDENTITY
    old_signer["verification"]["certificate_identity"] = HISTORICAL_CERTIFICATE_IDENTITY
    with pytest.raises(ReleaseManifestError, match="workflow_identity"):
        validate_manifest(old_signer)
    assert list(validator.iter_errors(old_signer))

    # A new release that still carries the pre-transfer name is rejected by both.
    stale = deepcopy(value)
    stale["repository"] = HISTORICAL_REPOSITORY
    with pytest.raises(ReleaseManifestError, match="repository"):
        validate_manifest(stale)
    assert list(validator.iter_errors(stale))

    # A pinned historical release keeps its name and its package and verifies with both.
    source_sha, image_digest = next(iter(HISTORICAL_RELEASES.items()))
    historical = deepcopy(value)
    historical["repository"] = HISTORICAL_REPOSITORY
    historical["source"]["git_sha"] = source_sha
    historical["image"]["repository"] = HISTORICAL_IMAGE_REPOSITORY
    historical["image"]["digest"] = image_digest
    historical["image"]["reference"] = HISTORICAL_IMAGE_REPOSITORY + "@" + image_digest
    historical["release_id"] = f"{source_sha[:12]}-{image_digest.split(':', 1)[1][:12]}"
    historical["build"]["workflow_identity"] = HISTORICAL_CERTIFICATE_IDENTITY
    historical["verification"]["certificate_identity"] = HISTORICAL_CERTIFICATE_IDENTITY
    validate_manifest(historical)
    validator.validate(historical)
    assert expected_certificate_identity(historical) == HISTORICAL_CERTIFICATE_IDENTITY

    # A pinned historical release cannot claim the current identity either.
    relabelled = deepcopy(historical)
    relabelled["verification"]["certificate_identity"] = CERTIFICATE_IDENTITY
    with pytest.raises(ReleaseManifestError, match="certificate identity"):
        validate_manifest(relabelled)
    assert list(validator.iter_errors(relabelled))

    # ... nor claim the current package: the pinned digests were never published there.
    moved = deepcopy(historical)
    moved["image"]["repository"] = IMAGE_REPOSITORY
    moved["image"]["reference"] = IMAGE_REPOSITORY + "@" + image_digest
    with pytest.raises(ReleaseManifestError, match="image.repository"):
        validate_manifest(moved)
    assert list(validator.iter_errors(moved))

    # The historical name is bound to the pair: a different digest for that SHA fails.
    mismatched = deepcopy(historical)
    other_digest = "sha256:" + ("e" * 64)
    mismatched["image"]["digest"] = other_digest
    mismatched["image"]["reference"] = HISTORICAL_IMAGE_REPOSITORY + "@" + other_digest
    mismatched["release_id"] = f"{source_sha[:12]}-{'e' * 12}"
    with pytest.raises(ReleaseManifestError, match="repository"):
        validate_manifest(mismatched)
    assert list(validator.iter_errors(mismatched))

    # Any other repository name is rejected outright.
    foreign = deepcopy(value)
    foreign["repository"] = "someone-else/Middleware-"
    with pytest.raises(ReleaseManifestError, match="repository"):
        validate_manifest(foreign)
    assert list(validator.iter_errors(foreign))
