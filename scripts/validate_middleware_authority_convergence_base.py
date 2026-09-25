#!/usr/bin/env python3
"""Validate Middleware source authority and historical Server A inventory."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / "config" / "middleware-authority-convergence.v1.json"
CURRENT_AUTHORITY_PATH = (
    ROOT / "config" / "middleware-forward-release-authority.v1.json"
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
CANONICAL_REPOSITORY = "ingtrader21-spec/Middleware-"
# Forward releases publish to the repository owner's package; every signed
# image observed so far was published to the pre-transfer package and stays
# referenced there by digest.
CANONICAL_IMAGE_REPOSITORY = "ghcr.io/ingtrader21-spec/codestra-middleware"
OBSERVED_IMAGE_REPOSITORY = "ghcr.io/appolon1908-hue/codestra-middleware"
LEGACY_REPOSITORY = "Codestra-SRL/codestra-middleware"
LEGACY_BACKUP_REPOSITORY = (
    "ghcr.io/appolon1908-hue/codestra-middleware-legacy"
)
CURRENT_SCHEMA_HEAD = "0069_agent_provisioning_rls"
PREDECESSOR_SCHEMA_HEAD = "0009_observability_incidents"
PENDING_CANDIDATE_STATUS = "PENDING_EXACT_PROTECTED_MERGE_BUILD"


def _mapping(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return {}
    return value


def _list(value: Any, path: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return []
    return value


def _expect(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def _sha(value: Any) -> bool:
    return isinstance(value, str) and SHA40.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def _load_json_object(
    path: Path,
    *,
    label: str,
    errors: list[str],
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label} cannot be loaded: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} root must be an object")
        return {}
    return value


def _validate_signed_predecessor(
    value: Any,
    *,
    errors: list[str],
) -> dict[str, Any]:
    predecessor = _mapping(
        value,
        "artifactAuthority.historicalSignedPredecessor",
        errors,
    )
    _expect(
        predecessor.get("role") == "historical-predecessor-only",
        "signed predecessor must be historical only",
        errors,
    )
    _expect(
        predecessor.get("promotionAuthorized") is False,
        "signed predecessor promotion must be forbidden",
        errors,
    )
    source_sha = predecessor.get("sourceSha")
    digest = predecessor.get("imageDigest")
    _expect(_sha(source_sha), "predecessor source SHA is invalid", errors)
    _expect(
        _sha(predecessor.get("gitTreeId")),
        "predecessor Git tree ID is invalid",
        errors,
    )
    _expect(_digest(digest), "predecessor image digest is invalid", errors)
    _expect(
        predecessor.get("imageReference")
        == f"{OBSERVED_IMAGE_REPOSITORY}@{digest}",
        "predecessor image reference must bind the observed repository and digest",
        errors,
    )
    _expect(
        predecessor.get("schemaHead") == PREDECESSOR_SCHEMA_HEAD,
        "historical predecessor schema head mismatch",
        errors,
    )
    _expect(
        predecessor.get("verification") == "PASS",
        "predecessor verification must be PASS",
        errors,
    )
    _expect(
        predecessor.get("signature") == "sigstore-keyless-verified",
        "predecessor signature evidence missing",
        errors,
    )
    _expect(
        predecessor.get("sbom") == "present",
        "predecessor SBOM evidence missing",
        errors,
    )
    _expect(
        predecessor.get("vulnerabilityGate") == "PASS",
        "predecessor vulnerability gate must pass",
        errors,
    )
    _expect(
        isinstance(predecessor.get("workflowRunId"), int)
        and predecessor["workflowRunId"] > 0,
        "predecessor workflowRunId invalid",
        errors,
    )
    _expect(
        isinstance(predecessor.get("artifactId"), int)
        and predecessor["artifactId"] > 0,
        "predecessor artifactId invalid",
        errors,
    )
    _expect(
        _digest(predecessor.get("artifactArchiveDigest")),
        "predecessor artifact archive digest invalid",
        errors,
    )
    return predecessor


def validate_forward_authority(
    authority: dict[str, Any],
) -> list[str]:
    """Validate the current, fail-closed forward release authority."""

    errors: list[str] = []
    _expect(
        authority.get("schemaVersion") == 1,
        "forward authority schemaVersion must be 1",
        errors,
    )
    _expect(
        authority.get("kind") == "middleware-forward-release-authority",
        "forward authority kind mismatch",
        errors,
    )

    repository = _mapping(
        authority.get("repositoryAuthority"),
        "repositoryAuthority",
        errors,
    )
    _expect(
        repository.get("repository") == CANONICAL_REPOSITORY,
        "forward authority repository mismatch",
        errors,
    )
    _expect(
        repository.get("protectedRef") == "refs/heads/main",
        "forward authority must resolve protected main",
        errors,
    )
    _expect(
        repository.get("staticSourceShaAllowed") is False,
        "static source SHA authority must remain forbidden",
        errors,
    )
    _expect(
        repository.get("ruleset") == "middleware-main-production-authority",
        "forward authority ruleset mismatch",
        errors,
    )

    artifacts = _mapping(
        authority.get("artifactAuthority"),
        "artifactAuthority",
        errors,
    )
    _expect(
        artifacts.get("imageRepository") == CANONICAL_IMAGE_REPOSITORY,
        "forward image repository mismatch",
        errors,
    )
    _expect(
        artifacts.get("releaseWorkflow") == ".github/workflows/release.yml",
        "forward release workflow mismatch",
        errors,
    )
    _expect(
        artifacts.get("releaseManifestSchema")
        == "contracts/release-manifest.v1.schema.json",
        "release manifest schema mismatch",
        errors,
    )
    _expect(
        artifacts.get("requiredSchemaHead") == CURRENT_SCHEMA_HEAD,
        f"current required schema head must be {CURRENT_SCHEMA_HEAD}",
        errors,
    )
    _expect(
        artifacts.get("candidateStatus") == PENDING_CANDIDATE_STATUS,
        "current candidate status must remain pending exact protected merge build",
        errors,
    )
    _expect(
        artifacts.get("currentSignedCandidate") is None,
        "current signed candidate must be null until exact protected-main build",
        errors,
    )
    _validate_signed_predecessor(
        artifacts.get("historicalSignedPredecessor"),
        errors=errors,
    )

    runtime = _mapping(
        authority.get("runtimeAuthority"),
        "runtimeAuthority",
        errors,
    )
    _expect(
        runtime.get("runtimeState") == "must_be_proven_at_execution",
        "runtime state must be proven at execution",
        errors,
    )
    _expect(
        runtime.get("repositoryMetadataClaimsDeployment") is False,
        "repository metadata must not claim deployment",
        errors,
    )
    _expect(
        runtime.get("certificationIssue") == 118,
        "runtime certification issue mismatch",
        errors,
    )
    required_evidence = _list(
        runtime.get("requiredEvidence"),
        "runtimeAuthority.requiredEvidence",
        errors,
    )
    _expect(
        len(required_evidence) >= 7,
        "runtime evidence list is incomplete",
        errors,
    )
    _expect(
        any(CURRENT_SCHEMA_HEAD in str(item) for item in required_evidence),
        "runtime evidence must require the current schema head",
        errors,
    )

    legacy_boundary = _mapping(
        authority.get("legacyBoundary"),
        "legacyBoundary",
        errors,
    )
    _expect(
        legacy_boundary.get("sourceRepository") == LEGACY_REPOSITORY,
        "legacy source repository mismatch",
        errors,
    )
    _expect(
        legacy_boundary.get("imageCatalog")
        == "config/middleware-authority-convergence.v1.json",
        "legacy image catalog mismatch",
        errors,
    )
    for key in (
        "forwardBuildsAuthorized",
        "runtimeExpansionAuthorized",
        "deletionAuthorized",
    ):
        _expect(
            legacy_boundary.get(key) is False,
            f"legacyBoundary.{key} must be false",
            errors,
        )
    _expect(
        legacy_boundary.get("rollbackRetentionRequired") is True,
        "legacy rollback retention must remain required",
        errors,
    )

    safety = _mapping(
        authority.get("safetyBoundary"),
        "forward safetyBoundary",
        errors,
    )
    _expect(
        safety.get("callsPlacedExpected") == 0,
        "forward callsPlacedExpected must be zero",
        errors,
    )
    for key, value in safety.items():
        if key != "callsPlacedExpected":
            _expect(value is False, f"forward safetyBoundary.{key} must be false", errors)

    return errors


def validate_document(
    document: dict[str, Any],
    root: Path = ROOT,
) -> list[str]:
    """Validate the dated Server A inventory against current authority."""

    errors: list[str] = []
    _expect(document.get("schemaVersion") == 1, "schemaVersion must be 1", errors)
    _expect(
        document.get("kind") == "middleware-authority-convergence",
        "kind must be middleware-authority-convergence",
        errors,
    )
    _expect(
        document.get("snapshotRole")
        == "observed-evidence-not-deployment-authority",
        "snapshotRole must explicitly deny deployment authority",
        errors,
    )

    current_authority = _load_json_object(
        root / "config" / "middleware-forward-release-authority.v1.json",
        label="current forward authority",
        errors=errors,
    )
    errors.extend(validate_forward_authority(current_authority))
    current_artifacts = _mapping(
        current_authority.get("artifactAuthority"),
        "current artifactAuthority",
        errors,
    )
    historical_predecessor = _mapping(
        current_artifacts.get("historicalSignedPredecessor"),
        "current historicalSignedPredecessor",
        errors,
    )

    server = _mapping(document.get("serverA"), "serverA", errors)
    _expect(
        server.get("host") == "65.109.65.169",
        "serverA.host mismatch",
        errors,
    )
    _expect(
        server.get("runtimeMutationStatus") == "NOT_EXECUTED",
        "repository evidence must not claim a Server A mutation",
        errors,
    )
    _expect(
        server.get("productionChanged") is False,
        "productionChanged must be false",
        errors,
    )
    _expect(
        server.get("revalidationRequiredBeforeMutation") is True,
        "runtime inventory must be revalidated before mutation",
        errors,
    )

    snapshot_authority = _mapping(
        document.get("forwardAuthority"),
        "snapshot forwardAuthority",
        errors,
    )
    snapshot_source = _mapping(
        snapshot_authority.get("source"),
        "snapshot forwardAuthority.source",
        errors,
    )
    _expect(
        snapshot_source.get("repository") == CANONICAL_REPOSITORY,
        "snapshot source repository mismatch",
        errors,
    )
    _expect(
        snapshot_source.get("protectedRef") == "refs/heads/main",
        "snapshot source must identify protected main",
        errors,
    )
    _expect(
        snapshot_source.get("staticShaIsAuthority") is False,
        "snapshot static SHA must not be authority",
        errors,
    )
    _expect(
        _sha(snapshot_source.get("observedProtectedMainSha")),
        "snapshot observed protected-main SHA is invalid",
        errors,
    )
    _expect(
        _sha(snapshot_source.get("observedGitTreeId")),
        "snapshot observed Git tree ID is invalid",
        errors,
    )

    snapshot_image = _mapping(
        snapshot_authority.get("image"),
        "snapshot forwardAuthority.image",
        errors,
    )
    _expect(
        snapshot_image.get("repository") == OBSERVED_IMAGE_REPOSITORY,
        "snapshot image repository mismatch",
        errors,
    )
    _expect(
        snapshot_image.get("releaseWorkflow") == ".github/workflows/release.yml",
        "snapshot release workflow mismatch",
        errors,
    )
    snapshot_candidate = _mapping(
        snapshot_image.get("currentSignedCandidate"),
        "snapshot signed candidate",
        errors,
    )
    candidate_sha = snapshot_candidate.get("sourceSha")
    candidate_digest = snapshot_candidate.get("imageDigest")
    _expect(_sha(candidate_sha), "snapshot candidate source SHA is invalid", errors)
    _expect(
        _sha(snapshot_candidate.get("gitTreeId")),
        "snapshot candidate Git tree ID is invalid",
        errors,
    )
    _expect(
        _digest(candidate_digest),
        "snapshot candidate image digest is invalid",
        errors,
    )
    _expect(
        snapshot_candidate.get("imageReference")
        == f"{OBSERVED_IMAGE_REPOSITORY}@{candidate_digest}",
        "snapshot candidate image reference mismatch",
        errors,
    )
    _expect(
        candidate_sha == snapshot_source.get("observedProtectedMainSha"),
        "snapshot candidate source does not match its captured source",
        errors,
    )
    _expect(
        snapshot_candidate.get("gitTreeId")
        == snapshot_source.get("observedGitTreeId"),
        "snapshot candidate tree does not match its captured source",
        errors,
    )
    _expect(
        snapshot_candidate.get("schemaHead") == PREDECESSOR_SCHEMA_HEAD,
        "snapshot predecessor schema head mismatch",
        errors,
    )

    predecessor_keys = (
        "sourceSha",
        "gitTreeId",
        "imageDigest",
        "imageReference",
        "releaseId",
        "schemaHead",
        "builtAt",
        "workflowRunId",
        "workflowRunAttempt",
        "artifactId",
        "artifactArchiveDigest",
        "signature",
        "sbom",
        "vulnerabilityGate",
        "verification",
    )
    for key in predecessor_keys:
        _expect(
            snapshot_candidate.get(key) == historical_predecessor.get(key),
            f"snapshot predecessor evidence drifted for {key}",
            errors,
        )
    _expect(
        historical_predecessor.get("promotionAuthorized") is False,
        "historical predecessor must not be promotable",
        errors,
    )

    legacy = _mapping(document.get("legacySourceBackup"), "legacySourceBackup", errors)
    _expect(
        legacy.get("repository") == LEGACY_REPOSITORY,
        "wrong legacy source repository",
        errors,
    )
    _expect(
        legacy.get("role") == "rollback-only-source-history",
        "legacy source must be rollback-only",
        errors,
    )
    _expect(
        legacy.get("protectedRef") == "refs/heads/main",
        "legacy snapshot must identify main",
        errors,
    )
    _expect(
        _sha(legacy.get("observedProtectedMainSha")),
        "legacy observed main SHA invalid",
        errors,
    )
    _expect(
        _sha(legacy.get("observedGitTreeId")),
        "legacy observed tree ID invalid",
        errors,
    )
    for key in (
        "newForwardReleasesAuthorized",
        "deleteAuthorized",
        "forcePushAuthorized",
    ):
        _expect(
            legacy.get(key) is False,
            f"legacySourceBackup.{key} must be false",
            errors,
        )

    comparison = _mapping(document.get("sourceComparison"), "sourceComparison", errors)
    canonical_comparison = _mapping(
        comparison.get("canonical"),
        "sourceComparison.canonical",
        errors,
    )
    legacy_comparison = _mapping(
        comparison.get("legacy"),
        "sourceComparison.legacy",
        errors,
    )
    _expect(
        canonical_comparison.get("currentObservedSha") == candidate_sha,
        "snapshot canonical comparison SHA mismatch",
        errors,
    )
    _expect(
        legacy_comparison.get("currentObservedSha")
        == legacy.get("observedProtectedMainSha"),
        "legacy comparison SHA mismatch",
        errors,
    )
    for name, value in (
        ("canonical", canonical_comparison),
        ("legacy", legacy_comparison),
    ):
        _expect(
            _sha(value.get("previousSnapshotSha")),
            f"{name} previous snapshot SHA invalid",
            errors,
        )
        _expect(
            isinstance(value.get("aheadBy"), int) and value["aheadBy"] >= 0,
            f"{name} aheadBy invalid",
            errors,
        )
        _expect(
            value.get("behindBy") == 0,
            f"{name} comparison must not claim an unreviewed behind state",
            errors,
        )
    _expect(
        comparison.get("bulkSourceMergeAuthorized") is False,
        "bulk legacy source merge must remain forbidden",
        errors,
    )
    _expect(
        len(
            _list(
                comparison.get("canonicalCapabilitiesNowPresent"),
                "canonicalCapabilitiesNowPresent",
                errors,
            )
        )
        >= 8,
        "canonical capability review is incomplete",
        errors,
    )
    _expect(
        len(
            _list(
                comparison.get("remainingPerWorkloadCertificationBoundaries"),
                "remainingPerWorkloadCertificationBoundaries",
                errors,
            )
        )
        >= 6,
        "remaining compatibility boundaries are incomplete",
        errors,
    )

    families = _list(document.get("runtimeImageFamilies"), "runtimeImageFamilies", errors)
    family_ids: set[str] = set()
    workload_ids: set[str] = set()
    destination_tags: set[str] = set()
    registry_mirror_ids: set[str] = set()
    workload_count = 0

    for index, raw_family in enumerate(families):
        family = _mapping(
            raw_family,
            f"runtimeImageFamilies[{index}]",
            errors,
        )
        prefix = f"runtimeImageFamilies[{index}]"
        family_id = family.get("id")
        _expect(
            isinstance(family_id, str)
            and ID.fullmatch(family_id) is not None,
            f"{prefix}.id invalid",
            errors,
        )
        if isinstance(family_id, str):
            _expect(
                family_id not in family_ids,
                f"duplicate family id: {family_id}",
                errors,
            )
            family_ids.add(family_id)

        authority_name = family.get("authority")
        role = family.get("role")
        _expect(
            authority_name
            in {"appolon1908-hue", "Codestra-SRL", "unreconciled-historical"},
            f"{prefix}.authority invalid",
            errors,
        )
        if authority_name in {"Codestra-SRL", "unreconciled-historical"}:
            _expect(
                role == "rollback-only",
                f"{prefix} legacy family must be rollback-only",
                errors,
            )
        if authority_name == "appolon1908-hue":
            _expect(
                role == "superseded-appolon-runtime",
                f"{prefix} appolon runtime must be marked superseded",
                errors,
            )

        if "sourceSha" in family:
            _expect(
                _sha(family.get("sourceSha")),
                f"{prefix}.sourceSha invalid",
                errors,
            )
        else:
            _expect(
                family.get("sourceStatus")
                in {"UNESTABLISHED", "INVALID_REVISION_METADATA"},
                f"{prefix} needs a valid sourceSha or explicit source status",
                errors,
            )

        digest = family.get("digest")
        reference = family.get("runtimeReference")
        digest_kind = family.get("digestKind")
        _expect(_digest(digest), f"{prefix}.digest invalid", errors)
        _expect(
            isinstance(reference, str) and bool(reference),
            f"{prefix}.runtimeReference missing",
            errors,
        )
        _expect(
            digest_kind in {"registry-manifest-digest", "docker-image-id"},
            f"{prefix}.digestKind invalid",
            errors,
        )
        if digest_kind == "registry-manifest-digest":
            _expect(
                isinstance(reference, str) and reference.endswith(f"@{digest}"),
                f"{prefix} registry reference must end in exact digest",
                errors,
            )
        if digest_kind == "docker-image-id":
            _expect(
                isinstance(reference, str)
                and ("@sha256:" in reference or ":" in reference),
                f"{prefix} local image reference invalid",
                errors,
            )

        workloads = _list(
            family.get("workloads"),
            f"{prefix}.workloads",
            errors,
        )
        _expect(bool(workloads), f"{prefix}.workloads must not be empty", errors)
        for workload in workloads:
            _expect(
                isinstance(workload, str)
                and CONTAINER.fullmatch(workload) is not None,
                f"{prefix} invalid workload name: {workload!r}",
                errors,
            )
            if isinstance(workload, str):
                _expect(
                    workload not in workload_ids,
                    f"workload appears in multiple image families: {workload}",
                    errors,
                )
                workload_ids.add(workload)
                workload_count += 1

        backup = _mapping(family.get("backup"), f"{prefix}.backup", errors)
        method = backup.get("method")
        if method == "registry-preserve-digest":
            registry_mirror_ids.add(str(family_id))
            _expect(
                digest_kind == "registry-manifest-digest",
                f"{prefix} exact registry mirror requires manifest digest",
                errors,
            )
            _expect(
                authority_name == "Codestra-SRL",
                f"{prefix} registry mirror is only for Codestra-SRL images",
                errors,
            )
            _expect(
                backup.get("state") in {"PENDING_ACTIONS_MIRROR", "VERIFIED"},
                f"{prefix} registry mirror state invalid",
                errors,
            )
            destination = backup.get("destinationDigestReference")
            _expect(
                destination == f"{LEGACY_BACKUP_REPOSITORY}@{digest}",
                f"{prefix} destination digest reference mismatch",
                errors,
            )
        elif method == "server-a-archive-and-config-digest-mirror":
            _expect(
                digest_kind == "docker-image-id",
                f"{prefix} Server A archive method requires Docker image ID",
                errors,
            )
            _expect(
                backup.get("state") in {"PENDING_SERVER_A_ACCESS", "VERIFIED"},
                f"{prefix} Server A backup state invalid",
                errors,
            )
            _expect(
                backup.get("evidenceCommand")
                == "scripts/server-a-backup-legacy-middleware-images.sh",
                f"{prefix} Server A backup command mismatch",
                errors,
            )
        elif method == "retain-existing-appolon-ghcr-digest":
            _expect(
                authority_name == "appolon1908-hue",
                f"{prefix} appolon retention assigned to wrong authority",
                errors,
            )
            _expect(
                backup.get("state") == "AVAILABLE_IN_APPOLON_GHCR",
                f"{prefix} appolon backup state invalid",
                errors,
            )
            _expect(
                backup.get("reference") == reference,
                f"{prefix} appolon retained reference mismatch",
                errors,
            )
        else:
            errors.append(f"{prefix}.backup.method is unsupported: {method!r}")

        destination_tag = backup.get("destinationTag")
        if destination_tag is not None:
            _expect(
                isinstance(destination_tag, str)
                and destination_tag.startswith(f"{LEGACY_BACKUP_REPOSITORY}:"),
                f"{prefix} backup tag must use appolon legacy package",
                errors,
            )
            if isinstance(destination_tag, str):
                _expect(
                    destination_tag not in destination_tags,
                    f"duplicate destination tag: {destination_tag}",
                    errors,
                )
                destination_tags.add(destination_tag)

        _expect(
            isinstance(family.get("convergenceDisposition"), str)
            and bool(family["convergenceDisposition"]),
            f"{prefix}.convergenceDisposition missing",
            errors,
        )
        _expect(
            isinstance(family.get("configurationAuthority"), str)
            and family["configurationAuthority"].startswith("/"),
            f"{prefix}.configurationAuthority must be an absolute Server A path",
            errors,
        )
        _expect(
            digest != candidate_digest,
            f"{prefix} must not classify the historical predecessor as legacy",
            errors,
        )

    expected_registry_mirrors = {
        "codestra-integration-api",
        "codestra-notification-and-scheduler",
        "codestra-odoo-result-worker",
        "codestra-webphone-session-issuer",
    }
    _expect(
        registry_mirror_ids == expected_registry_mirrors,
        f"exact registry mirror set drifted: {sorted(registry_mirror_ids)}",
        errors,
    )
    _expect(
        workload_count == server.get("runtimeWorkloadsCatalogued"),
        "workload count mismatch: "
        f"catalog={workload_count}, "
        f"declared={server.get('runtimeWorkloadsCatalogued')}",
        errors,
    )

    policy = _mapping(document.get("convergencePolicy"), "convergencePolicy", errors)
    _expect(
        policy.get("singleForwardRepository") == CANONICAL_REPOSITORY,
        "convergence policy source authority mismatch",
        errors,
    )
    _expect(
        policy.get("singleForwardImageRepository")
        == CANONICAL_IMAGE_REPOSITORY,
        "convergence policy image authority mismatch",
        errors,
    )
    _expect(
        policy.get("legacyBackupImageRepository") == LEGACY_BACKUP_REPOSITORY,
        "legacy backup package mismatch",
        errors,
    )
    for key in (
        "blindWholeFleetReplacementAllowed",
        "legacyNewBuildsAllowed",
        "legacyRuntimeExpansionAllowed",
    ):
        _expect(
            policy.get(key) is False,
            f"convergencePolicy.{key} must be false",
            errors,
        )
    _expect(
        policy.get("legacyImagesMustRemainAvailableForRollback") is True,
        "legacy rollback images must be retained",
        errors,
    )
    _expect(
        len(
            _list(
                policy.get("canonicalPromotionRequires"),
                "canonicalPromotionRequires",
                errors,
            )
        )
        >= 9,
        "canonical promotion gate list is incomplete",
        errors,
    )
    _expect(
        len(_list(policy.get("retirementOrder"), "retirementOrder", errors))
        >= 5,
        "retirement order is incomplete",
        errors,
    )

    safety = _mapping(document.get("safetyBoundary"), "safetyBoundary", errors)
    _expect(
        safety.get("callsPlacedExpected") == 0,
        "callsPlacedExpected must be zero",
        errors,
    )
    for key, value in safety.items():
        if key != "callsPlacedExpected":
            _expect(value is False, f"safetyBoundary.{key} must be false", errors)

    required_paths = (
        "config/middleware-authority-convergence.v1.json",
        "config/middleware-forward-release-authority.v1.json",
        "scripts/server-a-backup-legacy-middleware-images.sh",
        ".github/workflows/mirror-codestra-legacy-middleware-images.yml",
        "docs/production/MIDDLEWARE-AUTHORITY-CONVERGENCE.md",
        "MIDDLEWARE-AUTHORITY-RECONCILIATION.yaml",
    )
    for relative in required_paths:
        _expect(
            (root / relative).is_file(),
            f"required convergence asset missing: {relative}",
            errors,
        )

    return errors


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    path = Path(arguments[0]).resolve() if arguments else DEFAULT_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"MIDDLEWARE_AUTHORITY_CONVERGENCE=FAIL: {exc}",
            file=sys.stderr,
        )
        return 1
    if not isinstance(value, dict):
        print(
            "MIDDLEWARE_AUTHORITY_CONVERGENCE=FAIL: root must be an object",
            file=sys.stderr,
        )
        return 1
    errors = validate_document(value, root=ROOT)
    if errors:
        print("MIDDLEWARE_AUTHORITY_CONVERGENCE=FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    current_authority = json.loads(CURRENT_AUTHORITY_PATH.read_text(encoding="utf-8"))
    artifacts = current_authority["artifactAuthority"]
    families = value["runtimeImageFamilies"]
    workload_count = sum(len(item["workloads"]) for item in families)
    registry_mirrors = sum(
        item["backup"]["method"] == "registry-preserve-digest"
        for item in families
    )
    local_backups = sum(
        item["backup"]["method"]
        == "server-a-archive-and-config-digest-mirror"
        for item in families
    )
    print("MIDDLEWARE_AUTHORITY_CONVERGENCE=PASS")
    print(f"FORWARD_SOURCE={CANONICAL_REPOSITORY}@protected-main-event-sha")
    print(f"REQUIRED_SCHEMA_HEAD={artifacts['requiredSchemaHead']}")
    print(f"SIGNED_CANDIDATE_STATUS={artifacts['candidateStatus']}")
    print("CURRENT_SIGNED_CANDIDATE=NONE")
    print(
        "HISTORICAL_SIGNED_PREDECESSOR="
        f"{artifacts['historicalSignedPredecessor']['imageReference']}"
    )
    print("HISTORICAL_PREDECESSOR_PROMOTION_AUTHORIZED=NO")
    print(f"RUNTIME_IMAGE_FAMILIES={len(families)}")
    print(f"RUNTIME_WORKLOADS={workload_count}")
    print(f"EXACT_REGISTRY_MIRRORS={registry_mirrors}")
    print(f"SERVER_A_LOCAL_BACKUPS={local_backups}")
    print("SERVER_A_MUTATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
