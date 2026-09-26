#!/usr/bin/env python3
"""Validate implementation controls for Middleware authority convergence."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = Path("config/middleware-authority-convergence.v1.json")
CURRENT_AUTHORITY_PATH = Path("config/middleware-forward-release-authority.v1.json")
WORKFLOW_PATH = Path(".github/workflows/mirror-codestra-legacy-middleware-images.yml")
BACKUP_SCRIPT_PATH = Path("scripts/server-a-backup-legacy-middleware-images.sh")
DOCKERFILE_PATH = Path("Dockerfile.runtime")
DOCKERIGNORE_PATH = Path(".dockerignore")
DOC_PATH = Path("docs/production/MIDDLEWARE-AUTHORITY-CONVERGENCE.md")
EXPECTED_FAMILY_COUNT = 16
EXPECTED_WORKLOAD_COUNT = 31
EXPECTED_REGISTRY_MIRRORS = 4
EXPECTED_LOCAL_BACKUPS = 11
CURRENT_SCHEMA_HEAD = "0070_agent_provisioning_lifecycle"
OBSERVED_SIGNED_SCHEMA_HEAD = "0057_platform_service_catalog"
PENDING_CANDIDATE_STATUS = "PENDING_EXACT_PROTECTED_MERGE_BUILD"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
# Every observed signed release was published to the pre-transfer package;
# forward releases publish to ghcr.io/ingtrader21-spec/codestra-middleware
# (config/middleware-forward-release-authority.v1.json artifactAuthority).
OBSERVED_SIGNED_IMAGE = "ghcr.io/appolon1908-hue/codestra-middleware"


def _read(root: Path, relative: Path, errors: list[str]) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        errors.append(f"required regular file missing: {relative.as_posix()}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"cannot read {relative.as_posix()}: {exc}")
        return ""


def _load_object(
    root: Path,
    relative: Path,
    *,
    label: str,
    errors: list[str],
) -> dict[str, Any]:
    raw = _read(root, relative, errors)
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        errors.append(f"{label} is invalid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} root must be an object")
        return {}
    return value


def _validate_observed_signed_evidence(
    value: Any,
    *,
    label: str,
    errors: list[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return {}
    if value.get("role") != "observed-signed-evidence-not-static-authority":
        errors.append(f"{label} role must deny static authority")
    if value.get("promotionAuthorized") is not False:
        errors.append(f"{label} promotion must be forbidden")
    if (
        not isinstance(value.get("sourceSha"), str)
        or SHA40.fullmatch(value["sourceSha"]) is None
    ):
        errors.append(f"{label} source SHA is malformed")
    if (
        not isinstance(value.get("gitTreeId"), str)
        or SHA40.fullmatch(value["gitTreeId"]) is None
    ):
        errors.append(f"{label} Git tree ID is malformed")
    digest = value.get("imageDigest")
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        errors.append(f"{label} image digest is malformed")
    if value.get("imageReference") != f"{OBSERVED_SIGNED_IMAGE}@{digest}":
        errors.append(f"{label} image reference is not observed-package and digest-bound")
    if value.get("schemaHead") != OBSERVED_SIGNED_SCHEMA_HEAD:
        errors.append(f"{label} schema head must be {OBSERVED_SIGNED_SCHEMA_HEAD}")
    for field in (
        "artifactArchiveDigest",
        "releaseManifestSha256",
        "sigstoreBundleSha256",
        "sbomSha256",
        "vulnerabilityReportSha256",
    ):
        if (
            not isinstance(value.get(field), str)
            or DIGEST.fullmatch(value[field]) is None
        ):
            errors.append(f"{label} {field} is malformed")
    for field in ("workflowRunId", "workflowRunAttempt", "artifactId"):
        if not isinstance(value.get(field), int) or value[field] <= 0:
            errors.append(f"{label} {field} is invalid")
    expected = {
        "signature": "sigstore-keyless-verified",
        "provenance": "slsa-v1-verified",
        "sbom": "spdx-2.3-verified",
        "vulnerabilityGate": "PASS",
        "verification": "PASS",
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            errors.append(f"{label} {field} evidence mismatch")
    return value


def validate_assets(root: Path = ROOT) -> list[str]:
    """Return implementation errors; an empty list means PASS."""

    errors: list[str] = []
    catalog = _load_object(
        root,
        CATALOG_PATH,
        label="historical inventory catalog",
        errors=errors,
    )
    current_authority = _load_object(
        root,
        CURRENT_AUTHORITY_PATH,
        label="current forward release authority",
        errors=errors,
    )
    workflow = _read(root, WORKFLOW_PATH, errors)
    backup_script = _read(root, BACKUP_SCRIPT_PATH, errors)
    dockerfile = _read(root, DOCKERFILE_PATH, errors)
    dockerignore = _read(root, DOCKERIGNORE_PATH, errors)
    documentation = _read(root, DOC_PATH, errors)

    families = catalog.get("runtimeImageFamilies", [])
    if not isinstance(families, list):
        errors.append("runtimeImageFamilies must be an array")
        families = []

    workload_count = 0
    registry_mirrors = 0
    local_backups = 0
    for family in families:
        if not isinstance(family, dict):
            errors.append("runtimeImageFamilies entries must be objects")
            continue
        workloads = family.get("workloads", [])
        if not isinstance(workloads, list):
            errors.append(f"family {family.get('id')!r} workloads must be an array")
            workloads = []
        workload_count += len(workloads)
        backup = family.get("backup", {})
        if not isinstance(backup, dict):
            errors.append(f"family {family.get('id')!r} backup must be an object")
            continue
        method = backup.get("method")
        if method == "registry-preserve-digest":
            registry_mirrors += 1
        elif method == "server-a-archive-and-config-digest-mirror":
            local_backups += 1

    if len(families) != EXPECTED_FAMILY_COUNT:
        errors.append(
            "runtime image family count drifted: expected "
            f"{EXPECTED_FAMILY_COUNT}, got {len(families)}"
        )
    if workload_count != EXPECTED_WORKLOAD_COUNT:
        errors.append(
            "runtime workload count drifted: expected "
            f"{EXPECTED_WORKLOAD_COUNT}, got {workload_count}"
        )
    if registry_mirrors != EXPECTED_REGISTRY_MIRRORS:
        errors.append(
            "registry mirror count drifted: expected "
            f"{EXPECTED_REGISTRY_MIRRORS}, got {registry_mirrors}"
        )
    if local_backups != EXPECTED_LOCAL_BACKUPS:
        errors.append(
            "local backup count drifted: expected "
            f"{EXPECTED_LOCAL_BACKUPS}, got {local_backups}"
        )

    snapshot_candidate = (
        catalog.get("forwardAuthority", {})
        .get("image", {})
        .get("currentSignedCandidate", {})
    )
    if not isinstance(snapshot_candidate, dict):
        errors.append("historical snapshot candidate must be an object")
        snapshot_candidate = {}
    snapshot_digest = snapshot_candidate.get("imageDigest")
    if (
        not isinstance(snapshot_digest, str)
        or DIGEST.fullmatch(snapshot_digest) is None
    ):
        errors.append("historical snapshot candidate digest is malformed")

    artifacts = current_authority.get("artifactAuthority", {})
    if not isinstance(artifacts, dict):
        errors.append("current artifactAuthority must be an object")
        artifacts = {}
    if artifacts.get("requiredSchemaHead") != CURRENT_SCHEMA_HEAD:
        errors.append(f"current authority must require schema {CURRENT_SCHEMA_HEAD}")
    if artifacts.get("candidateStatus") != PENDING_CANDIDATE_STATUS:
        errors.append("current candidate status must remain exact-main-build pending")
    if artifacts.get("currentSignedCandidate") is not None:
        errors.append("current signed candidate must be null before exact-main build")
    latest = _validate_observed_signed_evidence(
        artifacts.get("latestVerifiedSignedEvidence"),
        label="latest verified signed evidence",
        errors=errors,
    )
    previous = _validate_observed_signed_evidence(
        artifacts.get("previousVerifiedSignedEvidence"),
        label="previous verified signed evidence",
        errors=errors,
    )
    if latest.get("sourceSha") == previous.get("sourceSha"):
        errors.append(
            "latest and previous signed evidence must use distinct source SHAs"
        )
    if latest.get("imageDigest") == previous.get("imageDigest"):
        errors.append(
            "latest and previous signed evidence must use distinct image digests"
        )
    predecessor = artifacts.get("historicalSignedPredecessor", {})
    if not isinstance(predecessor, dict):
        errors.append("historicalSignedPredecessor must be an object")
        predecessor = {}
    predecessor_digest = predecessor.get("imageDigest")
    if (
        not isinstance(predecessor_digest, str)
        or DIGEST.fullmatch(predecessor_digest) is None
    ):
        errors.append("historical predecessor digest is malformed")
    if predecessor.get("promotionAuthorized") is not False:
        errors.append("historical predecessor promotion must be forbidden")
    if predecessor_digest != snapshot_digest:
        errors.append("historical inventory and predecessor digest disagree")
    if predecessor.get("schemaHead") != "0009_observability_incidents":
        errors.append("historical predecessor schema identity drifted")

    workflow_requirements = {
        "manual dispatch": "workflow_dispatch:",
        "protected-main guard": 'test "$GITHUB_REF" = "refs/heads/main"',
        "exact checkout guard": 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        "source package credential": "CODESTRA_GHCR_TOKEN",
        "digest preservation": "--preserve-digests",
        "raw manifest comparison": "Raw source and destination manifests differ",
        "no runtime promotion evidence": '"runtime_promoted": False',
        "source retention evidence": '"codestra_source_retained": True',
    }
    for label, needle in workflow_requirements.items():
        if needle not in workflow:
            errors.append(f"mirror workflow missing {label}")

    if re.search(r"(?m)^\s*push\s*:", workflow):
        errors.append("mirror workflow must not run automatically on push")
    for needle in (
        "docker build ",
        "docker/build-push-action",
        "buildah bud ",
        "podman build ",
    ):
        if needle in workflow:
            errors.append(
                f"mirror workflow must copy, not rebuild images: found {needle!r}"
            )

    script_requirements = {
        "root gate": 'fail "root_required"',
        "Server A address gate": 'fail "server_a_host_identity_mismatch"',
        "catalog validation": "validate_middleware_authority_convergence.py",
        "missing workload failure": "MISSING_EXPECTED_WORKLOADS",
        "environment non-capture": '"environment_values_captured": False',
        "mount-source non-capture": '"mount_sources_captured": False',
        "mount-destination evidence": '"mount_destinations_captured": True',
        "docker-save archive": 'docker image save "$expected_id"',
        "archive config verification": "docker save config digest mismatch",
        "isolated restore denial": '"isolated_restore_performed": False',
        "isolated restore requirement": (
            '"isolated_restore_required_before_cutover": True'
        ),
        "private registry auth gate": "validate_private_file",
        "temporary tag cleanup": "trap cleanup_temp_tag EXIT",
        "run checksum verification": "sha256sum --check --strict SHA256SUMS",
    }
    for label, needle in script_requirements.items():
        if needle not in backup_script:
            errors.append(f"Server A backup script missing {label}")

    for needle in (
        "docker compose up",
        "docker compose down",
        "docker container restart",
        "docker restart",
        "docker container stop",
        "docker stop",
        "docker container rm",
    ):
        if needle in backup_script:
            errors.append(
                f"backup script must not mutate running containers: found {needle!r}"
            )

    marker = "FROM ${TEST_BASE} AS test"
    if marker not in dockerfile:
        errors.append("Dockerfile test target marker is missing")
    else:
        runtime_section, test_section = dockerfile.split(marker, 1)
        for path in (
            "MIDDLEWARE-AUTHORITY-RECONCILIATION.yaml",
            ".github/workflows/mirror-codestra-legacy-middleware-images.yml",
        ):
            if path in runtime_section:
                errors.append(
                    f"authority-only asset leaked into production runtime stage: {path}"
                )
            if path not in test_section:
                errors.append(f"Docker test target does not package {path}")

    allowlist_line = "!.github/workflows/mirror-codestra-legacy-middleware-images.yml"
    if allowlist_line not in dockerignore.splitlines():
        errors.append("Docker context does not allowlist the mirror workflow")
    if ".github/workflows/*" not in dockerignore.splitlines():
        errors.append("Docker context no longer denies workflows by default")

    documentation_requirements = (
        "only forward source",
        "rollback-only",
        "CODESTRA_GHCR_TOKEN",
        "isolated restore",
        "0057_platform_service_catalog",
        "PENDING_EXACT_PROTECTED_MERGE_BUILD",
        "historical predecessor",
        "SERVER_A_RUNTIME_REVALIDATION=NOT_EXECUTED",
        "PRODUCTION_CHANGED=NO",
        "CALLS_PLACED=0",
    )
    lower_documentation = documentation.lower()
    for phrase in documentation_requirements:
        if phrase.lower() not in lower_documentation:
            errors.append(
                f"authority documentation missing required statement: {phrase}"
            )

    return errors


def main() -> int:
    errors = validate_assets()
    if errors:
        print("MIDDLEWARE_AUTHORITY_ASSETS=FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("MIDDLEWARE_AUTHORITY_ASSETS=PASS")
    print(f"REQUIRED_SCHEMA_HEAD={CURRENT_SCHEMA_HEAD}")
    print(f"SIGNED_CANDIDATE_STATUS={PENDING_CANDIDATE_STATUS}")
    print(f"RUNTIME_IMAGE_FAMILIES={EXPECTED_FAMILY_COUNT}")
    print(f"RUNTIME_WORKLOADS={EXPECTED_WORKLOAD_COUNT}")
    print(f"EXACT_REGISTRY_MIRRORS={EXPECTED_REGISTRY_MIRRORS}")
    print(f"SERVER_A_LOCAL_BACKUPS={EXPECTED_LOCAL_BACKUPS}")
    print("HISTORICAL_PREDECESSOR_PROMOTION_AUTHORIZED=NO")
    print("SERVER_A_RUNTIME_MUTATED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
