#!/usr/bin/env python3
"""Validate the machine-readable middleware workstream manifest."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config" / "integration-branches.json"
BRANCH_RE = re.compile(
    r"^(?:integration|platform|core|observability|testing)/"
    r"[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?$"
)
VERIFICATION_STATUS = "not_observed_on_middleware_host_verification_only"
REQUIRED_VERIFICATION_BRANCHES = {
    "integration/mautic",
    "integration/postal-email",
    "integration/jasmin-sms",
    "integration/crawlee",
    "testing/playwright",
}
REQUIRED_SHARED_BRANCHES = {
    "core/integration-contracts",
    "core/event-ledger-outbox",
    "core/webhook-inbox-replay",
    "core/workers-scheduler",
    "platform/nats-jetstream",
    "platform/temporal",
}
EXPECTED_SYNC_POLICY = {
    "main_must_be_ancestor_of_active_work": True,
    "completed_workstreams_refresh_from_main": True,
    "direct_workstream_deployment": False,
    "immutable_release_from_merged_sha_only": True,
}
EXPECTED_EXTERNAL_AUTHORITIES = {
    "integration_and_release": {
        "repository": "appolon1908-hue/codestra-production-platform",
        "branch": "release/production-activation",
        "contract_catalog": "contracts/catalog.v1.json",
        "runtime_composition": "composition/runtime-composition.v1.json",
        "release_manifest_schema": "release/platform-release-manifest.v1.schema.json",
        "caddy_config_home": "operations/caddy",
    },
    "crawler_source": {
        "repository": "appolon1908-hue/kyqra-crawler",
        "branch": "main",
        "retired_repository": "appolon1908-hue/kyqra",
    },
}


def fail(errors: list[str]) -> int:
    print("Workstream manifest validation failed:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    return 1


def load_manifest(errors: list[str]) -> dict[str, Any] | None:
    try:
        raw = MANIFEST_PATH.read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load {MANIFEST_PATH.relative_to(ROOT)}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append("manifest root must be a JSON object")
        return None
    return value


def main() -> int:
    errors: list[str] = []
    manifest = load_manifest(errors)
    if manifest is None:
        return fail(errors)

    version = manifest.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 5:
        errors.append("version must be an integer greater than or equal to 5")

    if manifest.get("base_branch") != "main":
        errors.append("base_branch must be exactly 'main'")

    if manifest.get("deployment_from_workstream_branches") is not False:
        errors.append("deployment_from_workstream_branches must be false")

    if manifest.get("canonical_contract_branch") != "core/integration-contracts":
        errors.append(
            "canonical_contract_branch must be exactly 'core/integration-contracts'"
        )

    if manifest.get("connectivity_map") != "config/connectivity-map.json":
        errors.append("connectivity_map must reference config/connectivity-map.json")

    if manifest.get("canonical_event_schema") != (
        "contracts/platform/event-envelope.v1.schema.json"
    ):
        errors.append(
            "canonical_event_schema must reference the canonical event schema"
        )

    if manifest.get("synchronization_policy") != EXPECTED_SYNC_POLICY:
        errors.append("synchronization_policy is incomplete or unsafe")

    if manifest.get("external_authorities") != EXPECTED_EXTERNAL_AUTHORITIES:
        errors.append("external_authorities is incomplete or non-canonical")

    raw_workstreams = manifest.get("workstreams")
    if not isinstance(raw_workstreams, list) or not raw_workstreams:
        errors.append("workstreams must be a non-empty array")
        raw_workstreams = []

    branches: list[str] = []
    verification_branches: set[str] = set()

    for index, item in enumerate(raw_workstreams):
        location = f"workstreams[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{location} must be an object")
            continue

        branch = item.get("branch")
        category = item.get("category")
        runtime_status = item.get("runtime_status")
        scope = item.get("scope")

        if not isinstance(branch, str) or not BRANCH_RE.fullmatch(branch):
            errors.append(f"{location}.branch is not a valid canonical workstream branch")
        else:
            branches.append(branch)

        if not isinstance(category, str) or not category.strip():
            errors.append(f"{location}.category must be a non-empty string")
        if not isinstance(runtime_status, str) or not runtime_status.strip():
            errors.append(f"{location}.runtime_status must be a non-empty string")
        if not isinstance(scope, str) or len(scope.strip()) < 20:
            errors.append(f"{location}.scope must be a meaningful non-empty description")

        if isinstance(branch, str) and runtime_status == VERIFICATION_STATUS:
            verification_branches.add(branch)

    duplicate_branches = sorted(
        branch for branch in set(branches) if branches.count(branch) > 1
    )
    if duplicate_branches:
        errors.append(
            "duplicate workstream branches: " + ", ".join(duplicate_branches)
        )

    branch_set = set(branches)
    missing_shared = sorted(REQUIRED_SHARED_BRANCHES - branch_set)
    if missing_shared:
        errors.append(
            "required shared workstreams are missing: " + ", ".join(missing_shared)
        )

    declared_verification = manifest.get("not_observed_with_verification_branches")
    if not isinstance(declared_verification, list) or not all(
        isinstance(branch, str) for branch in declared_verification
    ):
        errors.append(
            "not_observed_with_verification_branches must be an array of branch names"
        )
        declared_verification_set: set[str] = set()
    else:
        declared_verification_set = set(declared_verification)
        if len(declared_verification_set) != len(declared_verification):
            errors.append("not_observed_with_verification_branches contains duplicates")

    if verification_branches != declared_verification_set:
        missing = sorted(verification_branches - declared_verification_set)
        extra = sorted(declared_verification_set - verification_branches)
        if missing:
            errors.append(
                "verification branches missing from summary list: " + ", ".join(missing)
            )
        if extra:
            errors.append(
                "summary list contains non-verification branches: " + ", ".join(extra)
            )

    missing_required = sorted(REQUIRED_VERIFICATION_BRANCHES - verification_branches)
    if missing_required:
        errors.append(
            "required verification workstreams are missing: "
            + ", ".join(missing_required)
        )

    by_branch = {
        item.get("branch"): item
        for item in raw_workstreams
        if isinstance(item, dict) and isinstance(item.get("branch"), str)
    }
    rabbitmq = by_branch.get("platform/rabbitmq", {})
    if rabbitmq.get("runtime_status") != (
        "provider_local_not_central_verification_only"
    ):
        errors.append("RabbitMQ must remain provider-local and non-central")

    if errors:
        return fail(errors)

    print(
        "Workstream manifest validation passed: "
        f"{len(branches)} unique branches, "
        f"{len(verification_branches)} verification-only branches, "
        f"{len(REQUIRED_SHARED_BRANCHES)} shared contract branches."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
