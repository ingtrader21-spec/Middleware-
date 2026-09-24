#!/usr/bin/env python3
"""Fail-closed validation for the full Codestra production integration lock."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, cast

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config" / "production-integration-lock.v1.json"
EVIDENCE_DIR = ROOT / "artifacts" / "production-integration-lock"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPO_RE = re.compile(r"^appolon1908-hue/[A-Za-z0-9_.-]+$")
SOURCE_STATES = {
    "protected_source_ready",
    "candidate_pending_review",
    "candidate_needs_refresh",
    "governance_incomplete",
    "source_only",
    "authority_only",
}
CHECK_STATES = {"active", "missing", "unverified"}
REVIEWER_STATES = {"available", "requested", "pending-access", "unverified"}
BINDING_STATES = {
    "source-ready",
    "source-only",
    "runtime-unverified",
    "not-observed",
    "unverified",
}
PRODUCTION_STATES = {"BLOCKED", "SOURCE_READY", "PENDING_PROTECTED_MERGE"}
CANDIDATE_STATES = {
    "refresh-from-main-required",
    "pending-review-before-development-reconciliation",
    "superseded-by-reconciled-development-head",
    "pending-exact-head-review",
    "blocked-by-pr-55-and-refresh",
    "pending-review-and-source-pin-refresh",
    "ci-running-and-reviewer-access-pending",
    "reviewer-access-pending",
    "independent-review-requested",
    "reviewer-and-ruleset-access-pending",
}
GLOBAL_GATES = [
    "protected_merged_source",
    "exact_head_ci",
    "independent_approval",
    "signed_immutable_artifact",
    "staging_readonly_deployment",
    "source_and_digest_readback",
    "identity_and_route_matrix",
    "provider_readback",
    "backup_restore",
    "rollback_rehearsal",
    "monitoring_continuity",
    "bounded_read_only_canary",
]
COMPONENT_DEFAULT_KEYS = {
    "branch",
    "source",
    "protected",
    "checks",
    "reviewer",
    "prs",
    "deps",
    "binding",
    "state",
    "blockers",
}
COMPONENT_REQUIRED_KEYS = {"id", "repo", "rid", "sha"}
COMPONENT_ALLOWED_KEYS = COMPONENT_REQUIRED_KEYS | COMPONENT_DEFAULT_KEYS
CERTIFICATION_FIELDS = {
    "immutable_image_digest",
    "staging_evidence",
    "backup_restore_evidence",
    "rollback_evidence",
    "runtime_readback_evidence",
}


class LockError(RuntimeError):
    """The integration lock would permit an unsupported production claim."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise LockError(message)


def require_mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LockError(message)
    require(
        all(isinstance(key, str) for key in value),
        f"{message}: keys must be strings",
    )
    return cast(Mapping[str, Any], value)


def require_list(value: object, message: str) -> list[Any]:
    if not isinstance(value, list):
        raise LockError(message)
    return value


def require_nonempty_string(value: object, message: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise LockError(message)
    return value


def require_integer(value: object, message: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LockError(message)
    return value


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise LockError(f"cannot load integration lock: {path}") from exc
    if not isinstance(value, dict):
        raise LockError("integration lock must be an object")
    require(
        all(isinstance(key, str) for key in value),
        "integration lock keys must be strings",
    )
    return cast(dict[str, Any], value)


def expand_component(
    raw: Mapping[str, Any], defaults: Mapping[str, Any]
) -> dict[str, Any]:
    require(set(raw).issubset(COMPONENT_ALLOWED_KEYS), "unknown component field")
    require(COMPONENT_REQUIRED_KEYS.issubset(raw), "component identity fields missing")
    row = copy.deepcopy(dict(defaults))
    row.update(copy.deepcopy(dict(raw)))
    return row


def validate_candidate(component_id: str, candidate: Mapping[str, Any]) -> None:
    require(
        set(candidate) == {"n", "sha", "base", "status", "merge"},
        f"{component_id}: candidate field drift",
    )
    number = require_integer(candidate.get("n"), f"{component_id}: invalid PR number")
    require(number > 0, f"{component_id}: invalid PR number")
    sha = require_nonempty_string(
        candidate.get("sha"), f"{component_id}: invalid candidate SHA"
    )
    require(
        SHA_RE.fullmatch(sha) is not None,
        f"{component_id}: invalid candidate SHA",
    )
    require_nonempty_string(
        candidate.get("base"), f"{component_id}: candidate base missing"
    )
    status = require_nonempty_string(
        candidate.get("status"), f"{component_id}: invalid candidate status"
    )
    require(
        status in CANDIDATE_STATES,
        f"{component_id}: invalid candidate status",
    )
    merge_method = require_nonempty_string(
        candidate.get("merge"), f"{component_id}: invalid merge method"
    )
    require(
        merge_method in {"squash", "merge"},
        f"{component_id}: invalid merge method",
    )


def validate_certification(
    component: Mapping[str, Any],
    certification: Mapping[str, Any],
) -> None:
    cid = str(component["id"])
    require(
        set(certification) == CERTIFICATION_FIELDS, f"{cid}: certification field drift"
    )
    digest = require_nonempty_string(
        certification.get("immutable_image_digest"),
        f"{cid}: immutable digest required",
    )
    require(
        DIGEST_RE.fullmatch(digest) is not None,
        f"{cid}: immutable digest required",
    )
    for field in CERTIFICATION_FIELDS - {"immutable_image_digest"}:
        require_nonempty_string(certification.get(field), f"{cid}: {field} required")
    require(
        component["source"] == "protected_source_ready",
        f"{cid}: certified runtime requires protected source",
    )
    require(component["protected"] is True, f"{cid}: protected branch required")
    require(component["checks"] == "active", f"{cid}: active required checks required")


def validate_lock(value: Mapping[str, Any]) -> dict[str, Any]:
    require(value.get("schema_version") == "1.0", "unsupported lock schema")
    require(
        value.get("lock_id") == "codestra.middleware-full-production-integration.v1",
        "lock ID drift",
    )
    require(value.get("decision") == "NO_GO", "source lock decision must remain NO_GO")
    require(
        value.get("production_activated") is False, "production must remain inactive"
    )

    authority = require_mapping(value.get("authority"), "authority missing")
    require(
        authority.get("repository") == "appolon1908-hue/Middleware-",
        "authority repository drift",
    )
    base_sha = require_nonempty_string(
        authority.get("base_sha"), "authority base SHA invalid"
    )
    require(
        SHA_RE.fullmatch(base_sha) is not None,
        "authority base SHA invalid",
    )

    policy = require_mapping(value.get("release_policy"), "release policy missing")
    require(
        policy.get("immutable_artifacts_only") is True,
        "immutable artifacts are required",
    )
    require(
        policy.get("rebuild_between_environments") is False,
        "environment rebuilds are forbidden",
    )
    percent = require_integer(
        policy.get("max_read_only_canary_percent"),
        "read-only canary must be <=1 percent",
    )
    require(
        0 < percent <= 1,
        "read-only canary must be <=1 percent",
    )
    require(
        policy.get("read_only_canary_methods") == ["GET", "HEAD"],
        "read-only canary methods drift",
    )
    require(
        policy.get("required_global_gates") == GLOBAL_GATES,
        "global gate order or coverage drift",
    )
    calls_placed = require_integer(
        policy.get("calls_placed"), "CALLS_PLACED must remain zero"
    )
    require(calls_placed == 0, "CALLS_PLACED must remain zero")
    effects = require_mapping(
        policy.get("external_effects"), "external effects registry missing"
    )
    require(effects, "external effects registry missing")
    for name, enabled in effects.items():
        require(isinstance(name, str) and name, "invalid external effect name")
        require(enabled is False, f"external effect must remain disabled: {name}")

    defaults = require_mapping(
        value.get("component_defaults"), "component defaults missing"
    )
    require(set(defaults) == COMPONENT_DEFAULT_KEYS, "component default field drift")
    require(defaults.get("branch") == "main", "default branch drift")
    default_source = require_nonempty_string(
        defaults.get("source"), "default source state invalid"
    )
    require(default_source in SOURCE_STATES, "default source state invalid")
    require(defaults.get("protected") is False, "default protection must fail closed")
    default_checks = require_nonempty_string(
        defaults.get("checks"), "default checks invalid"
    )
    require(default_checks in CHECK_STATES, "default checks invalid")
    default_reviewer = require_nonempty_string(
        defaults.get("reviewer"), "default reviewer invalid"
    )
    require(default_reviewer in REVIEWER_STATES, "default reviewer invalid")
    require(defaults.get("prs") == [], "default PR list must be empty")
    require(defaults.get("deps") == [], "default dependencies must be empty")
    default_binding = require_nonempty_string(
        defaults.get("binding"), "default binding invalid"
    )
    require(default_binding in BINDING_STATES, "default binding invalid")
    require(
        defaults.get("state") == "BLOCKED", "default production state must be BLOCKED"
    )
    default_blockers = require_list(
        defaults.get("blockers"), "default blockers missing"
    )
    require(default_blockers, "default blockers missing")

    components_raw = require_list(
        value.get("components"), "component coverage incomplete"
    )
    require(
        len(components_raw) >= 20,
        "component coverage incomplete",
    )
    ids: set[str] = set()
    repositories: set[str] = set()
    repository_ids: set[int] = set()
    components: list[dict[str, Any]] = []
    for raw in components_raw:
        raw_component = require_mapping(raw, "component must be an object")
        row = expand_component(raw_component, defaults)
        cid = require_nonempty_string(row.get("id"), "component ID missing")
        require(cid not in ids, f"duplicate component ID: {cid}")
        ids.add(cid)

        repository = require_nonempty_string(
            row.get("repo"), f"{cid}: invalid repository authority"
        )
        require(
            REPO_RE.fullmatch(repository) is not None,
            f"{cid}: invalid repository authority",
        )
        require(repository not in repositories, f"duplicate repository: {repository}")
        repositories.add(repository)
        repository_id = require_integer(row.get("rid"), f"{cid}: repository ID invalid")
        require(repository_id > 0, f"{cid}: repository ID invalid")
        require(
            repository_id not in repository_ids,
            f"duplicate repository ID: {repository_id}",
        )
        repository_ids.add(repository_id)

        require_nonempty_string(row.get("branch"), f"{cid}: authority branch missing")
        source_sha = require_nonempty_string(
            row.get("sha"), f"{cid}: source SHA invalid"
        )
        require(
            SHA_RE.fullmatch(source_sha) is not None,
            f"{cid}: source SHA invalid",
        )
        source_state = require_nonempty_string(
            row.get("source"), f"{cid}: invalid source state"
        )
        require(source_state in SOURCE_STATES, f"{cid}: invalid source state")
        production_state = require_nonempty_string(
            row.get("state"), f"{cid}: invalid production state"
        )
        require(
            production_state in PRODUCTION_STATES,
            f"{cid}: invalid production state",
        )
        require(
            isinstance(row.get("protected"), bool), f"{cid}: branch protection invalid"
        )
        check_state = require_nonempty_string(
            row.get("checks"), f"{cid}: required-check state invalid"
        )
        require(check_state in CHECK_STATES, f"{cid}: required-check state invalid")
        reviewer_state = require_nonempty_string(
            row.get("reviewer"), f"{cid}: reviewer state invalid"
        )
        require(reviewer_state in REVIEWER_STATES, f"{cid}: reviewer state invalid")
        binding_state = require_nonempty_string(
            row.get("binding"), f"{cid}: binding state invalid"
        )
        require(binding_state in BINDING_STATES, f"{cid}: binding state invalid")
        row.update(
            source=source_state,
            state=production_state,
            checks=check_state,
            reviewer=reviewer_state,
            binding=binding_state,
        )
        blockers = require_list(
            row.get("blockers"), f"{cid}: blockers must be explicit"
        )
        require(blockers, f"{cid}: blockers must be explicit")
        require(
            all(isinstance(item, str) and item for item in blockers),
            f"{cid}: invalid blocker",
        )

        if row["source"] == "protected_source_ready":
            require(row["protected"] is True, f"{cid}: protected source claim invalid")
            require(
                row["checks"] == "active",
                f"{cid}: protected source requires active checks",
            )
        if row["protected"] is False or row["checks"] != "active":
            require(
                row["state"] == "BLOCKED",
                f"{cid}: incomplete governance must remain blocked",
            )

        prs = require_list(row.get("prs"), f"{cid}: candidates must be a list")
        for candidate in prs:
            validate_candidate(
                cid,
                require_mapping(candidate, f"{cid}: candidate must be an object"),
            )
        if row["source"] in {"candidate_pending_review", "candidate_needs_refresh"}:
            require(bool(prs), f"{cid}: candidate source state requires PR evidence")

        deps = require_list(row.get("deps"), f"{cid}: dependencies must be a list")
        require(
            all(isinstance(item, str) and item for item in deps),
            f"{cid}: invalid dependency",
        )
        row["deps"] = deps
        components.append(row)

    for row in components:
        for dependency in row["deps"]:
            require(dependency in ids, f"{row['id']}: unknown dependency: {dependency}")
            require(dependency != row["id"], f"{row['id']}: self-dependency forbidden")

    certifications = require_mapping(
        value.get("runtime_certifications"),
        "runtime certifications must be an object",
    )
    by_id: dict[str, dict[str, Any]] = {
        require_nonempty_string(row.get("id"), "component ID missing"): row
        for row in components
    }
    for cid, certification in certifications.items():
        require(cid in by_id, f"unknown runtime certification: {cid}")
        validate_certification(
            by_id[cid],
            require_mapping(certification, f"{cid}: certification must be an object"),
        )

    order = require_list(value.get("promotion_order"), "promotion order incomplete")
    require(len(order) >= 10, "promotion order incomplete")
    require(
        all(isinstance(step, str) and step for step in order), "invalid promotion step"
    )

    return {
        "schema_version": "1.0",
        "result": "PASS",
        "decision": "NO_GO",
        "component_count": len(components),
        "runtime_certified_count": len(certifications),
        "production_activated": False,
        "external_effects_enabled": [],
        "calls_placed": 0,
    }


def write_evidence(document: Mapping[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "validation.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=LOCK_PATH)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        document = validate_lock(load_lock(args.lock))
        write_evidence(document)
        print(
            "PRODUCTION_INTEGRATION_LOCK=PASS "
            f"components={document['component_count']} "
            f"runtime_certified={document['runtime_certified_count']} "
            "decision=NO_GO calls_placed=0"
        )
        return 0
    except LockError as exc:
        document = {
            "schema_version": "1.0",
            "result": "FAIL",
            "decision": "NO_GO",
            "production_activated": False,
            "calls_placed": 0,
            "error": str(exc),
        }
        write_evidence(document)
        print(f"PRODUCTION_INTEGRATION_LOCK=FAIL reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
