#!/usr/bin/env python3
"""Validate, apply, and verify exact default-branch release rulesets."""

from __future__ import annotations

from typing import TYPE_CHECKING

import argparse
import copy
import datetime as dt
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

if TYPE_CHECKING:
    from scripts.portfolio_ruleset.github_api import GitHubApi
else:
    from portfolio_ruleset.github_api import GitHubApi
if TYPE_CHECKING:
    from scripts.portfolio_ruleset.common import RolloutError
else:
    from portfolio_ruleset.common import RolloutError

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "portfolio-main-release-authorities.v1.json"
EVIDENCE_DIR = ROOT / "artifacts" / "portfolio-main-release-authorities"
TOKEN_ENV = "CODESTRA_REPOSITORY_ADMIN_TOKEN"
CONFIRMATION = "APPLY_MAIN_RELEASE_AUTHORITY_V1"
RULESET_NAME = "Codestra protected default-branch release gates"
EXPECTED_REVIEWER = {
    "login": "kazan555",
    "user_id": 77101516,
    "permission": "push",
}
CONFIG_FIELDS = {
    "schema_version",
    "authority_id",
    "owner",
    "ruleset_name",
    "reviewer",
    "required_approvals",
    "dismiss_stale_reviews",
    "require_last_push_approval",
    "require_review_thread_resolution",
    "require_branch_up_to_date",
    "allowed_merge_methods",
    "repositories",
}
REPOSITORY_FIELDS = {
    "repository",
    "repository_id",
    "default_branch",
    "required_status_checks",
}
EXPECTED_REPOSITORIES = {
    "appolon1908-hue/codestra": (1319808791, ("verify", "container")),
    "appolon1908-hue/backend2": (1319903950, ("validate", "container")),
    "appolon1908-hue/Telnexa-web": (
        1346958528,
        ("validate-build-smoke", "docker-build"),
    ),
    "appolon1908-hue/scrapper": (
        1329513537,
        ("deployment-policy", "validate"),
    ),
    "appolon1908-hue/Breero.com": (1331354808, ("quality",)),
    "appolon1908-hue/Moneybee-Backend": (
        1343760409,
        (
            "verify",
            "postgres-identity-tenancy",
            "containers (api)",
            "containers (worker)",
            "containers (migrate)",
            "application",
            "deployment-policy",
        ),
    ),
}


class PolicyError(RuntimeError):
    """The committed policy or observed GitHub state is not acceptable."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def require_mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(message)
    return value


def require_list(value: object, message: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(message)
    return value


def require_string(value: object, message: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyError(message)
    return value


def require_boolean(value: object, message: str) -> bool:
    if type(value) is not bool:
        raise PolicyError(message)
    return value


def require_nonnegative_integer(value: object, message: str) -> int:
    if type(value) is not int or value < 0:
        raise PolicyError(message)
    return value


def require_string_list(value: object, message: str) -> list[str]:
    values = require_list(value, message)
    result = [require_string(item, message) for item in values]
    require(len(result) == len(set(result)), message)
    return result


def require_exact_fields(
    value: Mapping[str, Any], expected: set[str], message: str
) -> None:
    if set(value) != expected:
        raise PolicyError(message)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise PolicyError(f"cannot load ruleset authority: {path}: {exc}") from exc
    require(isinstance(value, dict), "authority must be an object")
    return value


def validate_config(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    require_exact_fields(config, CONFIG_FIELDS, "authority field inventory drift")
    require(config.get("schema_version") == "1.0", "unsupported authority schema")
    require(
        config.get("authority_id") == "codestra.portfolio-main-release-authorities.v1",
        "authority ID drift",
    )
    require(config.get("owner") == "appolon1908-hue", "owner drift")
    require(config.get("ruleset_name") == RULESET_NAME, "ruleset name drift")
    require(config.get("reviewer") == EXPECTED_REVIEWER, "reviewer authority drift")
    required_approvals = config.get("required_approvals")
    require(
        isinstance(required_approvals, int)
        and not isinstance(required_approvals, bool)
        and required_approvals == 1,
        "exactly one approval is required",
    )
    require(config.get("dismiss_stale_reviews") is True, "stale reviews must be dismissed")
    require(
        config.get("require_last_push_approval") is True,
        "last-push approval must be required",
    )
    require(
        config.get("require_review_thread_resolution") is True,
        "review threads must be resolved",
    )
    require(
        config.get("require_branch_up_to_date") is True,
        "strict current-base checks are required",
    )
    require(config.get("allowed_merge_methods") == ["squash"], "squash-only policy drift")

    repositories = require_list(config.get("repositories"), "repositories must be a list")
    require(len(repositories) == len(EXPECTED_REPOSITORIES), "repository count drift")
    observed_names: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for raw_value in repositories:
        raw = require_mapping(raw_value, "repository record must be an object")
        require_exact_fields(raw, REPOSITORY_FIELDS, "repository record fields drift")
        name = require_string(raw.get("repository"), "repository name missing")
        require(name in EXPECTED_REPOSITORIES, "unknown repository")
        require(name not in observed_names, f"duplicate repository: {name}")
        observed_names.add(name)
        expected_id, expected_checks = EXPECTED_REPOSITORIES[name]
        repository_id = raw.get("repository_id")
        require(
            isinstance(repository_id, int)
            and not isinstance(repository_id, bool)
            and repository_id == expected_id,
            f"{name}: stable ID drift",
        )
        require(raw.get("default_branch") == "main", f"{name}: default branch drift")
        checks = require_string_list(
            raw.get("required_status_checks"), f"{name}: required checks missing"
        )
        require(
            tuple(checks) == expected_checks,
            f"{name}: required check policy drift",
        )
        normalized.append(dict(raw))
    require(observed_names == set(EXPECTED_REPOSITORIES), "repository coverage drift")
    return sorted(normalized, key=lambda item: str(item["repository"]).casefold())


def desired_ruleset(config: Mapping[str, Any], repository: Mapping[str, Any]) -> dict[str, Any]:
    checks = repository["required_status_checks"]
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {
                "include": ["~DEFAULT_BRANCH"],
                "exclude": [],
            }
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["squash"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_last_push_approval": True,
                    "required_approving_review_count": 1,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": context} for context in checks
                    ],
                    "strict_required_status_checks_policy": True,
                },
            },
        ],
    }


def normalize_ruleset(value: Mapping[str, Any]) -> dict[str, Any]:
    conditions = require_mapping(value.get("conditions"), "ruleset conditions missing")
    ref_name = require_mapping(
        conditions.get("ref_name"), "ruleset ref conditions missing"
    )
    included_refs = require_string_list(
        ref_name.get("include"), "ruleset included refs missing or invalid"
    )
    excluded_refs = require_string_list(
        ref_name.get("exclude"), "ruleset excluded refs missing or invalid"
    )
    rules = require_list(value.get("rules"), "ruleset rules missing")
    by_type: dict[str, Mapping[str, Any]] = {}
    for raw_value in rules:
        raw = require_mapping(raw_value, "ruleset contains an invalid rule")
        rule_type = require_string(raw.get("type"), "ruleset rule type invalid")
        require(rule_type not in by_type, f"duplicate ruleset rule: {rule_type}")
        by_type[rule_type] = raw
    required_types = {
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
        "required_status_checks",
    }
    require(required_types.issubset(by_type), "required ruleset rule missing")

    pull = require_mapping(
        by_type["pull_request"].get("parameters"),
        "pull-request parameters missing",
    )
    status = require_mapping(
        by_type["required_status_checks"].get("parameters"),
        "status-check parameters missing",
    )
    status_rows = require_list(
        status.get("required_status_checks"), "required status checks missing"
    )
    checks: list[dict[str, Any]] = []
    observed_contexts: set[str] = set()
    for row_value in status_rows:
        row = require_mapping(row_value, "invalid status-check record")
        context = require_string(row.get("context"), "invalid status-check context")
        require(context not in observed_contexts, f"duplicate status context: {context}")
        observed_contexts.add(context)
        check = copy.deepcopy(dict(row))
        check["context"] = context
        integration_id = row.get("integration_id")
        if integration_id is not None:
            require(
                isinstance(integration_id, int)
                and not isinstance(integration_id, bool)
                and integration_id > 0,
                f"{context}: invalid status-check integration ID",
            )
        provider_slug = row.get("provider_slug")
        if provider_slug is not None:
            require_string(provider_slug, f"{context}: invalid status-check provider slug")
        checks.append(check)
    checks.sort(key=lambda row: str(row["context"]))

    known_pull_parameters = {
        "allowed_merge_methods",
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_extra_approval_for_unattributed_changes",
        "require_last_push_approval",
        "required_approving_review_count",
        "required_review_thread_resolution",
    }
    known_status_parameters = {
        "do_not_enforce_on_create",
        "required_status_checks",
        "strict_required_status_checks_policy",
    }
    allowed_merge_methods = require_string_list(
        pull.get("allowed_merge_methods"), "allowed merge methods missing or invalid"
    )
    pull_flags = {
        key: require_boolean(pull.get(key), f"{key} must be boolean")
        for key in (
            "dismiss_stale_reviews_on_push",
            "require_code_owner_review",
            "require_last_push_approval",
            "required_review_thread_resolution",
        )
    }
    extra_approval = pull.get("require_extra_approval_for_unattributed_changes")
    if extra_approval is not None:
        extra_approval = require_boolean(
            extra_approval,
            "require_extra_approval_for_unattributed_changes must be boolean",
        )
    approving_review_count = require_nonnegative_integer(
        pull.get("required_approving_review_count"),
        "required_approving_review_count must be a non-negative integer",
    )
    do_not_enforce_on_create = require_boolean(
        status.get("do_not_enforce_on_create"),
        "do_not_enforce_on_create must be boolean",
    )
    strict_status_checks = require_boolean(
        status.get("strict_required_status_checks_policy"),
        "strict_required_status_checks_policy must be boolean",
    )
    return {
        "name": value.get("name"),
        "target": value.get("target"),
        "enforcement": value.get("enforcement"),
        "bypass_actors": value.get("bypass_actors"),
        "conditions": {
            "ref_name": {
                "include": sorted(included_refs),
                "exclude": sorted(excluded_refs),
            }
        },
        "rules": {
            "deletion": True,
            "non_fast_forward": True,
            "required_linear_history": True,
            "pull_request": {
                "allowed_merge_methods": allowed_merge_methods,
                **pull_flags,
                "require_extra_approval_for_unattributed_changes": extra_approval,
                "required_approving_review_count": approving_review_count,
                "additional_parameters": {
                    key: copy.deepcopy(pull[key])
                    for key in sorted(set(pull) - known_pull_parameters)
                },
            },
            "required_status_checks": {
                "do_not_enforce_on_create": do_not_enforce_on_create,
                "contexts": [row["context"] for row in checks],
                "checks": checks,
                "strict_required_status_checks_policy": strict_status_checks,
                "additional_parameters": {
                    key: copy.deepcopy(status[key])
                    for key in sorted(set(status) - known_status_parameters)
                },
            },
        },
        "additional_rules": {
            rule_type: copy.deepcopy(dict(by_type[rule_type]))
            for rule_type in sorted(set(by_type) - required_types)
        },
    }


def rules_by_type(ruleset: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rules = require_list(ruleset.get("rules"), "ruleset rules missing")
    result: dict[str, Mapping[str, Any]] = {}
    for raw_value in rules:
        raw = require_mapping(raw_value, "ruleset contains an invalid rule")
        rule_type = require_string(raw.get("type"), "ruleset rule type invalid")
        require(rule_type not in result, f"duplicate ruleset rule: {rule_type}")
        result[rule_type] = raw
    return result


def merge_ruleset_preserving_stronger_controls(
    existing: Mapping[str, Any], baseline: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a baseline-compliant payload without removing stronger live controls."""

    normalize_ruleset(baseline)
    merged = copy.deepcopy(dict(baseline))
    existing_rules = rules_by_type(existing)
    merged_rules = rules_by_type(merged)

    existing_conditions = require_mapping(
        existing.get("conditions"), "existing ruleset conditions missing"
    )
    existing_refs = require_mapping(
        existing_conditions.get("ref_name"), "existing ruleset ref conditions missing"
    )
    existing_includes = require_string_list(
        existing_refs.get("include"), "existing included refs missing or invalid"
    )
    merged_conditions = require_mapping(
        merged.get("conditions"), "merged ruleset conditions missing"
    )
    merged_refs_value = merged_conditions.get("ref_name")
    if not isinstance(merged_refs_value, dict):
        raise PolicyError("merged ruleset ref conditions missing")
    merged_includes = require_string_list(
        merged_refs_value.get("include"), "merged included refs missing or invalid"
    )
    merged_refs_value["include"] = list(
        dict.fromkeys(merged_includes + existing_includes)
    )

    merged_rule_list = require_list(merged.get("rules"), "merged rules missing")
    for rule_type, rule in existing_rules.items():
        if rule_type not in merged_rules:
            merged_rule_list.append(copy.deepcopy(dict(rule)))

    merged_pull_value = merged_rules["pull_request"].get("parameters")
    if not isinstance(merged_pull_value, dict):
        raise PolicyError("merged pull-request parameters missing")
    existing_pull_rule = existing_rules.get("pull_request")
    if existing_pull_rule is not None:
        existing_pull = require_mapping(
            existing_pull_rule.get("parameters"),
            "existing pull-request parameters missing",
        )
        for key, item in existing_pull.items():
            if key not in merged_pull_value:
                merged_pull_value[key] = copy.deepcopy(item)
        boolean_keys = (
            "dismiss_stale_reviews_on_push",
            "require_code_owner_review",
            "require_extra_approval_for_unattributed_changes",
            "require_last_push_approval",
            "required_review_thread_resolution",
        )
        for key in boolean_keys:
            if key not in existing_pull:
                continue
            existing_flag = require_boolean(
                existing_pull.get(key), f"existing {key} must be boolean"
            )
            if existing_flag:
                merged_pull_value[key] = True
        existing_count = existing_pull.get("required_approving_review_count", 0)
        require(
            isinstance(existing_count, int) and not isinstance(existing_count, bool),
            "existing approving-review count invalid",
        )
        baseline_count = merged_pull_value.get("required_approving_review_count")
        require(
            isinstance(baseline_count, int) and not isinstance(baseline_count, bool),
            "baseline approving-review count invalid",
        )
        merged_pull_value["required_approving_review_count"] = max(
            existing_count, baseline_count
        )

    merged_status_value = merged_rules["required_status_checks"].get("parameters")
    if not isinstance(merged_status_value, dict):
        raise PolicyError("merged status-check parameters missing")
    baseline_checks = require_list(
        merged_status_value.get("required_status_checks"),
        "baseline status checks missing",
    )
    existing_checks: list[Any] = []
    existing_status_rule = existing_rules.get("required_status_checks")
    if existing_status_rule is not None:
        existing_status = require_mapping(
            existing_status_rule.get("parameters"),
            "existing status-check parameters missing",
        )
        for key, item in existing_status.items():
            if key not in merged_status_value:
                merged_status_value[key] = copy.deepcopy(item)
        for key in (
            "do_not_enforce_on_create",
            "strict_required_status_checks_policy",
        ):
            if key in existing_status:
                require_boolean(
                    existing_status.get(key), f"existing {key} must be boolean"
                )
        existing_checks = require_list(
            existing_status.get("required_status_checks"),
            "existing status checks missing",
        )

    existing_by_context: dict[str, Mapping[str, Any]] = {}
    for row_value in existing_checks:
        row = require_mapping(row_value, "invalid existing status check")
        context = require_string(row.get("context"), "invalid existing status context")
        require(
            context not in existing_by_context,
            f"duplicate existing status context: {context}",
        )
        integration_id = row.get("integration_id")
        if integration_id is not None:
            require(
                isinstance(integration_id, int)
                and not isinstance(integration_id, bool)
                and integration_id > 0,
                f"{context}: invalid status-check integration ID",
            )
        provider_slug = row.get("provider_slug")
        if provider_slug is not None:
            require_string(provider_slug, f"{context}: invalid status-check provider slug")
        existing_by_context[context] = row

    combined_checks: list[dict[str, Any]] = []
    baseline_contexts: set[str] = set()
    for row_value in baseline_checks:
        row = require_mapping(row_value, "invalid baseline status check")
        context = require_string(row.get("context"), "invalid baseline status context")
        require(
            context not in baseline_contexts,
            f"duplicate baseline status context: {context}",
        )
        baseline_contexts.add(context)
        combined = copy.deepcopy(dict(row))
        existing_row = existing_by_context.get(context)
        if existing_row is not None:
            for key, item in existing_row.items():
                if key not in combined:
                    combined[key] = copy.deepcopy(item)
        combined_checks.append(combined)
    for context, row in existing_by_context.items():
        if context not in baseline_contexts:
            combined_checks.append(copy.deepcopy(dict(row)))
    merged_status_value["required_status_checks"] = combined_checks
    normalize_ruleset(merged)
    return merged


def ruleset_meets_baseline(
    actual: Mapping[str, Any], baseline: Mapping[str, Any]
) -> bool:
    try:
        effective = merge_ruleset_preserving_stronger_controls(actual, baseline)
        return normalize_ruleset(actual) == normalize_ruleset(effective)
    except PolicyError:
        return False


def repo_path(name: str) -> str:
    return urllib.parse.quote(name, safe="/")


def find_ruleset(api: GitHubApi, repository: str) -> dict[str, Any] | None:
    matches = [
        row
        for row in api.list_rulesets(repository)
        if row.get("name") == RULESET_NAME
        and row.get("source_type", "Repository") == "Repository"
    ]
    require(len(matches) <= 1, f"{repository}: duplicate named rulesets")
    return matches[0] if matches else None


def verify_live(
    api: GitHubApi,
    config: Mapping[str, Any],
    repository: Mapping[str, Any],
    *,
    exact_expected: Mapping[str, Any] | None = None,
) -> int:
    full_name = str(repository["repository"])
    existing = find_ruleset(api, full_name)
    if existing is None:
        raise PolicyError(f"{full_name}: ruleset missing")
    ruleset_id = existing.get("id")
    if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
        raise PolicyError(f"{full_name}: ruleset ID invalid")
    observed = api.get_ruleset(full_name, ruleset_id)
    baseline = desired_ruleset(config, repository)
    require(
        ruleset_meets_baseline(observed, baseline),
        f"{full_name}: live ruleset is weaker than policy",
    )
    if exact_expected is not None:
        require(
            ruleset_meets_baseline(observed, exact_expected),
            f"{full_name}: stronger live controls changed during apply",
        )
    return ruleset_id


def write_evidence(document: Mapping[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "result.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "## Protected default-branch release authorities",
        "",
        f"- Result: `{document.get('result')}`",
        f"- Mode: `{document.get('mode')}`",
        f"- Source SHA: `{document.get('source_sha')}`",
        "- Target: `~DEFAULT_BRANCH`",
        "- Approvals: `1`",
        "- Merge method: `squash`",
        "- Bypass actors: `none`",
        "",
        "| Repository | Action | Ruleset | Result |",
        "|---|---|---:|---|",
    ]
    for row in document.get("repositories", []):
        lines.append(
            f"| `{row.get('repository')}` | `{row.get('action')}` | "
            f"`{row.get('ruleset_id', '')}` | `{row.get('result')}` |"
        )
    (EVIDENCE_DIR / "result.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def execute(mode: str, confirmation: str) -> dict[str, Any]:
    config = load_config()
    repositories = validate_config(config)
    if mode == "validate":
        for repository in repositories:
            normalize_ruleset(desired_ruleset(config, repository))
        return {
            "schema_version": "1.0",
            "mode": mode,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "result": "PASS",
            "repositories": [
                {
                    "repository": item["repository"],
                    "action": "policy-validated",
                    "result": "PASS",
                }
                for item in repositories
            ],
        }

    require(mode in {"apply", "verify"}, "unsupported mode")
    if mode == "apply":
        require(confirmation == CONFIRMATION, "exact apply confirmation required")
    token = os.environ.get(TOKEN_ENV, "")
    require(bool(token), f"{TOKEN_ENV} is required")
    api = GitHubApi(token)

    preflight: list[
        tuple[
            dict[str, Any],
            dict[str, Any] | None,
            dict[str, Any] | None,
            dict[str, Any],
        ]
    ] = []
    for repository in repositories:
        full_name = str(repository["repository"])
        metadata = api.request("GET", f"/repos/{repo_path(full_name)}").payload
        require(isinstance(metadata, dict), f"{full_name}: repository metadata invalid")
        require(metadata.get("id") == repository["repository_id"], f"{full_name}: ID drift")
        require(metadata.get("default_branch") == "main", f"{full_name}: default branch drift")
        require(metadata.get("archived") is False, f"{full_name}: repository is archived")
        require(metadata.get("disabled") is False, f"{full_name}: repository is disabled")
        permissions = metadata.get("permissions")
        require(
            isinstance(permissions, Mapping) and permissions.get("admin") is True,
            f"{full_name}: token lacks repository administration",
        )
        existing = find_ruleset(api, full_name)
        current: dict[str, Any] | None = None
        effective = desired_ruleset(config, repository)
        if existing is not None:
            ruleset_id = existing.get("id")
            if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
                raise PolicyError(f"{full_name}: ruleset ID invalid")
            current = api.get_ruleset(full_name, ruleset_id)
            effective = merge_ruleset_preserving_stronger_controls(current, effective)
        preflight.append((repository, existing, current, effective))

    results: list[dict[str, Any]] = []
    for repository, existing, current, effective in preflight:
        full_name = str(repository["repository"])
        action = "verify"
        if mode == "apply":
            if current is not None and ruleset_meets_baseline(current, effective):
                action = "already-compliant"
            else:
                _, action = api.upsert_ruleset(full_name, effective, existing)
        ruleset_id = verify_live(
            api,
            config,
            repository,
            exact_expected=effective if mode == "apply" else None,
        )
        results.append(
            {
                "repository": full_name,
                "action": action,
                "ruleset_id": ruleset_id,
                "result": "PASS",
            }
        )
    return {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "mode": mode,
        "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "actor": os.environ.get("GITHUB_ACTOR", "local"),
        "result": "PASS",
        "production_changed": False,
        "runtime_contacted": False,
        "repositories": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("validate", "apply", "verify"), default="validate")
    parser.add_argument("--confirm", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        document = execute(args.mode, args.confirm)
        write_evidence(document)
        print(
            "PORTFOLIO_MAIN_RELEASE_AUTHORITY="
            f"PASS mode={args.mode} repositories={len(document['repositories'])}"
        )
        return 0
    except (PolicyError, RolloutError) as exc:
        document = {
            "schema_version": "1.0",
            "mode": args.mode,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "result": "FAIL",
            "production_changed": False,
            "runtime_contacted": False,
            "error": str(exc),
            "repositories": [],
        }
        write_evidence(document)
        print(f"PORTFOLIO_MAIN_RELEASE_AUTHORITY=FAIL reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
