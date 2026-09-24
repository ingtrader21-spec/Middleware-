#!/usr/bin/env python3
"""Apply and verify fixed integration-repository review and ruleset authority."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "integration-main-release-authorities.v1.json"
EVIDENCE_DIR = ROOT / "artifacts" / "integration-main-release-authorities"
TOKEN_ENV = "CODESTRA_REPOSITORY_ADMIN_TOKEN"
CONFIRMATION = "APPLY_INTEGRATION_MAIN_RELEASE_AUTHORITY_V1"
AUTHORITY_ID = "codestra.integration-main-release-authorities.v1"
RULESET_NAME = "Codestra integration protected-main release gates"
EXPECTED_OWNER = "appolon1908-hue"
EXPECTED_REVIEWER = {
    "login": "kazan555",
    "user_id": 77101516,
    "permission": "push",
    "admin": False,
}
EXPECTED_REPOSITORIES = {
    "appolon1908-hue/social.codestra.co": (
        1348783113,
        (
            "Backend policy, migration, test, and build",
            "Backend container build and hardening",
            "certify",
        ),
    ),
    "appolon1908-hue/Codestra-AI": (
        1351354401,
        ("unit-and-contract", "postgres-certification", "container-build"),
    ),
    "appolon1908-hue/Codestra-Marketing-": (
        1351352422,
        ("unit-and-contract", "postgres-certification", "container-build"),
    ),
    "appolon1908-hue/Vicidialer-Codestra": (
        1347744324,
        (
            "deploy-readiness / deploy-readiness / secret-scan",
            "deploy-readiness / deploy-readiness / source-ci",
        ),
    ),
}


class PolicyError(RuntimeError):
    """Committed policy or observed GitHub state is invalid."""


class GitHubApiError(PolicyError):
    """A status-bearing GitHub API failure."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class PendingInvitation(PolicyError):
    """At least one exact reviewer invitation still needs acceptance."""


def require(condition: bool, message: str) -> None:
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
    if not isinstance(value, str) or not value:
        raise PolicyError(message)
    return value


def require_string_list(value: object, message: str) -> list[str]:
    values = require_list(value, message)
    result = [require_string(item, message) for item in values]
    require(len(result) == len(set(result)), message)
    return result


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot load integration authority: {path}") from exc
    require(isinstance(value, dict), "authority must be an object")
    return value


def validate_config(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    require(config.get("schema_version") == "1.0", "unsupported authority schema")
    require(config.get("authority_id") == AUTHORITY_ID, "authority ID drift")
    require(config.get("owner") == EXPECTED_OWNER, "owner drift")
    require(config.get("ruleset_name") == RULESET_NAME, "ruleset name drift")
    require(config.get("reviewer") == EXPECTED_REVIEWER, "reviewer authority drift")
    require(config.get("required_approvals") == 1, "exactly one approval is required")
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
    require(config.get("allowed_merge_methods") == ["squash"], "squash-only drift")
    require(config.get("bypass_actors") == [], "bypass actors are forbidden")

    rows = require_list(config.get("repositories"), "repositories must be a list")
    require(len(rows) == len(EXPECTED_REPOSITORIES), "repository count drift")
    observed: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for raw_value in rows:
        raw = require_mapping(raw_value, "repository record must be an object")
        name = require_string(raw.get("repository"), "repository name missing")
        require(name in EXPECTED_REPOSITORIES, "unknown repository")
        require(name not in observed, f"duplicate repository: {name}")
        observed.add(name)
        expected_id, expected_checks = EXPECTED_REPOSITORIES[name]
        require(raw.get("repository_id") == expected_id, f"{name}: stable ID drift")
        require(raw.get("default_branch") == "main", f"{name}: default branch drift")
        checks = require_list(
            raw.get("required_status_checks"),
            f"{name}: required status checks missing",
        )
        require(
            tuple(checks) == expected_checks
            and len(checks) == len(set(checks)),
            f"{name}: required status check drift",
        )
        normalized.append(dict(raw))
    require(observed == set(EXPECTED_REPOSITORIES), "repository coverage drift")
    return sorted(normalized, key=lambda row: str(row["repository"]).casefold())


def desired_ruleset(repository: Mapping[str, Any]) -> dict[str, Any]:
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
                        {"context": context}
                        for context in repository["required_status_checks"]
                    ],
                    "strict_required_status_checks_policy": True,
                },
            },
        ],
    }


def normalize_ruleset(value: Mapping[str, Any]) -> dict[str, Any]:
    conditions = require_mapping(value.get("conditions"), "ruleset conditions missing")
    ref_name = require_mapping(
        conditions.get("ref_name"),
        "ruleset ref conditions missing",
    )
    included_refs = require_string_list(
        ref_name.get("include"),
        "ruleset included refs missing or invalid",
    )
    excluded_refs = require_string_list(
        ref_name.get("exclude"),
        "ruleset excluded refs missing or invalid",
    )
    rules = require_list(value.get("rules"), "ruleset rules missing")

    by_type: dict[str, Mapping[str, Any]] = {}
    for raw_value in rules:
        raw = require_mapping(raw_value, "invalid ruleset rule")
        kind = require_string(raw.get("type"), "invalid ruleset rule type")
        require(kind not in by_type, f"duplicate ruleset rule: {kind}")
        by_type[kind] = raw
    required_rule_types = {
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
        "required_status_checks",
    }
    require(
        required_rule_types.issubset(by_type),
        "required ruleset rule missing",
    )

    pull = require_mapping(
        by_type["pull_request"].get("parameters"),
        "pull request parameters missing",
    )
    status = require_mapping(
        by_type["required_status_checks"].get("parameters"),
        "status check parameters missing",
    )
    raw_checks = require_list(
        status.get("required_status_checks"),
        "status checks missing",
    )
    checks: list[dict[str, Any]] = []
    observed_contexts: set[str] = set()
    for row_value in raw_checks:
        row = require_mapping(row_value, "invalid status check")
        context = require_string(row.get("context"), "invalid status context")
        require(context not in observed_contexts, f"duplicate status context: {context}")
        observed_contexts.add(context)
        check = copy.deepcopy(dict(row))
        check["context"] = context
        integration_id = row.get("integration_id")
        if integration_id is not None:
            if (
                not isinstance(integration_id, int)
                or isinstance(integration_id, bool)
                or integration_id <= 0
            ):
                raise PolicyError(f"{context}: invalid status-check integration ID")
            check["integration_id"] = integration_id
        checks.append(check)
    checks.sort(key=lambda check: str(check["context"]))

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
                "allowed_merge_methods": list(pull.get("allowed_merge_methods", [])),
                "dismiss_stale_reviews_on_push": pull.get("dismiss_stale_reviews_on_push"),
                "require_code_owner_review": pull.get("require_code_owner_review"),
                "require_extra_approval_for_unattributed_changes": pull.get(
                    "require_extra_approval_for_unattributed_changes"
                ),
                "require_last_push_approval": pull.get("require_last_push_approval"),
                "required_approving_review_count": pull.get(
                    "required_approving_review_count"
                ),
                "required_review_thread_resolution": pull.get(
                    "required_review_thread_resolution"
                ),
                "additional_parameters": {
                    key: copy.deepcopy(pull[key])
                    for key in sorted(set(pull) - known_pull_parameters)
                },
            },
            "required_status_checks": {
                "do_not_enforce_on_create": status.get("do_not_enforce_on_create"),
                "contexts": [check["context"] for check in checks],
                "checks": checks,
                "strict_required_status_checks_policy": status.get(
                    "strict_required_status_checks_policy"
                ),
                "additional_parameters": {
                    key: copy.deepcopy(status[key])
                    for key in sorted(set(status) - known_status_parameters)
                },
            },
        },
        "additional_rules": {
            kind: copy.deepcopy(dict(by_type[kind]))
            for kind in sorted(set(by_type) - required_rule_types)
        },
    }


def rules_by_type(ruleset: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rules = require_list(ruleset.get("rules"), "ruleset rules missing")
    result: dict[str, Mapping[str, Any]] = {}
    for raw_value in rules:
        raw = require_mapping(raw_value, "invalid ruleset rule")
        kind = require_string(raw.get("type"), "invalid ruleset rule type")
        require(kind not in result, f"duplicate ruleset rule: {kind}")
        result[kind] = raw
    return result


def merge_ruleset_preserving_stronger_controls(
    existing: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply the baseline without deleting stronger live protection."""

    normalize_ruleset(baseline)
    merged = copy.deepcopy(dict(baseline))
    existing_rules = rules_by_type(existing)
    merged_rules = rules_by_type(merged)

    existing_conditions = require_mapping(
        existing.get("conditions"),
        "existing ruleset conditions missing",
    )
    existing_ref_name = require_mapping(
        existing_conditions.get("ref_name"),
        "existing ruleset ref conditions missing",
    )
    existing_included_refs = require_string_list(
        existing_ref_name.get("include"),
        "existing included refs missing or invalid",
    )
    merged_conditions = require_mapping(
        merged.get("conditions"),
        "merged ruleset conditions missing",
    )
    merged_ref_name_value = merged_conditions.get("ref_name")
    if not isinstance(merged_ref_name_value, dict):
        raise PolicyError("merged ruleset ref conditions missing")
    merged_included_refs = require_string_list(
        merged_ref_name_value.get("include"),
        "merged included refs missing or invalid",
    )
    merged_ref_name_value["include"] = list(
        dict.fromkeys(merged_included_refs + existing_included_refs)
    )

    for kind, rule in existing_rules.items():
        if kind not in merged_rules:
            cast_rules = require_list(merged.get("rules"), "merged rules missing")
            cast_rules.append(copy.deepcopy(dict(rule)))

    merged_pull_value = merged_rules["pull_request"].get("parameters")
    if not isinstance(merged_pull_value, dict):
        raise PolicyError("merged pull request parameters missing")
    merged_pull = merged_pull_value
    existing_pull_rule = existing_rules.get("pull_request")
    if existing_pull_rule is not None:
        existing_pull = require_mapping(
            existing_pull_rule.get("parameters"),
            "existing pull request parameters missing",
        )
        for key, value in existing_pull.items():
            if key not in merged_pull:
                merged_pull[key] = copy.deepcopy(value)
        for key in (
            "dismiss_stale_reviews_on_push",
            "require_code_owner_review",
            "require_extra_approval_for_unattributed_changes",
            "require_last_push_approval",
            "required_review_thread_resolution",
        ):
            if existing_pull.get(key) is True:
                merged_pull[key] = True
        existing_count = existing_pull.get("required_approving_review_count", 0)
        if not isinstance(existing_count, int) or isinstance(existing_count, bool):
            raise PolicyError("existing approving-review count invalid")
        merged_pull["required_approving_review_count"] = max(
            int(merged_pull["required_approving_review_count"]),
            existing_count,
        )

    merged_status_value = merged_rules["required_status_checks"].get("parameters")
    if not isinstance(merged_status_value, dict):
        raise PolicyError("merged status parameters missing")
    merged_status = merged_status_value
    baseline_checks = require_list(
        merged_status.get("required_status_checks"),
        "baseline status checks missing",
    )
    existing_checks: list[Any] = []
    existing_status_rule = existing_rules.get("required_status_checks")
    if existing_status_rule is not None:
        existing_status = require_mapping(
            existing_status_rule.get("parameters"),
            "existing status parameters missing",
        )
        for key, value in existing_status.items():
            if key not in merged_status:
                merged_status[key] = copy.deepcopy(value)
        existing_checks = require_list(
            existing_status.get("required_status_checks"),
            "existing status checks missing",
        )

    by_context: dict[str, Mapping[str, Any]] = {}
    for row_value in existing_checks:
        row = require_mapping(row_value, "invalid existing status check")
        context = require_string(
            row.get("context"),
            "invalid existing status context",
        )
        require(context not in by_context, f"duplicate existing status context: {context}")
        by_context[context] = row

    combined_checks: list[dict[str, Any]] = []
    baseline_contexts: set[str] = set()
    for row_value in baseline_checks:
        row = require_mapping(row_value, "invalid baseline status check")
        context = require_string(
            row.get("context"),
            "invalid baseline status context",
        )
        require(context not in baseline_contexts, f"duplicate baseline status context: {context}")
        baseline_contexts.add(context)
        source = copy.deepcopy(dict(row))
        existing_row = by_context.get(context)
        if existing_row is not None:
            for key, value in existing_row.items():
                if key not in source:
                    source[key] = copy.deepcopy(value)
        combined_checks.append(source)
    for row_value in existing_checks:
        row = require_mapping(row_value, "invalid existing status check")
        context = require_string(
            row.get("context"),
            "invalid existing status context",
        )
        if context not in baseline_contexts:
            combined_checks.append(copy.deepcopy(dict(row)))
    merged_status["required_status_checks"] = combined_checks
    return merged


def ruleset_meets_baseline(
    actual: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> bool:
    effective = merge_ruleset_preserving_stronger_controls(actual, baseline)
    try:
        return normalize_ruleset(actual) == normalize_ruleset(effective)
    except PolicyError:
        return False


class FailClosedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward an administration bearer token through a redirect."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(FailClosedRedirectHandler())


class GitHubApi:
    def __init__(self, token: str) -> None:
        self.token = token
        self.base = "https://api.github.com"

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.base + path,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "codestra-integration-authority-v1",
            },
        )
        try:
            with NO_REDIRECT_OPENER.open(request, timeout=30) as response:
                raw = response.read()
                value = json.loads(raw) if raw else None
                return response.status, value
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            detail = raw.decode("utf-8", errors="replace")
            raise GitHubApiError(
                exc.code,
                f"GitHub API {method} {path} failed with HTTP {exc.code}: {detail[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise PolicyError(f"GitHub API {method} {path} unavailable") from exc


def repo_path(name: str) -> str:
    return urllib.parse.quote(name, safe="/")


def read_reviewer_permission(
    api: GitHubApi,
    repository: str,
    encoded_repository: str,
    *,
    allow_missing: bool,
) -> str | None:
    try:
        status, value = api.request(
            "GET",
            f"/repos/{encoded_repository}/collaborators/"
            f"{EXPECTED_REVIEWER['login']}/permission",
        )
    except GitHubApiError as exc:
        if allow_missing and exc.status_code == 404:
            return None
        raise
    require(status == 200, f"{repository}: reviewer permission readback failed")
    permission = require_mapping(
        value,
        f"{repository}: reviewer permission readback invalid",
    ).get("permission")
    require(
        isinstance(permission, str),
        f"{repository}: reviewer permission readback invalid",
    )
    return permission


def ensure_exact_reviewer_write(
    api: GitHubApi,
    repository: str,
    encoded_repository: str,
    mode: str,
) -> tuple[str, bool]:
    permission = read_reviewer_permission(
        api,
        repository,
        encoded_repository,
        allow_missing=True,
    )
    if permission == "write":
        return "verified-write", False
    if mode == "verify":
        raise PolicyError(f"{repository}: reviewer permission is not exact write")

    status, _ = api.request(
        "PUT",
        f"/repos/{encoded_repository}/collaborators/{EXPECTED_REVIEWER['login']}",
        {"permission": "push"},
    )
    require(status in {201, 204}, f"{repository}: unexpected collaborator response")
    if status == 201:
        return "invitation-pending", True

    permission = read_reviewer_permission(
        api,
        repository,
        encoded_repository,
        allow_missing=False,
    )
    require(
        permission == "write",
        f"{repository}: collaborator permission did not read back as exact write",
    )
    return "added-and-verified-write", False


def find_ruleset(api: GitHubApi, repository: str) -> dict[str, Any] | None:
    _, payload_value = api.request(
        "GET",
        f"/repos/{repo_path(repository)}/rulesets?includes_parents=false&per_page=100",
    )
    payload = require_list(payload_value, f"{repository}: ruleset list invalid")
    matches = [
        row
        for row in payload
        if isinstance(row, Mapping)
        and row.get("name") == RULESET_NAME
        and row.get("source_type", "Repository") == "Repository"
    ]
    require(len(matches) <= 1, f"{repository}: duplicate named rulesets")
    return dict(matches[0]) if matches else None


def verify_ruleset(
    api: GitHubApi,
    repository: str,
    expected: Mapping[str, Any],
    *,
    exact_expected: Mapping[str, Any] | None = None,
) -> int:
    found = find_ruleset(api, repository)
    if found is None:
        raise PolicyError(f"{repository}: integration ruleset missing")
    ruleset_id = found.get("id")
    if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
        raise PolicyError(f"{repository}: ruleset ID invalid")
    _, payload_value = api.request(
        "GET",
        f"/repos/{repo_path(repository)}/rulesets/{ruleset_id}",
    )
    payload = require_mapping(
        payload_value,
        f"{repository}: ruleset readback invalid",
    )
    require(
        ruleset_meets_baseline(payload, expected),
        f"{repository}: live integration ruleset is weaker than committed policy",
    )
    if exact_expected is not None:
        require(
            ruleset_meets_baseline(payload, exact_expected),
            f"{repository}: stronger live ruleset controls changed during apply",
        )
    return ruleset_id


def write_evidence(document: Mapping[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "result.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "## Integration protected-main release authorities",
        "",
        f"- Result: `{document.get('result')}`",
        f"- Mode: `{document.get('mode')}`",
        f"- Source SHA: `{document.get('source_sha')}`",
        "- Reviewer: `kazan555` (`push`, non-admin)",
        "- Required approvals: `1`",
        "- Merge method: `squash`",
        "- Bypass actors: `none`",
        "- Runtime contacted: `NO`",
        "",
        "| Repository | Reviewer | Ruleset | Result |",
        "|---|---|---:|---|",
    ]
    for row in document.get("repositories", []):
        lines.append(
            f"| `{row.get('repository')}` | `{row.get('reviewer')}` | "
            f"`{row.get('ruleset_id', '')}` | `{row.get('result')}` |"
        )
    (EVIDENCE_DIR / "result.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def execute(mode: str, confirmation: str) -> dict[str, Any]:
    config = load_config()
    repositories = validate_config(config)
    for repository in repositories:
        normalize_ruleset(desired_ruleset(repository))

    base = {
        "schema_version": "1.0",
        "mode": mode,
        "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "production_changed": False,
        "runtime_contacted": False,
        "external_effects_enabled": False,
    }
    if mode == "validate":
        return {
            **base,
            "result": "PASS",
            "repositories": [
                {
                    "repository": row["repository"],
                    "reviewer": "policy-validated",
                    "ruleset_id": None,
                    "result": "PASS",
                }
                for row in repositories
            ],
        }

    require(mode in {"apply", "verify"}, "unsupported mode")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        require(
            os.environ.get("GITHUB_REPOSITORY") == "ingtrader21-spec/Middleware-",
            "workflow repository drift",
        )
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "protected main required")
        require(
            os.environ.get("GITHUB_ACTOR") == os.environ.get("GITHUB_REPOSITORY_OWNER"),
            "repository owner must dispatch",
        )
    if mode == "apply":
        require(confirmation == CONFIRMATION, "exact apply confirmation required")
    token = os.environ.get(TOKEN_ENV, "")
    require(bool(token), f"{TOKEN_ENV} is required")
    api = GitHubApi(token)

    _, reviewer = api.request("GET", f"/users/{EXPECTED_REVIEWER['login']}")
    require(isinstance(reviewer, Mapping), "reviewer identity readback invalid")
    require(
        reviewer.get("id") == EXPECTED_REVIEWER["user_id"],
        "reviewer stable user ID drift",
    )

    pending = False
    results: list[dict[str, Any]] = []
    for repository in repositories:
        name = str(repository["repository"])
        encoded = repo_path(name)
        _, metadata = api.request("GET", f"/repos/{encoded}")
        require(isinstance(metadata, Mapping), f"{name}: metadata invalid")
        require(metadata.get("id") == repository["repository_id"], f"{name}: ID drift")
        require(metadata.get("default_branch") == "main", f"{name}: default branch drift")
        require(metadata.get("archived") is False, f"{name}: repository archived")
        require(metadata.get("disabled") is False, f"{name}: repository disabled")
        permissions = metadata.get("permissions")
        require(
            isinstance(permissions, Mapping) and permissions.get("admin") is True,
            f"{name}: token lacks repository administration",
        )

        reviewer_state, invitation_pending = ensure_exact_reviewer_write(
            api,
            name,
            encoded,
            mode,
        )
        pending = pending or invitation_pending

        desired = desired_ruleset(repository)
        existing = find_ruleset(api, name)
        effective = desired
        if existing is not None:
            existing_ruleset_id = existing.get("id")
            require(isinstance(existing_ruleset_id, int), f"{name}: ruleset ID invalid")
            _, current = api.request(
                "GET",
                f"/repos/{encoded}/rulesets/{existing_ruleset_id}",
            )
            require(isinstance(current, Mapping), f"{name}: ruleset readback invalid")
            effective = merge_ruleset_preserving_stronger_controls(current, desired)

        if mode == "apply":
            if existing is None:
                api.request("POST", f"/repos/{encoded}/rulesets", effective)
            else:
                if not ruleset_meets_baseline(current, effective):
                    api.request(
                        "PUT",
                        f"/repos/{encoded}/rulesets/{existing_ruleset_id}",
                        effective,
                    )
        ruleset_id = verify_ruleset(
            api,
            name,
            desired,
            exact_expected=effective if mode == "apply" else None,
        )
        results.append(
            {
                "repository": name,
                "reviewer": reviewer_state,
                "ruleset_id": ruleset_id,
                "result": "BLOCKED" if reviewer_state == "invitation-pending" else "PASS",
            }
        )

    document = {
        **base,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "actor": os.environ.get("GITHUB_ACTOR", "local"),
        "result": "BLOCKED" if pending else "PASS",
        "repositories": results,
    }
    if pending:
        write_evidence(document)
        raise PendingInvitation(
            "exact reviewer invitations are pending; acceptance and readback are required"
        )
    return document


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
            "INTEGRATION_MAIN_RELEASE_AUTHORITY="
            f"PASS mode={args.mode} repositories={len(document['repositories'])}"
        )
        return 0
    except PendingInvitation as exc:
        print(f"INTEGRATION_MAIN_RELEASE_AUTHORITY=BLOCKED reason={exc}", file=sys.stderr)
        return 2
    except PolicyError as exc:
        document = {
            "schema_version": "1.0",
            "mode": args.mode,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "result": "FAIL",
            "production_changed": False,
            "runtime_contacted": False,
            "external_effects_enabled": False,
            "error": str(exc),
            "repositories": [],
        }
        write_evidence(document)
        print(f"INTEGRATION_MAIN_RELEASE_AUTHORITY=FAIL reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
