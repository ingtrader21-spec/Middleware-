#!/usr/bin/env python3
"""Idempotently apply and verify the encoded GitHub repository governance baseline."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence, cast

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "repository-governance.v1.json"
API_VERSION = "2026-03-10"
RULESET_NAME = "middleware-main-production-authority"
TOKEN_ENV = "CODESTRA_REPOSITORY_ADMIN_TOKEN"
REQUIRED_CHECK_APP_ID = 15368


class GovernanceApplyError(RuntimeError):
    """The encoded policy is invalid or live GitHub settings do not conform."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GovernanceApplyError(message)


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceApplyError(f"cannot load policy: {path}") from exc
    require(isinstance(policy, dict), "governance policy must be an object")
    require(policy.get("schema_version") == "1.0", "unsupported governance schema")
    require(
        policy.get("repository") == "ingtrader21-spec/Middleware-",
        "repository authority drift",
    )
    require(
        isinstance(policy.get("repository_profile"), dict),
        "repository_profile policy is missing",
    )
    require(isinstance(policy.get("merge_policy"), dict), "merge_policy is missing")
    require(
        isinstance(policy.get("default_branch_ruleset"), dict),
        "default_branch_ruleset is missing",
    )
    require(isinstance(policy.get("actions_policy"), dict), "actions_policy is missing")
    require(isinstance(policy.get("security_policy"), dict), "security_policy is missing")
    require(isinstance(policy.get("environments"), dict), "environments policy is missing")
    return policy


def repository_patch(policy: Mapping[str, Any]) -> dict[str, Any]:
    profile = policy["repository_profile"]
    merge = policy["merge_policy"]
    return {
        "description": profile["description"],
        "has_issues": profile["has_issues"],
        "has_wiki": profile["has_wiki"],
        "allow_squash_merge": merge["allow_squash_merge"],
        "allow_merge_commit": merge["allow_merge_commit"],
        "allow_rebase_merge": merge["allow_rebase_merge"],
        "allow_auto_merge": merge["allow_auto_merge"],
        "allow_update_branch": merge["allow_update_branch"],
        "delete_branch_on_merge": merge["delete_branch_on_merge"],
        "web_commit_signoff_required": merge["web_commit_signoff_required"],
        "squash_merge_commit_title": "PR_TITLE",
        "squash_merge_commit_message": "PR_BODY",
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        },
    }


def ruleset_payload(policy: Mapping[str, Any]) -> dict[str, Any]:
    encoded = policy["default_branch_ruleset"]
    checks = encoded["required_status_checks"]
    if not isinstance(checks, list) or not checks:
        raise GovernanceApplyError("required status checks are invalid")
    require(all(isinstance(item, str) for item in checks), "required status checks are invalid")
    require(len(checks) == len(set(checks)), "required status checks contain duplicates")
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": encoded["enforcement"],
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
                    "dismiss_stale_reviews_on_push": encoded[
                        "dismiss_stale_reviews"
                    ],
                    "require_code_owner_review": encoded[
                        "require_code_owner_review"
                    ],
                    "require_extra_approval_for_unattributed_changes": encoded.get(
                        "require_extra_approval_for_unattributed_changes", False
                    ),
                    "require_last_push_approval": False,
                    "required_approving_review_count": encoded[
                        "required_approvals"
                    ],
                    "required_review_thread_resolution": encoded[
                        "require_review_thread_resolution"
                    ],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {
                            "context": context,
                            "integration_id": REQUIRED_CHECK_APP_ID,
                        }
                        for context in checks
                    ],
                    "strict_required_status_checks_policy": encoded[
                        "require_branch_up_to_date"
                    ],
                },
            },
        ],
    }


def deployment_branch_policy_keys(
    environment: Mapping[str, Any],
) -> set[tuple[str, str]]:
    branch_policy = environment.get("deployment_branch_policy")
    if not isinstance(branch_policy, Mapping):
        raise GovernanceApplyError("deployment branch policy is missing")
    protected_branches = branch_policy.get("protected_branches")
    custom_branch_policies = branch_policy.get("custom_branch_policies")
    require(
        isinstance(protected_branches, bool)
        and isinstance(custom_branch_policies, bool)
        and protected_branches is not custom_branch_policies,
        "exactly one deployment branch-policy mode must be active",
    )

    desired = environment.get("allowed_branches", [])
    require(isinstance(desired, list), "allowed_branches must be a list")
    if protected_branches:
        require(
            not desired,
            "protected-branch mode must not define custom branch policies",
        )
        return set()
    require(bool(desired), "custom branch-policy mode requires allowed_branches")

    desired_keys = {
        (item.get("name"), item.get("type", "branch"))
        for item in desired
        if isinstance(item, Mapping)
    }
    require(
        len(desired_keys) == len(desired)
        and all(
            isinstance(branch_name, str)
            and branch_name
            and policy_type in {"branch", "tag"}
            for branch_name, policy_type in desired_keys
        ),
        "allowed branch policies are invalid",
    )
    return cast(set[tuple[str, str]], desired_keys)


def environment_payload(environment: Mapping[str, Any]) -> dict[str, Any]:
    wait_timer = environment.get("wait_timer", 0)
    require(
        isinstance(wait_timer, int)
        and not isinstance(wait_timer, bool)
        and 0 <= wait_timer <= 43_200,
        "environment wait_timer is invalid",
    )
    prevent_self_review = environment.get("prevent_self_review")
    can_admins_bypass = environment.get("can_admins_bypass")
    require(
        isinstance(prevent_self_review, bool),
        "prevent_self_review must be boolean",
    )
    require(
        isinstance(can_admins_bypass, bool),
        "can_admins_bypass must be boolean",
    )

    reviewers = environment.get("reviewers", [])
    require(isinstance(reviewers, list), "environment reviewers must be a list")
    normalized_reviewers: list[dict[str, Any]] = []
    reviewer_keys: set[tuple[str, int]] = set()
    for reviewer in reviewers:
        require(isinstance(reviewer, Mapping), "environment reviewer must be an object")
        reviewer_type = reviewer.get("type")
        reviewer_id = reviewer.get("id")
        require(reviewer_type in {"User", "Team"}, "invalid environment reviewer type")
        require(
            isinstance(reviewer_id, int)
            and not isinstance(reviewer_id, bool)
            and reviewer_id > 0,
            "invalid reviewer ID",
        )
        key = (str(reviewer_type), reviewer_id)
        require(key not in reviewer_keys, "duplicate environment reviewer")
        reviewer_keys.add(key)
        normalized_reviewers.append({"type": reviewer_type, "id": reviewer_id})
    require(
        not normalized_reviewers or prevent_self_review is True,
        "reviewed environments must prevent self-review",
    )

    branch_policy = environment.get("deployment_branch_policy")
    if not isinstance(branch_policy, Mapping):
        raise GovernanceApplyError("deployment branch policy is missing")
    deployment_branch_policy_keys(environment)
    return {
        "wait_timer": wait_timer,
        "prevent_self_review": prevent_self_review,
        "can_admins_bypass": can_admins_bypass,
        "reviewers": normalized_reviewers,
        "deployment_branch_policy": {
            "protected_branches": branch_policy["protected_branches"],
            "custom_branch_policies": branch_policy["custom_branch_policies"],
        },
    }


@dataclass(frozen=True)
class ApiResponse:
    status: int
    payload: Any


class GitHubApi:
    def __init__(self, *, repository: str, token: str) -> None:
        require("/" in repository, "repository must use owner/name form")
        require(bool(token), f"{TOKEN_ENV} is required")
        self.repository = repository
        self.base = f"https://api.github.com/repos/{repository}"
        self._token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Any | None = None,
        expected: Iterable[int] = (200,),
    ) -> ApiResponse:
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "codestra-middleware-governance-applier",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                value = json.loads(raw.decode("utf-8")) if raw else None
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")[:1200]
            raise GovernanceApplyError(
                f"GitHub API {method} {path} returned {exc.code}: {raw}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise GovernanceApplyError(
                f"GitHub API unavailable for {method} {path}"
            ) from exc
        expected_set = set(expected)
        require(
            status in expected_set,
            f"GitHub API {method} {path} returned {status}; expected {sorted(expected_set)}",
        )
        return ApiResponse(status=status, payload=value)


def _rules_by_type(ruleset: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        raise GovernanceApplyError("ruleset rules are unavailable")
    result: dict[str, Mapping[str, Any]] = {}
    for item in rules:
        require(isinstance(item, dict), "ruleset contains an invalid rule")
        rule_type = item.get("type")
        if not isinstance(rule_type, str) or not rule_type:
            raise GovernanceApplyError("ruleset rule type is invalid")
        require(rule_type not in result, f"duplicate ruleset rule: {rule_type}")
        result[rule_type] = item
    return result


def _matching_rulesets(api: GitHubApi) -> list[Mapping[str, Any]]:
    response = api.request(
        "GET",
        "/rulesets?per_page=100&includes_parents=false",
        expected=(200,),
    ).payload
    require(isinstance(response, list), "ruleset list is invalid")
    return [
        item
        for item in response
        if isinstance(item, dict)
        and item.get("name") == RULESET_NAME
        and item.get("source_type", "Repository") == "Repository"
    ]


def verify_automated_security_fixes(api: GitHubApi) -> None:
    """Require enabled, unpaused security updates from GitHub's read-back."""

    response = api.request(
        "GET",
        "/automated-security-fixes",
        expected=(200,),
    )
    state = _require_mapping(response.payload, "Dependabot security update state is invalid")
    require(state.get("enabled") is True, "Dependabot security updates are not enabled")
    require(state.get("paused") is False, "Dependabot security updates are paused or unknown")


def apply_ruleset(api: GitHubApi, policy: Mapping[str, Any]) -> int:
    matches = _matching_rulesets(api)
    require(len(matches) <= 1, f"multiple rulesets named {RULESET_NAME}")
    payload = ruleset_payload(policy)
    if matches:
        ruleset_id = matches[0].get("id")
        require(isinstance(ruleset_id, int), "existing ruleset ID is unavailable")
        response = api.request(
            "PUT",
            f"/rulesets/{ruleset_id}",
            payload=payload,
            expected=(200,),
        )
    else:
        response = api.request(
            "POST",
            "/rulesets",
            payload=payload,
            expected=(201,),
        )
    ruleset_id = response.payload.get("id") if isinstance(response.payload, dict) else None
    if not isinstance(ruleset_id, int):
        raise GovernanceApplyError("applied ruleset ID is unavailable")
    return ruleset_id


def apply_environment(
    api: GitHubApi,
    *,
    name: str,
    encoded: Mapping[str, Any],
) -> None:
    encoded_name = urllib.parse.quote(name, safe="")
    api.request(
        "PUT",
        f"/environments/{encoded_name}",
        payload=environment_payload(encoded),
        expected=(200,),
    )

    desired_keys = deployment_branch_policy_keys(encoded)
    if not desired_keys:
        return

    policies_path = (
        f"/environments/{encoded_name}/deployment-branch-policies"
    )
    observed = api.request(
        "GET",
        f"{policies_path}?per_page=100",
        expected=(200,),
    ).payload
    require(isinstance(observed, dict), f"{name}: branch-policy list is invalid")
    policies = observed.get("branch_policies")
    if not isinstance(policies, list):
        raise GovernanceApplyError(f"{name}: branch policies are unavailable")

    observed_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for item in policies:
        require(isinstance(item, dict), f"{name}: invalid branch policy")
        policy_name = item.get("name")
        policy_type = item.get("type", "branch")
        if not isinstance(policy_name, str) or not policy_name:
            raise GovernanceApplyError(f"{name}: branch-policy name is invalid")
        require(isinstance(policy_type, str), f"{name}: branch-policy type is invalid")
        key = (policy_name, policy_type)
        require(key not in observed_by_key, f"{name}: duplicate branch policy {key}")
        observed_by_key[key] = item

    for key, item in observed_by_key.items():
        if key not in desired_keys:
            policy_id = item.get("id")
            require(isinstance(policy_id, int), f"{name}: branch-policy ID is invalid")
            api.request(
                "DELETE",
                f"{policies_path}/{policy_id}",
                expected=(204,),
            )

    for branch_name, policy_type in sorted(desired_keys):
        if (branch_name, policy_type) not in observed_by_key:
            api.request(
                "POST",
                policies_path,
                payload={"name": branch_name, "type": policy_type},
                expected=(200, 303),
            )


def apply_live(api: GitHubApi, policy: Mapping[str, Any]) -> None:
    apply_ruleset(api, policy)
    api.request(
        "PATCH",
        "",
        payload=repository_patch(policy),
        expected=(200,),
    )
    api.request(
        "PUT",
        "/topics",
        payload={"names": policy["repository_profile"]["topics"]},
        expected=(200,),
    )
    actions = policy["actions_policy"]
    api.request(
        "PUT",
        "/actions/permissions/workflow",
        payload={
            "default_workflow_permissions": actions["default_workflow_permissions"],
            "can_approve_pull_request_reviews": actions[
                "allow_actions_to_create_or_approve_pull_requests"
            ],
        },
        expected=(204,),
    )
    api.request("PUT", "/vulnerability-alerts", expected=(204,))
    api.request("PUT", "/automated-security-fixes", expected=(204,))
    api.request("PUT", "/private-vulnerability-reporting", expected=(204,))

    environments = policy["environments"]
    if not isinstance(environments, dict) or not environments:
        raise GovernanceApplyError("environments are missing")
    for name, encoded in sorted(environments.items()):
        if not isinstance(name, str) or not name:
            raise GovernanceApplyError("environment name is invalid")
        require(isinstance(encoded, dict), f"{name}: environment policy is invalid")
        apply_environment(api, name=name, encoded=encoded)


def _require_mapping(value: Any, message: str) -> Mapping[str, Any]:
    require(isinstance(value, dict), message)
    return value


def verify_ruleset(
    api: GitHubApi,
    policy: Mapping[str, Any],
) -> None:
    matches = _matching_rulesets(api)
    require(len(matches) == 1, f"expected one ruleset named {RULESET_NAME}")
    ruleset_id = matches[0].get("id")
    require(isinstance(ruleset_id, int), "ruleset ID is unavailable")
    ruleset = api.request(
        "GET",
        f"/rulesets/{ruleset_id}?includes_parents=false",
        expected=(200,),
    ).payload
    ruleset = _require_mapping(ruleset, "ruleset detail is invalid")
    expected = ruleset_payload(policy)

    require(ruleset.get("name") == expected["name"], "ruleset name drift")
    require(ruleset.get("target") == "branch", "ruleset target drift")
    require(ruleset.get("enforcement") == "active", "ruleset enforcement drift")
    require(ruleset.get("bypass_actors") == [], "ruleset permits bypass actors")
    conditions = _require_mapping(ruleset.get("conditions"), "ruleset conditions missing")
    ref_name = _require_mapping(conditions.get("ref_name"), "ruleset ref condition missing")
    require(
        set(ref_name.get("include", [])) == {"~DEFAULT_BRANCH"},
        "ruleset does not target only the default branch",
    )
    require(ref_name.get("exclude") == [], "ruleset excludes protected refs")

    observed_rules = _rules_by_type(ruleset)
    expected_rules = _rules_by_type(expected)
    require(
        set(observed_rules) == set(expected_rules),
        "ruleset rule-type drift",
    )
    for rule_type in ("pull_request", "required_status_checks"):
        observed_parameters = _require_mapping(
            observed_rules[rule_type].get("parameters"),
            f"{rule_type} parameters missing",
        )
        expected_parameters = _require_mapping(
            expected_rules[rule_type].get("parameters"),
            f"{rule_type} expected parameters missing",
        )
        if rule_type == "required_status_checks":
            observed_checks = observed_parameters.get("required_status_checks")
            expected_checks = expected_parameters.get("required_status_checks")
            if not isinstance(observed_checks, list):
                raise GovernanceApplyError("live status checks missing")
            if not isinstance(expected_checks, list):
                raise GovernanceApplyError("expected status checks missing")
            require(
                {
                    (item.get("context"), item.get("integration_id"))
                    for item in observed_checks
                    if isinstance(item, dict)
                }
                == {
                    (item.get("context"), item.get("integration_id"))
                    for item in expected_checks
                    if isinstance(item, dict)
                },
                "required status-check drift",
            )
            require(
                observed_parameters.get("strict_required_status_checks_policy")
                is expected_parameters.get("strict_required_status_checks_policy"),
                "strict status-check policy drift",
            )
        else:
            for key, value in expected_parameters.items():
                require(
                    observed_parameters.get(key) == value,
                    f"pull-request ruleset drift: {key}",
                )


def verify_environment(
    api: GitHubApi,
    *,
    name: str,
    encoded: Mapping[str, Any],
) -> None:
    encoded_name = urllib.parse.quote(name, safe="")
    environment = api.request(
        "GET",
        f"/environments/{encoded_name}",
        expected=(200,),
    ).payload
    environment = _require_mapping(environment, f"{name}: environment is invalid")
    expected = environment_payload(encoded)
    require(environment.get("name") == name, f"{name}: environment name drift")
    require(
        environment.get("protection_rules") is not None,
        f"{name}: environment protection rules unavailable",
    )
    branch_policy = _require_mapping(
        environment.get("deployment_branch_policy"),
        f"{name}: deployment branch policy missing",
    )
    expected_branch_policy = expected["deployment_branch_policy"]
    require(
        branch_policy.get("custom_branch_policies")
        is expected_branch_policy["custom_branch_policies"],
        f"{name}: custom branch-policy mode drift",
    )
    require(
        branch_policy.get("protected_branches")
        is expected_branch_policy["protected_branches"],
        f"{name}: protected-branch mode drift",
    )
    require(
        environment.get("can_admins_bypass") is expected["can_admins_bypass"],
        f"{name}: administrator-bypass policy drift",
    )

    protection_rules = environment.get("protection_rules")
    if not isinstance(protection_rules, list):
        raise GovernanceApplyError(f"{name}: protection rules invalid")
    wait_rules = [
        item
        for item in protection_rules
        if isinstance(item, dict) and item.get("type") == "wait_timer"
    ]
    if expected["wait_timer"]:
        require(
            len(wait_rules) == 1
            and wait_rules[0].get("wait_timer") == expected["wait_timer"],
            f"{name}: wait timer drift",
        )
    else:
        require(not wait_rules, f"{name}: unexpected wait timer")

    reviewer_rules = [
        item
        for item in protection_rules
        if isinstance(item, dict) and item.get("type") == "required_reviewers"
    ]
    expected_reviewers = {
        (item["type"], item["id"]) for item in expected["reviewers"]
    }
    if expected_reviewers:
        require(len(reviewer_rules) == 1, f"{name}: required reviewer rule missing")
        observed_reviewers = reviewer_rules[0].get("reviewers")
        if not isinstance(observed_reviewers, list):
            raise GovernanceApplyError(f"{name}: reviewers missing")
        normalized: set[tuple[str, int]] = set()
        for item in observed_reviewers:
            require(isinstance(item, dict), f"{name}: invalid reviewer")
            reviewer_type = item.get("type")
            reviewer = item.get("reviewer")
            reviewer = _require_mapping(reviewer, f"{name}: reviewer object missing")
            reviewer_id = reviewer.get("id")
            if (
                reviewer_type not in {"User", "Team"}
                or not isinstance(reviewer_id, int)
                or isinstance(reviewer_id, bool)
            ):
                raise GovernanceApplyError(f"{name}: reviewer identity invalid")
            if not isinstance(reviewer_type, str):
                raise GovernanceApplyError(f"{name}: reviewer type invalid")
            normalized.add((reviewer_type, reviewer_id))
        require(
            len(normalized) == len(observed_reviewers),
            f"{name}: duplicate live reviewer",
        )
        require(normalized == expected_reviewers, f"{name}: reviewer drift")
        require(
            reviewer_rules[0].get("prevent_self_review")
            is expected["prevent_self_review"],
            f"{name}: prevent-self-review drift",
        )
    else:
        require(not reviewer_rules, f"{name}: unexpected required reviewers")

    expected_keys = deployment_branch_policy_keys(encoded)
    if not expected_keys:
        return

    policies = api.request(
        "GET",
        f"/environments/{encoded_name}/deployment-branch-policies?per_page=100",
        expected=(200,),
    ).payload
    policies = _require_mapping(policies, f"{name}: branch-policy list invalid")
    branch_policies = policies.get("branch_policies")
    if not isinstance(branch_policies, list):
        raise GovernanceApplyError(f"{name}: branch policies missing")
    observed_keys = {
        (item.get("name"), item.get("type", "branch"))
        for item in branch_policies
        if isinstance(item, dict)
    }
    require(observed_keys == expected_keys, f"{name}: allowed branch-policy drift")


def verify_live(api: GitHubApi, policy: Mapping[str, Any]) -> None:
    repository = api.request("GET", "", expected=(200,)).payload
    repository = _require_mapping(repository, "repository metadata is invalid")
    require(repository.get("full_name") == policy["repository"], "repository identity drift")
    require(repository.get("default_branch") == "main", "default branch drift")

    patch = repository_patch(policy)
    for key, expected in patch.items():
        if key == "security_and_analysis":
            continue
        require(repository.get(key) == expected, f"repository setting drift: {key}")
    security = _require_mapping(
        repository.get("security_and_analysis"),
        "security_and_analysis is unavailable",
    )
    for feature in ("secret_scanning", "secret_scanning_push_protection"):
        feature_state = _require_mapping(
            security.get(feature),
            f"{feature} state is unavailable",
        )
        require(feature_state.get("status") == "enabled", f"{feature} is not enabled")

    topics = api.request("GET", "/topics", expected=(200,)).payload
    topics = _require_mapping(topics, "repository topics response is invalid")
    require(
        set(topics.get("names", []))
        == set(policy["repository_profile"]["topics"]),
        "repository topics drift",
    )

    actions = api.request(
        "GET",
        "/actions/permissions/workflow",
        expected=(200,),
    ).payload
    actions = _require_mapping(actions, "Actions workflow permissions are invalid")
    expected_actions = policy["actions_policy"]
    require(
        actions.get("default_workflow_permissions")
        == expected_actions["default_workflow_permissions"],
        "default workflow permission drift",
    )
    require(
        actions.get("can_approve_pull_request_reviews")
        is expected_actions["allow_actions_to_create_or_approve_pull_requests"],
        "Actions pull-request approval drift",
    )

    main = api.request("GET", "/branches/main", expected=(200,)).payload
    main = _require_mapping(main, "main branch metadata is invalid")
    require(main.get("protected") is True, "main is not protected")
    verify_ruleset(api, policy)

    api.request("GET", "/vulnerability-alerts", expected=(204,))
    verify_automated_security_fixes(api)
    private_reporting = api.request(
        "GET",
        "/private-vulnerability-reporting",
        expected=(200,),
    ).payload
    private_reporting = _require_mapping(
        private_reporting,
        "private vulnerability reporting state invalid",
    )
    require(
        private_reporting.get("enabled") is True,
        "private vulnerability reporting is disabled",
    )

    environments = policy["environments"]
    for name, encoded in sorted(environments.items()):
        verify_environment(api, name=name, encoded=encoded)


def print_plan(policy: Mapping[str, Any]) -> None:
    profile = policy["repository_profile"]
    checks = policy["default_branch_ruleset"]["required_status_checks"]
    environments = ", ".join(sorted(policy["environments"]))
    print(
        "REPOSITORY_GOVERNANCE_APPLIER=PLAN "
        f"repository={policy['repository']} "
        f"topics={len(profile['topics'])} "
        f"required_checks={len(checks)} "
        f"environments={environments} "
        "live_effects=UNCHANGED"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="apply and verify live settings")
    mode.add_argument("--verify-live", action="store_true", help="verify without mutation")
    args = parser.parse_args(argv)

    try:
        policy = load_policy()
        if not args.apply and not args.verify_live:
            print_plan(policy)
            return 0

        token = os.environ.get(TOKEN_ENV, "")
        api = GitHubApi(repository=policy["repository"], token=token)
        if args.apply:
            apply_live(api, policy)
        verify_live(api, policy)
    except GovernanceApplyError as exc:
        print(f"REPOSITORY_GOVERNANCE_APPLIER=FAIL reason={exc}", file=sys.stderr)
        return 1

    print(
        "REPOSITORY_GOVERNANCE_APPLIER=PASS "
        f"mode={'APPLY' if args.apply else 'VERIFY'} "
        "main_protected=YES live_effects=UNCHANGED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
