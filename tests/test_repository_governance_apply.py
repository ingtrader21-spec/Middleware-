from __future__ import annotations

import copy
from unittest.mock import Mock

import pytest

from scripts.apply_repository_governance import (
    ApiResponse,
    GovernanceApplyError,
    GitHubApi,
    environment_payload,
    repository_patch,
    ruleset_payload,
    verify_automated_security_fixes,
)
from scripts.validate_repository_governance import (
    GovernanceError,
    validate_environment_release_policy,
    validate_live_ruleset,
)


@pytest.fixture()
def policy() -> dict:
    return {
        "repository_profile": {
            "description": "Codestra durable integration and automation control plane",
            "topics": [
                "middleware",
                "fastapi",
                "postgresql",
                "keycloak",
                "kong",
                "n8n",
                "integration-platform",
                "outbox",
                "idempotency",
                "gitops",
            ],
            "has_issues": True,
            "has_wiki": False,
        },
        "merge_policy": {
            "allow_squash_merge": True,
            "allow_merge_commit": False,
            "allow_rebase_merge": False,
            "allow_auto_merge": True,
            "allow_update_branch": True,
            "delete_branch_on_merge": True,
            "web_commit_signoff_required": True,
        },
        "default_branch_ruleset": {
            "enforcement": "active",
            "required_approvals": 1,
            "require_code_owner_review": True,
            "dismiss_stale_reviews": True,
            "require_review_thread_resolution": True,
            "require_branch_up_to_date": True,
            "required_status_checks": [
                "validate",
                "Validate middleware source head",
                "Validate middleware merge result",
                "docker-runtime-build",
                "docker-test-build",
                "connector-runtime-build",
                "container-security",
                "Disposable PostgreSQL Redis integration",
                "Disposable NATS JetStream integration",
                "Temporal critical workflow integration",
                "Synthetic no-effect acceptance E2E",
            ],
        },
    }


def test_repository_patch_is_squash_only_and_secret_scanning_enabled(policy: dict) -> None:
    patch = repository_patch(policy)

    assert patch["allow_squash_merge"] is True
    assert patch["allow_merge_commit"] is False
    assert patch["allow_rebase_merge"] is False
    assert patch["allow_auto_merge"] is True
    assert patch["delete_branch_on_merge"] is True
    assert patch["web_commit_signoff_required"] is True
    assert patch["security_and_analysis"] == {
        "secret_scanning": {"status": "enabled"},
        "secret_scanning_push_protection": {"status": "enabled"},
    }


def test_dependabot_security_update_verifier_accepts_enabled_unpaused_state() -> None:
    api = Mock(spec=GitHubApi)
    api.request.return_value = ApiResponse(status=200, payload={"enabled": True, "paused": False})

    verify_automated_security_fixes(api)

    api.request.assert_called_once_with(
        "GET",
        "/automated-security-fixes",
        expected=(200,),
    )


@pytest.mark.parametrize("payload", [
    None, [], {}, {"enabled": True}, {"paused": False},
    {"enabled": False, "paused": False},
    {"enabled": True, "paused": True},
    {"enabled": 1, "paused": False},
    {"enabled": True, "paused": 0},
    {"enabled": "true", "paused": "false"},
])
def test_dependabot_security_update_verifier_rejects_inactive_or_invalid_state(payload) -> None:
    api = Mock(spec=GitHubApi)
    api.request.return_value = ApiResponse(status=200, payload=payload)

    with pytest.raises(GovernanceApplyError):
        verify_automated_security_fixes(api)


def test_ruleset_has_no_bypass_and_exact_required_checks(policy: dict) -> None:
    payload = ruleset_payload(policy)
    rules = {item["type"]: item for item in payload["rules"]}

    assert payload["enforcement"] == "active"
    assert payload["bypass_actors"] == []
    assert payload["conditions"] == {
        "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
    }
    assert set(rules) == {
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
        "required_status_checks",
    }
    pull_request = rules["pull_request"]["parameters"]
    assert pull_request["allowed_merge_methods"] == ["squash"]
    assert pull_request["required_approving_review_count"] == 1
    assert pull_request["require_code_owner_review"] is True
    assert (
        pull_request["require_extra_approval_for_unattributed_changes"] is False
    )
    assert pull_request["required_review_thread_resolution"] is True
    status = rules["required_status_checks"]["parameters"]
    assert status["strict_required_status_checks_policy"] is True
    assert [item["context"] for item in status["required_status_checks"]] == policy[
        "default_branch_ruleset"
    ]["required_status_checks"]
    assert {
        item["integration_id"] for item in status["required_status_checks"]
    } == {15368}


def test_ruleset_rejects_duplicate_status_checks(policy: dict) -> None:
    broken = copy.deepcopy(policy)
    broken["default_branch_ruleset"]["required_status_checks"].append(
        "Validate middleware source head"
    )

    with pytest.raises(GovernanceApplyError, match="duplicates"):
        ruleset_payload(broken)


def test_live_ruleset_requires_github_actions_app_binding(policy: dict) -> None:
    payload = ruleset_payload(policy)
    live = {
        **payload,
        "source_type": "Repository",
        "source": "ingtrader21-spec/Middleware-",
    }
    validate_live_ruleset(live, policy["default_branch_ruleset"])

    checks = next(
        item for item in live["rules"] if item["type"] == "required_status_checks"
    )["parameters"]["required_status_checks"]
    checks[0]["integration_id"] = 1
    with pytest.raises(GovernanceError, match="app binding drift"):
        validate_live_ruleset(live, policy["default_branch_ruleset"])


def test_live_ruleset_requires_code_owner_review(policy: dict) -> None:
    payload = ruleset_payload(policy)
    live = {
        **payload,
        "source_type": "Repository",
        "source": "ingtrader21-spec/Middleware-",
    }
    pull_request = next(
        item for item in live["rules"] if item["type"] == "pull_request"
    )
    pull_request["parameters"]["require_code_owner_review"] = False

    with pytest.raises(GovernanceError, match="code-owner review requirement drift"):
        validate_live_ruleset(live, policy["default_branch_ruleset"])


def test_protected_environment_requires_independent_review() -> None:
    payload = environment_payload(
        {
            "wait_timer": 0,
            "prevent_self_review": True,
            "can_admins_bypass": False,
            "reviewers": [{"type": "User", "id": 77101516}],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
            "allowed_branches": [],
        }
    )

    assert payload["prevent_self_review"] is True
    assert payload["can_admins_bypass"] is False
    assert payload["reviewers"] == [{"type": "User", "id": 77101516}]
    assert payload["deployment_branch_policy"] == {
        "protected_branches": True,
        "custom_branch_policies": False,
    }


def test_custom_branch_environment_remains_supported() -> None:
    payload = environment_payload(
        {
            "wait_timer": 0,
            "prevent_self_review": False,
            "can_admins_bypass": False,
            "reviewers": [],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
            "allowed_branches": [{"name": "main", "type": "branch"}],
        }
    )

    assert payload["reviewers"] == []
    assert payload["deployment_branch_policy"]["custom_branch_policies"] is True


@pytest.mark.parametrize(
    ("protected_branches", "custom_branch_policies"),
    [(True, True), (False, False)],
)
def test_environment_rejects_ambiguous_branch_policy_modes(
    protected_branches: bool,
    custom_branch_policies: bool,
) -> None:
    with pytest.raises(
        GovernanceApplyError,
        match="exactly one deployment branch-policy mode",
    ):
        environment_payload(
            {
                "wait_timer": 0,
                "prevent_self_review": False,
                "can_admins_bypass": False,
                "reviewers": [],
                "deployment_branch_policy": {
                    "protected_branches": protected_branches,
                    "custom_branch_policies": custom_branch_policies,
                },
                "allowed_branches": [],
            }
        )


def test_environment_rejects_duplicate_reviewers() -> None:
    reviewer = {"type": "User", "id": 77101516}
    with pytest.raises(GovernanceApplyError, match="duplicate environment reviewer"):
        environment_payload(
            {
                "wait_timer": 0,
                "prevent_self_review": True,
                "can_admins_bypass": False,
                "reviewers": [reviewer, reviewer],
                "deployment_branch_policy": {
                    "protected_branches": True,
                    "custom_branch_policies": False,
                },
                "allowed_branches": [],
            }
        )


def independent_environment_policy() -> dict:
    environment = {
        "wait_timer": 0,
        "prevent_self_review": True,
        "can_admins_bypass": False,
        "reviewers": [{"type": "User", "id": 77101516}],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
        "allowed_branches": [],
        "live_write_secrets_allowed": False,
    }
    return {
        "environments": {
            "staging": copy.deepcopy(environment),
            "production": copy.deepcopy(environment),
        },
        "release_policy": {
            "live_writes_default": False,
            "odoo_write_default": False,
            "live_apply_authorized_default": False,
            "production_release_requires_independent_human_approval": True,
            "production_release_environment": "production",
        },
    }


def test_source_policy_requires_independent_environment_approval() -> None:
    encoded = independent_environment_policy()
    validate_environment_release_policy(encoded)

    encoded["environments"]["production"]["prevent_self_review"] = False
    with pytest.raises(GovernanceError, match="self-review"):
        validate_environment_release_policy(encoded)


def test_source_policy_rejects_boolean_wait_timer() -> None:
    encoded = independent_environment_policy()
    encoded["environments"]["production"]["wait_timer"] = False

    with pytest.raises(GovernanceError, match="wait timer drift"):
        validate_environment_release_policy(encoded)


def test_source_policy_rejects_admin_bypass_and_custom_production_refs() -> None:
    encoded = independent_environment_policy()
    encoded["environments"]["production"]["can_admins_bypass"] = True
    with pytest.raises(GovernanceError, match="administrator bypass"):
        validate_environment_release_policy(encoded)

    encoded = independent_environment_policy()
    encoded["environments"]["production"]["deployment_branch_policy"] = {
        "protected_branches": False,
        "custom_branch_policies": True,
    }
    with pytest.raises(GovernanceError, match="protected branches"):
        validate_environment_release_policy(encoded)


def test_environment_rejects_invalid_reviewer() -> None:
    with pytest.raises(GovernanceApplyError, match="reviewer ID"):
        environment_payload(
            {
                "wait_timer": 0,
                "prevent_self_review": True,
                "can_admins_bypass": False,
                "reviewers": [{"type": "User", "id": 0}],
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
                "allowed_branches": [{"name": "main", "type": "branch"}],
            }
        )
