from __future__ import annotations

from typing import TYPE_CHECKING

import copy
import importlib.util
import os
import sys
import tempfile
import types
import unittest
import urllib.request
from unittest import mock
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_portfolio_main_release_authorities.py"
sys.path.insert(0, str(ROOT / "scripts"))
if TYPE_CHECKING:
    from scripts.portfolio_ruleset import github_api  # noqa: E402
else:
    from portfolio_ruleset import github_api  # noqa: E402

SPEC = importlib.util.spec_from_file_location("portfolio_main_release_authorities", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PortfolioMainReleaseAuthoritiesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = MODULE.load_config()

    def test_committed_authority_is_exact(self) -> None:
        records = MODULE.validate_config(self.config)
        self.assertEqual(
            {record["repository"] for record in records},
            set(MODULE.EXPECTED_REPOSITORIES),
        )

    def test_every_ruleset_is_fail_closed(self) -> None:
        records = MODULE.validate_config(self.config)
        for record in records:
            value = MODULE.normalize_ruleset(MODULE.desired_ruleset(self.config, record))
            self.assertEqual(value["bypass_actors"], [])
            self.assertEqual(
                value["conditions"],
                {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            )
            rules = value["rules"]
            self.assertTrue(rules["deletion"])
            self.assertTrue(rules["non_fast_forward"])
            self.assertTrue(rules["required_linear_history"])
            self.assertEqual(
                rules["pull_request"],
                {
                    "allowed_merge_methods": ["squash"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_extra_approval_for_unattributed_changes": None,
                    "require_last_push_approval": True,
                    "required_approving_review_count": 1,
                    "required_review_thread_resolution": True,
                    "additional_parameters": {},
                },
            )
            self.assertEqual(
                rules["required_status_checks"]["contexts"],
                sorted(record["required_status_checks"]),
            )
            self.assertTrue(
                rules["required_status_checks"]["strict_required_status_checks_policy"]
            )

    def test_validate_mode_never_requires_a_token_or_mutates_github(self) -> None:
        result = MODULE.execute("validate", "")
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(len(result["repositories"]), 6)
        self.assertTrue(
            all(row["action"] == "policy-validated" for row in result["repositories"])
        )

    def test_zero_approval_policy_is_rejected(self) -> None:
        value = copy.deepcopy(self.config)
        value["required_approvals"] = 0
        with self.assertRaises(MODULE.PolicyError):
            MODULE.validate_config(value)

    def test_boolean_approval_count_is_rejected(self) -> None:
        value = copy.deepcopy(self.config)
        value["required_approvals"] = True
        with self.assertRaisesRegex(MODULE.PolicyError, "exactly one approval"):
            MODULE.validate_config(value)

    def test_reviewer_authority_drift_is_rejected(self) -> None:
        value = copy.deepcopy(self.config)
        value["reviewer"]["login"] = "unapproved-reviewer"
        with self.assertRaisesRegex(MODULE.PolicyError, "reviewer authority drift"):
            MODULE.validate_config(value)

    def test_unknown_authority_field_is_rejected(self) -> None:
        value = copy.deepcopy(self.config)
        value["approval_alias"] = 1
        with self.assertRaisesRegex(MODULE.PolicyError, "field inventory drift"):
            MODULE.validate_config(value)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.json"
            path.write_text(
                '{"schema_version":"1.0","schema_version":"2.0"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.PolicyError, "duplicate key"):
                MODULE.load_config(path)

    def test_repository_or_check_drift_is_rejected(self) -> None:
        value = copy.deepcopy(self.config)
        value["repositories"][0]["required_status_checks"] = ["made-up-check"]
        with self.assertRaises(MODULE.PolicyError):
            MODULE.validate_config(value)

    def test_apply_requires_exact_confirmation_before_api_use(self) -> None:
        with self.assertRaises(MODULE.PolicyError):
            MODULE.execute("apply", "WRONG")

    def test_repository_admin_api_redirects_are_rejected(self) -> None:
        handler = github_api.FailClosedRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                urllib.request.Request(
                    "https://api.github.com/user",
                    headers={"Authorization": "Bearer protected-placeholder"},
                ),
                None,
                302,
                "Found",
                {},
                "https://attacker.invalid/capture",
            )
        )

    def stronger_live_ruleset(self, record: dict[str, Any]) -> dict[str, Any]:
        existing = copy.deepcopy(MODULE.desired_ruleset(self.config, record))
        existing["conditions"]["ref_name"]["include"].append(
            "refs/heads/release/*"
        )
        pull = next(
            rule for rule in existing["rules"] if rule["type"] == "pull_request"
        )
        pull["parameters"]["require_code_owner_review"] = True
        pull["parameters"]["require_extra_approval_for_unattributed_changes"] = True
        pull["parameters"]["required_approving_review_count"] = 2
        pull["parameters"]["future_review_control"] = "strict"
        status = next(
            rule
            for rule in existing["rules"]
            if rule["type"] == "required_status_checks"
        )
        status["parameters"]["future_status_control"] = "strict"
        status["parameters"]["required_status_checks"][0]["integration_id"] = 12345
        status["parameters"]["required_status_checks"][0]["provider_slug"] = (
            "github-actions"
        )
        status["parameters"]["required_status_checks"].append(
            {"context": "existing-security-gate", "integration_id": 67890}
        )
        existing["rules"].append({"type": "required_signatures"})
        return existing

    def test_merge_preserves_stronger_controls_and_provider_bindings(self) -> None:
        record = MODULE.validate_config(self.config)[0]
        baseline = MODULE.desired_ruleset(self.config, record)
        existing = self.stronger_live_ruleset(record)

        merged = MODULE.merge_ruleset_preserving_stronger_controls(
            existing, baseline
        )
        normalized = MODULE.normalize_ruleset(merged)
        pull = normalized["rules"]["pull_request"]
        self.assertTrue(pull["require_code_owner_review"])
        self.assertTrue(pull["require_extra_approval_for_unattributed_changes"])
        self.assertEqual(pull["required_approving_review_count"], 2)
        self.assertEqual(
            pull["additional_parameters"]["future_review_control"], "strict"
        )
        status = normalized["rules"]["required_status_checks"]
        checks = {row["context"]: row for row in status["checks"]}
        first_context = record["required_status_checks"][0]
        self.assertEqual(checks[first_context]["integration_id"], 12345)
        self.assertEqual(checks[first_context]["provider_slug"], "github-actions")
        self.assertIn("existing-security-gate", checks)
        self.assertEqual(
            status["additional_parameters"]["future_status_control"], "strict"
        )
        self.assertIn("required_signatures", normalized["additional_rules"])
        self.assertTrue(MODULE.ruleset_meets_baseline(existing, baseline))

    def test_malformed_live_status_binding_fails_closed(self) -> None:
        record = MODULE.validate_config(self.config)[0]
        baseline = MODULE.desired_ruleset(self.config, record)
        existing = self.stronger_live_ruleset(record)
        status = next(
            rule
            for rule in existing["rules"]
            if rule["type"] == "required_status_checks"
        )
        status["parameters"]["required_status_checks"][0]["integration_id"] = True
        with self.assertRaisesRegex(MODULE.PolicyError, "integration ID"):
            MODULE.merge_ruleset_preserving_stronger_controls(existing, baseline)

    def test_integer_boolean_rule_flag_fails_closed(self) -> None:
        record = MODULE.validate_config(self.config)[0]
        baseline = MODULE.desired_ruleset(self.config, record)
        existing = self.stronger_live_ruleset(record)
        pull = next(
            rule for rule in existing["rules"] if rule["type"] == "pull_request"
        )
        pull["parameters"]["require_code_owner_review"] = 1
        with self.assertRaisesRegex(MODULE.PolicyError, "must be boolean"):
            MODULE.merge_ruleset_preserving_stronger_controls(existing, baseline)

    def test_integer_boolean_status_flag_fails_closed(self) -> None:
        record = MODULE.validate_config(self.config)[0]
        baseline = MODULE.desired_ruleset(self.config, record)
        existing = self.stronger_live_ruleset(record)
        status = next(
            rule
            for rule in existing["rules"]
            if rule["type"] == "required_status_checks"
        )
        status["parameters"]["do_not_enforce_on_create"] = 0
        with self.assertRaisesRegex(MODULE.PolicyError, "must be boolean"):
            MODULE.merge_ruleset_preserving_stronger_controls(existing, baseline)

    def test_malformed_provider_slug_fails_closed(self) -> None:
        record = MODULE.validate_config(self.config)[0]
        baseline = MODULE.desired_ruleset(self.config, record)
        existing = self.stronger_live_ruleset(record)
        status = next(
            rule
            for rule in existing["rules"]
            if rule["type"] == "required_status_checks"
        )
        status["parameters"]["required_status_checks"][0]["provider_slug"] = {}
        with self.assertRaisesRegex(MODULE.PolicyError, "provider slug"):
            MODULE.merge_ruleset_preserving_stronger_controls(existing, baseline)

    def test_missing_baseline_rule_is_repaired_without_losing_extra_rules(self) -> None:
        record = MODULE.validate_config(self.config)[0]
        baseline = MODULE.desired_ruleset(self.config, record)
        existing = self.stronger_live_ruleset(record)
        existing["rules"] = [
            rule
            for rule in existing["rules"]
            if rule["type"] != "required_status_checks"
        ]

        self.assertFalse(MODULE.ruleset_meets_baseline(existing, baseline))
        merged = MODULE.merge_ruleset_preserving_stronger_controls(existing, baseline)
        normalized = MODULE.normalize_ruleset(merged)
        self.assertIn("required_status_checks", normalized["rules"])
        self.assertIn("required_signatures", normalized["additional_rules"])

    def test_malformed_allowed_merge_methods_fails_as_policy_error(self) -> None:
        record = MODULE.validate_config(self.config)[0]
        ruleset = MODULE.desired_ruleset(self.config, record)
        pull = next(
            rule for rule in ruleset["rules"] if rule["type"] == "pull_request"
        )
        pull["parameters"]["allowed_merge_methods"] = {}
        with self.assertRaisesRegex(MODULE.PolicyError, "allowed merge methods"):
            MODULE.normalize_ruleset(ruleset)

    def test_apply_is_noop_when_stronger_rulesets_already_satisfy_policy(self) -> None:
        records = MODULE.validate_config(self.config)
        rulesets = {
            str(record["repository"]): self.stronger_live_ruleset(record)
            for record in records
        }
        repository_ids = {
            str(record["repository"]): record["repository_id"] for record in records
        }

        class FakeApi:
            writes = 0

            def __init__(self, token: str) -> None:
                self.token = token

            def request(self, method: str, path: str) -> object:
                self.assert_read(method)
                name = path.removeprefix("/repos/")
                return types.SimpleNamespace(
                    payload={
                        "id": repository_ids[name],
                        "default_branch": "main",
                        "archived": False,
                        "disabled": False,
                        "permissions": {"admin": True},
                    }
                )

            @staticmethod
            def assert_read(method: str) -> None:
                if method != "GET":
                    raise AssertionError(f"unexpected mutation: {method}")

            def list_rulesets(self, full_name: str) -> list[dict[str, Any]]:
                return [{"id": repository_ids[full_name], "name": MODULE.RULESET_NAME}]

            def get_ruleset(
                self, full_name: str, ruleset_id: int
            ) -> dict[str, Any]:
                self.assertEqualId(full_name, ruleset_id)
                return copy.deepcopy(rulesets[full_name])

            @staticmethod
            def assertEqualId(full_name: str, ruleset_id: int) -> None:
                if repository_ids[full_name] != ruleset_id:
                    raise AssertionError("unexpected ruleset ID")

            def upsert_ruleset(self, *_args: object, **_kwargs: object) -> object:
                type(self).writes += 1
                raise AssertionError("compliant ruleset must not be rewritten")

        with (
            mock.patch.object(MODULE, "GitHubApi", FakeApi),
            mock.patch.dict(
                os.environ,
                {MODULE.TOKEN_ENV: "test-only-placeholder"},
                clear=False,
            ),
        ):
            result = MODULE.execute("apply", MODULE.CONFIRMATION)

        self.assertEqual(FakeApi.writes, 0)
        self.assertTrue(
            all(row["action"] == "already-compliant" for row in result["repositories"])
        )


if __name__ == "__main__":
    unittest.main()
