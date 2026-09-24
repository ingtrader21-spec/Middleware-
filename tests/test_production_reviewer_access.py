from __future__ import annotations

import copy
import importlib.util
import json
import unittest
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_production_reviewer_access.py"
CONFIG = ROOT / "config" / "production-reviewer-access.v1.json"
WORKFLOW = ROOT / ".github" / "workflows" / "production-reviewer-access.yml"

spec = importlib.util.spec_from_file_location(
    "production_reviewer_access",
    SCRIPT,
)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


class ProductionReviewerAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config: dict[str, Any] = json.loads(
            CONFIG.read_text(encoding="utf-8")
        )

    def test_exact_fixed_repository_set_and_ids_validate(self) -> None:
        repositories = MODULE.validate_config(self.config)
        self.assertEqual(set(repositories), set(MODULE.EXPECTED_REPOSITORIES))
        self.assertEqual(len(repositories), 19)
        self.assertEqual(
            {
                row["repository"]: row["repository_id"]
                for row in self.config["repositories"]
            },
            MODULE.EXPECTED_REPOSITORIES,
        )
        self.assertEqual(self.config["reviewer"], MODULE.EXPECTED_REVIEWER)

    def test_every_repository_is_owner_scoped(self) -> None:
        transferred = {"ingtrader21-spec/Middleware-": "ingtrader21-spec"}
        self.assertEqual(MODULE.BASE.TRANSFERRED_REPOSITORY_OWNERS, transferred)
        for repository in MODULE.validate_config(self.config):
            owner = transferred.get(repository, "appolon1908-hue")
            self.assertTrue(repository.startswith(f"{owner}/"))
        self.assertEqual(
            MODULE.EXPECTED_REPOSITORIES["ingtrader21-spec/Middleware-"], 1347559071
        )

    def test_transferred_repository_under_any_other_owner_fails(self) -> None:
        broken = copy.deepcopy(self.config)
        for row in broken["repositories"]:
            if row["repository"] == "ingtrader21-spec/Middleware-":
                row["repository"] = "appolon1908-hue/Middleware-"
        with self.assertRaises(MODULE.AccessError):
            MODULE.validate_config(broken)

    def test_foreign_or_unknown_repository_fails(self) -> None:
        broken = copy.deepcopy(self.config)
        broken["repositories"][0]["repository"] = (
            "another-owner/not-authorized"
        )
        with self.assertRaises(MODULE.AccessError):
            MODULE.validate_config(broken)

    def test_stable_repository_id_drift_fails(self) -> None:
        broken = copy.deepcopy(self.config)
        broken["repositories"][0]["repository_id"] += 1
        with self.assertRaises(MODULE.AccessError):
            MODULE.validate_config(broken)

    def test_duplicate_repository_or_id_fails(self) -> None:
        duplicate_name = copy.deepcopy(self.config)
        duplicate_name["repositories"][-1] = copy.deepcopy(
            duplicate_name["repositories"][0]
        )
        with self.assertRaises(MODULE.AccessError):
            MODULE.validate_config(duplicate_name)

        duplicate_id = copy.deepcopy(self.config)
        duplicate_id["repositories"][-1]["repository_id"] = (
            duplicate_id["repositories"][0]["repository_id"]
        )
        with self.assertRaises(MODULE.AccessError):
            MODULE.validate_config(duplicate_id)

    def test_admin_reviewer_policy_fails(self) -> None:
        broken = copy.deepcopy(self.config)
        broken["reviewer"]["admin"] = True
        with self.assertRaises(MODULE.AccessError):
            MODULE.validate_config(broken)

    def test_validate_mode_is_offline_and_non_mutating(self) -> None:
        document = MODULE.execute("validate", "")
        self.assertEqual(document["result"], "PASS")
        self.assertEqual(len(document["repositories"]), 19)
        self.assertFalse(document["runtime_contacted"])
        self.assertFalse(document["production_changed"])
        self.assertFalse(document["external_effects_enabled"])

    def test_permission_helper_accepts_only_exact_write(self) -> None:
        self.assertTrue(
            MODULE.permission_is_write({"permission": "write"})
        )
        self.assertFalse(
            MODULE.permission_is_write({"permission": "push"})
        )
        self.assertFalse(
            MODULE.permission_is_write({"permission": "maintain"})
        )
        self.assertFalse(
            MODULE.permission_is_write({"permission": "admin"})
        )
        self.assertFalse(
            MODULE.permission_is_write({"permission": "read"})
        )
        self.assertFalse(MODULE.permission_is_write(None))

    def test_admin_api_redirects_are_rejected(self) -> None:
        handler = MODULE.FailClosedRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                urllib.request.Request(
                    "https://api.github.com/user",
                    headers={"Authorization": "Bearer protected"},
                ),
                None,
                302,
                "Found",
                {},
                "https://attacker.example/capture",
            )
        )

    def test_workflow_apply_is_issue_command_only_and_policy_is_read_only(
        self,
    ) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        header, jobs = text.split("\njobs:\n", 1)
        self.assertNotIn("issues: write", header)
        _, apply = jobs.split("\n  apply:\n", 1)
        apply_condition = apply.split("\n    permissions:\n", 1)[0]
        self.assertIn("CONTROL_PLANE_MUTATION=repository-administration", apply_condition)
        self.assertIn("github.event_name == 'issue_comment'", apply_condition)
        self.assertIn("github.event.repository.id == 1347559071", apply_condition)
        self.assertIn("github.event.sender.id == 275410064", apply_condition)
        self.assertIn("github.event.comment.user.id == 275410064", apply_condition)
        self.assertIn("/apply-production-reviewer-access v1", apply_condition)
        self.assertNotIn("github.event_name == 'push'", apply_condition)
        self.assertNotIn("if: ${{ false }}", apply_condition)
        self.assertIn("issues: write", apply)
        self.assertIn(
            "python3 -I scripts/apply_production_reviewer_access.py",
            text,
        )


if __name__ == "__main__":
    unittest.main()
