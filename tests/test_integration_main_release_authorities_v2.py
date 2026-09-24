from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_integration_main_release_authorities_v2.py"
CONFIG = ROOT / "config" / "integration-main-release-authorities.v1.json"
WORKFLOW = ROOT / ".github" / "workflows" / "integration-main-release-authorities.yml"

spec = importlib.util.spec_from_file_location("integration_authority_v2", SCRIPT)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
MODULE.configure_base()


class IntegrationMainReleaseAuthorityV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.config: dict[str, Any] = json.loads(CONFIG.read_text(encoding="utf-8"))

    def exact_event(self) -> dict[str, Any]:
        return {
            "action": "created",
            "repository": {
                "id": MODULE.EXPECTED_REPOSITORY_ID,
                "full_name": MODULE.EXPECTED_REPOSITORY,
                "default_branch": "main",
                "owner": {"login": MODULE.EXPECTED_OWNER, "id": MODULE.EXPECTED_OWNER_ID},
            },
            "issue": {"number": MODULE.EXPECTED_ISSUE_NUMBER},
            "sender": {"login": MODULE.EXPECTED_OWNER, "id": MODULE.EXPECTED_OWNER_ID},
            "comment": {
                "body": MODULE.EXPECTED_ISSUE_COMMAND,
                "user": {"login": MODULE.EXPECTED_OWNER, "id": MODULE.EXPECTED_OWNER_ID},
            },
        }

    def test_exact_seven_repository_set_validates(self) -> None:
        rows = MODULE.BASE.validate_config(self.config)
        self.assertEqual(len(rows), 7)
        self.assertEqual({row["repository"] for row in rows}, set(MODULE.EXPECTED_REPOSITORIES))

    def test_new_governance_gap_repositories_are_exact(self) -> None:
        expected = {
            "appolon1908-hue/N8N",
            "appolon1908-hue/klyrow.com",
            "appolon1908-hue/Codestra-Prometheus",
        }
        observed = {row["repository"] for row in MODULE.BASE.validate_config(self.config)}
        self.assertTrue(expected.issubset(observed))

    def test_exact_issue_command_event_validates(self) -> None:
        MODULE.validate_issue_comment_event(self.exact_event())

    def test_fixed_cli_validates_runner_event_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(self.exact_event()), encoding="utf-8")
            with mock.patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(path)}):
                self.assertEqual(MODULE.main(["--validate-issue-comment-event"]), 0)

    def test_fixed_cli_rejects_duplicate_event_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text('{"action":"created","action":"edited"}', encoding="utf-8")
            with mock.patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(path)}):
                with self.assertRaises(MODULE.BASE.PolicyError):
                    MODULE.main(["--validate-issue-comment-event"])

    def test_issue_command_drift_fails(self) -> None:
        event = self.exact_event()
        event["comment"]["body"] = "/apply-integration-main-release-authority v2"
        with self.assertRaises(MODULE.BASE.PolicyError):
            MODULE.validate_issue_comment_event(event)

    def test_wrong_issue_fails(self) -> None:
        event = self.exact_event()
        event["issue"]["number"] = 129
        with self.assertRaises(MODULE.BASE.PolicyError):
            MODULE.validate_issue_comment_event(event)

    def test_pull_request_comment_fails(self) -> None:
        event = self.exact_event()
        event["issue"]["pull_request"] = {"url": "https://api.github.com/fake"}
        with self.assertRaises(MODULE.BASE.PolicyError):
            MODULE.validate_issue_comment_event(event)

    def test_actor_id_drift_fails(self) -> None:
        event = self.exact_event()
        event["sender"]["id"] = 1
        with self.assertRaises(MODULE.BASE.PolicyError):
            MODULE.validate_issue_comment_event(event)

    def test_workflow_keeps_exact_bounded_command(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        apply = text.split("\n  apply:\n", 1)[1]
        condition = apply.split("\n    permissions:\n", 1)[0]
        self.assertIn("issue_comment:", text)
        self.assertIn("github.event.issue.number == 130", text)
        self.assertIn("github.event.issue.pull_request == null", text)
        self.assertIn(MODULE.EXPECTED_ISSUE_COMMAND, text)
        self.assertIn("repository-administration", text)
        self.assertIn("CODESTRA_REPOSITORY_ADMIN_TOKEN", text)
        self.assertIn("git ls-remote origin refs/heads/main", text)
        self.assertIn("CONTROL_PLANE_MUTATION=repository-administration", condition)
        self.assertIn("github.event_name == 'issue_comment'", condition)
        self.assertIn("github.event.repository.id == 1347559071", condition)
        self.assertIn("github.event.sender.id == 275410064", condition)
        self.assertIn("github.event.comment.user.id == 275410064", condition)
        self.assertIn("github.event.comment.body == '/apply-integration-main-release-authority v1'", condition)
        self.assertNotIn("github.event_name == 'workflow_dispatch'", condition)
        self.assertNotIn("if: ${{ false }}", condition)
        self.assertNotIn("options: [validate, apply, verify]", text)
        self.assertNotIn("REQUESTED_MODE", text)
        self.assertIn(
            "python3 -I scripts/apply_integration_main_release_authorities_v2.py",
            text,
        )
        self.assertIn("--validate-issue-comment-event", text)
        self.assertIn("--mode apply", apply)
        self.assertIn("--confirm APPLY_INTEGRATION_MAIN_RELEASE_AUTHORITY_V1", apply)
        self.assertNotIn('"${args[@]}"', apply)
        self.assertNotIn("repository_input", text)
        self.assertNotIn("reviewer_input", text)

    def test_validate_mode_remains_offline(self) -> None:
        document = MODULE.BASE.execute("validate", "")
        self.assertEqual(document["result"], "PASS")
        self.assertEqual(len(document["repositories"]), 7)
        self.assertFalse(document["production_changed"])
        self.assertFalse(document["runtime_contacted"])
        self.assertFalse(document["external_effects_enabled"])

    def test_repository_id_drift_still_fails(self) -> None:
        broken = copy.deepcopy(self.config)
        broken["repositories"][0]["repository_id"] += 1
        with self.assertRaises(MODULE.BASE.PolicyError):
            MODULE.BASE.validate_config(broken)


if __name__ == "__main__":
    unittest.main()
