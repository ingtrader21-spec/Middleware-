from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply_portfolio_release_reviewer_access.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("portfolio_release_reviewer_access", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PortfolioReleaseReviewerAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = MODULE.load_config()

    def test_committed_reviewer_and_repository_set_are_exact(self) -> None:
        repositories = MODULE.validate_config(self.config)
        self.assertEqual(self.config["reviewer"], MODULE.EXPECTED_REVIEWER)
        self.assertEqual(
            {row["repository"] for row in repositories},
            set(MODULE.EXPECTED_REPOSITORIES),
        )

    def test_validate_mode_is_offline_and_non_mutating(self) -> None:
        result = MODULE.execute("validate", "")
        self.assertEqual(result["result"], "PASS")
        self.assertFalse(result["runtime_contacted"])
        self.assertFalse(result["production_changed"])
        self.assertEqual(result["reviewer"], "kazan555")
        self.assertEqual(len(result["repositories"]), 6)
        self.assertTrue(
            all(row["action"] == "policy-validated" for row in result["repositories"])
        )

    def test_reviewer_login_or_id_drift_is_rejected(self) -> None:
        for key, value in (("login", "other-user"), ("user_id", 1), ("permission", "admin")):
            config = copy.deepcopy(self.config)
            config["reviewer"][key] = value
            with self.assertRaises(MODULE.ReviewerAccessError):
                MODULE.validate_config(config)

    def test_repository_expansion_is_rejected(self) -> None:
        config = copy.deepcopy(self.config)
        config["repositories"].append(
            {
                "repository": "appolon1908-hue/other",
                "repository_id": 1,
                "default_branch": "main",
                "required_status_checks": ["verify"],
            }
        )
        with self.assertRaises(MODULE.ReviewerAccessError):
            MODULE.validate_config(config)

    def test_apply_requires_exact_confirmation_before_token_or_api(self) -> None:
        with self.assertRaises(MODULE.ReviewerAccessError):
            MODULE.execute("apply", "WRONG")

    def test_only_write_equivalent_permissions_are_accepted(self) -> None:
        for permission, role in (("push", "write"), ("maintain", "maintain"), ("admin", "admin")):
            self.assertEqual(MODULE.permission_state({"permission": permission, "role_name": role}), (permission, role))
        permission, role = MODULE.permission_state({"permission": "pull", "role_name": "read"})
        self.assertNotIn(permission, MODULE.ACCEPTED_PERMISSIONS)
        self.assertNotIn(role, MODULE.ACCEPTED_ROLES)


if __name__ == "__main__":
    unittest.main()
