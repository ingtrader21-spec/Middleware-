from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SCRIPT = (
    ROOT / "scripts" / "apply_integration_main_release_authorities.py"
)
CONFIG = (
    ROOT / "config" / "integration-main-release-authorities.v1.json"
)
WORKFLOW = (
    ROOT
    / ".github"
    / "workflows"
    / "integration-main-release-authorities.yml"
)

spec = importlib.util.spec_from_file_location(
    "integration_authority_public",
    PUBLIC_SCRIPT,
)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


class IntegrationAuthorityCompatibilityTests(unittest.TestCase):
    def test_original_public_entry_point_uses_seven_repository_policy(
        self,
    ) -> None:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        rows = MODULE.validate_config(config)
        self.assertEqual(len(rows), 7)
        self.assertEqual(
            {row["repository"] for row in rows},
            set(MODULE.V2.EXPECTED_REPOSITORIES),
        )

    def test_original_public_cli_validate_remains_usable(self) -> None:
        previous = MODULE.BASE.EVIDENCE_DIR
        try:
            with tempfile.TemporaryDirectory() as directory:
                MODULE.BASE.EVIDENCE_DIR = (
                    Path(directory) / "integration-main-release-authorities"
                )
                self.assertEqual(MODULE.main(["--mode", "validate"]), 0)
                self.assertTrue(MODULE.BASE.EVIDENCE_DIR.is_dir())
        finally:
            MODULE.BASE.EVIDENCE_DIR = previous

    def test_policy_job_has_no_issue_write_permission(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        header, jobs = text.split("\njobs:\n", 1)
        self.assertNotIn("issues: write", header)
        policy, apply = jobs.split("\n  apply:\n", 1)
        self.assertNotIn("issues: write", policy)
        self.assertIn("issues: write", apply)


if __name__ == "__main__":
    unittest.main()
