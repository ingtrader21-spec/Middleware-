from __future__ import annotations

from typing import TYPE_CHECKING

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

if TYPE_CHECKING:
    from scripts.portfolio_ruleset.common import (  # noqa: E402
        RolloutError,
        load_policy,
        normalize_ruleset_payload,
        validate_ruleset_payload,
    )
else:
    from portfolio_ruleset.common import (  # noqa: E402
        RolloutError,
        load_policy,
        normalize_ruleset_payload,
        validate_ruleset_payload,
    )
if TYPE_CHECKING:
    from scripts.portfolio_ruleset.rollout import (  # noqa: E402
        select_active_repositories,
        write_evidence,
    )
else:
    from portfolio_ruleset.rollout import (  # noqa: E402
        select_active_repositories,
        write_evidence,
    )


class PortfolioProductionRulesetTests(unittest.TestCase):
    def test_committed_policy_is_exact_and_complete(self) -> None:
        portfolio, ruleset = load_policy()
        self.assertEqual(portfolio["owner"], "appolon1908-hue")
        self.assertEqual(len(portfolio["known_active_repositories"]), 56)
        self.assertEqual(len(set(portfolio["known_active_repositories"])), 56)
        normalized = validate_ruleset_payload(ruleset)
        self.assertEqual(
            normalized["conditions"]["ref_name"]["include"],
            ["refs/heads/production"],
        )
        self.assertEqual(normalized["bypass_actors"], [])
        self.assertEqual(
            {rule["type"] for rule in normalized["rules"]},
            {
                "pull_request",
                "required_linear_history",
                "non_fast_forward",
                "deletion",
            },
        )

    def test_default_branch_target_is_rejected(self) -> None:
        _, ruleset = load_policy()
        broken = json.loads(json.dumps(ruleset))
        broken["conditions"]["ref_name"]["include"] = ["~DEFAULT_BRANCH"]
        with self.assertRaisesRegex(RolloutError, "refs/heads/production"):
            validate_ruleset_payload(broken)

    def test_review_or_bypass_drift_is_rejected(self) -> None:
        _, ruleset = load_policy()
        review_drift = json.loads(json.dumps(ruleset))
        pull_request = next(
            rule for rule in review_drift["rules"] if rule["type"] == "pull_request"
        )
        pull_request["parameters"]["required_approving_review_count"] = 1
        with self.assertRaisesRegex(RolloutError, "parameters"):
            validate_ruleset_payload(review_drift)

        bypass_drift = json.loads(json.dumps(ruleset))
        bypass_drift["bypass_actors"] = [
            {"actor_id": 1, "actor_type": "OrganizationAdmin"}
        ]
        with self.assertRaisesRegex(RolloutError, "bypass"):
            validate_ruleset_payload(bypass_drift)

    def test_live_response_normalization_ignores_uncontrolled_metadata(self) -> None:
        _, desired = load_policy()
        observed = json.loads(json.dumps(desired))
        observed.update(
            {
                "id": 1234,
                "source_type": "Repository",
                "source": "appolon1908-hue/example",
                "node_id": "RRS_example",
                "created_at": "2026-09-03T00:00:00Z",
                "updated_at": "2026-09-03T00:00:00Z",
            }
        )
        pull_request = next(
            rule for rule in observed["rules"] if rule["type"] == "pull_request"
        )
        pull_request["parameters"][
            "require_extra_approval_for_unattributed_changes"
        ] = False
        self.assertEqual(
            normalize_ruleset_payload(observed),
            normalize_ruleset_payload(desired),
        )

    def test_inventory_visibility_fails_closed_before_mutation(self) -> None:
        portfolio, _ = load_policy()
        observed = [
            {
                "name": name,
                "full_name": f"appolon1908-hue/{name}",
                "archived": False,
                "disabled": False,
            }
            for name in portfolio["known_active_repositories"][:-1]
        ]
        with self.assertRaisesRegex(RolloutError, "cannot see every known"):
            select_active_repositories(portfolio, observed)

    def test_evidence_has_human_and_machine_readable_outputs(self) -> None:
        document = {
            "overall_result": "PASS",
            "mode": "apply",
            "owner": "appolon1908-hue",
            "source_sha": "a" * 40,
            "ruleset_name": "AI automated production branch gates",
            "repositories_discovered": 1,
            "repositories_selected": 1,
            "repositories_verified": 1,
            "failure_count": 0,
            "results": [
                {
                    "repository": "appolon1908-hue/example",
                    "action": "created",
                    "result": "PASS",
                    "ruleset_id": 42,
                }
            ],
            "errors": [],
        }
        with tempfile.TemporaryDirectory() as temp:
            json_path, markdown_path = write_evidence(Path(temp), document)
            self.assertEqual(json.loads(json_path.read_text())["overall_result"], "PASS")
            markdown = markdown_path.read_text()
            self.assertIn("appolon1908-hue/example", markdown)
            self.assertIn("refs/heads/production", markdown)


if __name__ == "__main__":
    unittest.main()
