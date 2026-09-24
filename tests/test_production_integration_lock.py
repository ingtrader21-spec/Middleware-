from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_production_integration_lock.py"
LOCK = ROOT / "config" / "production-integration-lock.v1.json"

spec = importlib.util.spec_from_file_location("production_integration_lock", SCRIPT)
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


class ProductionIntegrationLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock: dict[str, Any] = json.loads(LOCK.read_text(encoding="utf-8"))

    def test_current_no_go_lock_is_valid(self) -> None:
        document = MODULE.validate_lock(self.lock)
        self.assertEqual(document["result"], "PASS")
        self.assertEqual(document["decision"], "NO_GO")
        self.assertEqual(document["runtime_certified_count"], 0)
        self.assertFalse(document["production_activated"])
        self.assertEqual(document["calls_placed"], 0)

    def test_live_effect_fails(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["release_policy"]["external_effects"]["email_delivery"] = True
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_duplicate_repository_fails(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["components"][1]["repo"] = broken["components"][0]["repo"]
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_candidate_state_without_pr_evidence_fails(self) -> None:
        broken = copy.deepcopy(self.lock)
        row = next(
            item
            for item in broken["components"]
            if item.get("source") == "candidate_pending_review"
        )
        row["prs"] = []
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_false_runtime_certification_fails_without_digest_and_evidence(
        self,
    ) -> None:
        broken = copy.deepcopy(self.lock)
        broken["runtime_certifications"]["middleware"] = {
            "immutable_image_digest": None,
            "staging_evidence": None,
            "backup_restore_evidence": None,
            "rollback_evidence": None,
            "runtime_readback_evidence": None,
        }
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_unprotected_component_cannot_be_source_ready(self) -> None:
        broken = copy.deepcopy(self.lock)
        row = next(
            item
            for item in broken["components"]
            if item.get("protected", False) is False
        )
        row["state"] = "SOURCE_READY"
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_invalid_source_sha_fails(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["components"][0]["sha"] = "main"
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_calls_placed_must_remain_zero(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["release_policy"]["calls_placed"] = 1
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_defaults_must_remain_fail_closed(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["component_defaults"]["state"] = "SOURCE_READY"
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_malformed_nested_shapes_fail_with_controlled_error(self) -> None:
        component_id = self.lock["components"][0]["id"]
        cases: list[tuple[str, tuple[str | int, ...], object]] = [
            ("authority", ("authority",), []),
            ("release policy", ("release_policy",), []),
            (
                "external effects",
                ("release_policy", "external_effects"),
                [],
            ),
            ("component defaults", ("component_defaults",), []),
            (
                "default blockers",
                ("component_defaults", "blockers"),
                "not-a-list",
            ),
            ("components", ("components",), {}),
            ("component", ("components", 0), "not-an-object"),
            ("component source", ("components", 0, "source"), []),
            ("candidate", ("components", 4, "prs", 0), "not-an-object"),
            ("candidate status", ("components", 4, "prs", 0, "status"), []),
            ("dependencies", ("components", 0, "deps"), {}),
            ("runtime certifications", ("runtime_certifications",), []),
            (
                "runtime certification",
                ("runtime_certifications",),
                {component_id: []},
            ),
            ("promotion order", ("promotion_order",), {}),
        ]

        for label, path, invalid in cases:
            with self.subTest(label=label):
                broken = copy.deepcopy(self.lock)
                target: Any = broken
                for segment in path[:-1]:
                    target = target[segment]
                target[path[-1]] = invalid
                with self.assertRaises(MODULE.LockError):
                    MODULE.validate_lock(broken)

    def test_booleans_are_not_accepted_as_integer_authority(self) -> None:
        for path in (
            ("release_policy", "calls_placed"),
            ("release_policy", "max_read_only_canary_percent"),
            ("components", 0, "rid"),
            ("components", 4, "prs", 0, "n"),
        ):
            with self.subTest(path=path):
                broken = copy.deepcopy(self.lock)
                target: Any = broken
                for segment in path[:-1]:
                    target = target[segment]
                target[path[-1]] = True
                with self.assertRaises(MODULE.LockError):
                    MODULE.validate_lock(broken)

    def test_authority_strings_must_be_canonical(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["components"][0]["branch"] = " main"
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(broken)

    def test_noncanonical_json_fails_closed(self) -> None:
        cases = (
            '{"schema_version":"1.0","schema_version":"2.0"}',
            '{"schema_version":NaN}',
            '{"schema_version":Infinity}',
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "lock.json"
            for source in cases:
                with self.subTest(source=source):
                    path.write_text(source, encoding="utf-8")
                    with self.assertRaises(MODULE.LockError):
                        MODULE.load_lock(path)


if __name__ == "__main__":
    unittest.main()
