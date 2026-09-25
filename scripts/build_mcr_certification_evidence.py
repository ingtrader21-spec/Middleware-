#!/usr/bin/env python3
"""Build exact-SHA MCR-M certification evidence from a successful JUnit suite."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from xml.etree import ElementTree as ET

DEPENDENCIES = tuple("ABCDEFHIJKL")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SCENARIOS = {
    "api_openapi": (
        "tests.test_campaign_recycling_contracts::test_endpoint_set_is_exact",
        ["Campaign-engine endpoint inventory matches the frozen MCR contract."],
    ),
    "tenant_isolation": (
        "tests.test_platform_api::test_operation_read_is_tenant_scoped_and_redacted",
        ["Operation readback enforces tenant scope and redacts provider detail."],
    ),
    "auth_negatives": (
        "tests.test_platform_security_matrix::test_identity_negative_matrix[tenant_mismatch-bearer_overrides11-403]",
        ["A tenant-mismatched bearer token is rejected with the governed 403 path."],
    ),
    "deterministic_engine": (
        "tests.test_campaign_recycling_engine::test_hash_is_stable_for_same_inputs",
        ["Campaign recycling produces a stable decision hash for identical inputs."],
    ),
    "postgres_concurrency": (
        "tests.test_runtime_migration_certification::test_concurrent_runner_cannot_apply",
        ["Concurrent migration ownership is rejected instead of applying twice."],
    ),
    "postgres_recovery": (
        "tests.test_runtime_migration_certification::test_successful_upgrade_return_cannot_replace_readback",
        ["Database upgrade success cannot replace independent schema readback."],
    ),
    "staging_no_effect": (
        "tests.test_runtime::test_runtime_safety_readback_proves_fail_closed_staging",
        ["Staging runtime safety readback proves external effects remain fail-closed."],
    ),
    "rollback_readback": (
        "tests.test_mcr_release_dependencies::test_mcr_rollback_readback_is_integrated",
        ["MCR rollback/readback operating evidence is present in the integrated source."],
    ),
    "observability": (
        "tests.test_observability::test_metrics_require_monitoring_identity_and_use_bounded_labels",
        ["MCR monitoring evidence uses authenticated access and bounded metric labels."],
    ),
    "ui_states": (
        "tests.test_mcr_release_dependencies::test_mcr_lead_journey_ui_states_are_integrated",
        ["Lead Journey source contains loading, error, empty, retry, and read-only decision states."],
    ),
}


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _test_ids(root: ET.Element) -> set[str]:
    result: set[str] = set()
    for case in root.iter("testcase"):
        classname = case.get("classname")
        name = case.get("name")
        require(classname and name, "JUnit testcase identity is incomplete")
        test_id = f"{classname}::{name}"
        require(test_id not in result, f"duplicate JUnit testcase: {test_id}")
        result.add(test_id)
    return result


def build(source_sha: str, results_xml: Path, output_dir: Path) -> dict[str, object]:
    require(bool(SHA.fullmatch(source_sha)), "full lowercase source SHA required")
    raw_xml = results_xml.read_bytes()
    require(b"<!DOCTYPE" not in raw_xml.upper() and b"<!ENTITY" not in raw_xml.upper(), "DTD/entity declarations forbidden")
    root = ET.fromstring(raw_xml)
    require(root.tag in {"testsuite", "testsuites"}, "invalid JUnit root")
    require(not list(root.iter("failure")), "failed JUnit evidence")
    require(not list(root.iter("error")), "errored JUnit evidence")
    require(not list(root.iter("skipped")), "skipped JUnit evidence")
    for suite in root.iter():
        if suite.tag in {"testsuite", "testsuites"}:
            for counter in ("failures", "errors", "skipped", "disabled"):
                require(suite.get(counter, "0") == "0", f"nonzero JUnit {counter}")
    ids = _test_ids(root)
    require(ids, "empty JUnit evidence")

    missing = [test_id for test_id, _ in SCENARIOS.values() if test_id not in ids]
    require(not missing, "missing MCR scenario tests: " + ", ".join(missing))

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    (output_dir / "results.xml").write_bytes(raw_xml)

    scenario_manifest: dict[str, dict[str, str]] = {}
    for scenario, (test_id, observations) in SCENARIOS.items():
        evidence_name = f"{scenario}.json"
        (output_dir / evidence_name).write_text(
            json.dumps(
                {
                    "source_sha": source_sha,
                    "scenario": scenario,
                    "result": "pass",
                    "observations": observations,
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        scenario_manifest[scenario] = {"test": test_id, "evidence": evidence_name}

    manifest = {
        "source_sha": source_sha,
        "dependency_mode": "integrated-source-closure",
        "dependencies": {key: source_sha for key in DEPENDENCIES},
        "scenarios": scenario_manifest,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--results-xml", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.source_sha, args.results_xml, args.output_dir)
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"MCR_CERTIFICATION_EVIDENCE=BLOCKED reason={exc}")
        return 1
    print("MCR_CERTIFICATION_EVIDENCE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())