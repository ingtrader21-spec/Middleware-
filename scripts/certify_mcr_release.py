#!/usr/bin/env python3
"""Read-only MCR certification. Only exact-SHA Actions evidence can certify.

Missing integration evidence is a release blocker, never a skipped success.
The artifact protocol is documented in docs/missions/MCR-M-QA-RELEASE.md.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from scripts.mcr_dependency_contract import DEPENDENCIES, load_dependency_contract

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "ingtrader21-spec/Middleware-"
BRANCH = "mission/mcr-m-qa-release-20260924"
WORKFLOW = ".github/workflows/middleware-ci.yml"
SCENARIOS = (
    "api_openapi",
    "tenant_isolation",
    "auth_negatives",
    "deterministic_engine",
    "postgres_concurrency",
    "postgres_recovery",
    "staging_no_effect",
    "rollback_readback",
    "observability",
    "ui_states",
)
SHA = re.compile(r"[0-9a-f]{40}")
MAX_ARCHIVE = 20 * 1024 * 1024


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def command(*args: str) -> str:
    return subprocess.check_output(
        args, cwd=ROOT, text=True, stderr=subprocess.PIPE, timeout=60
    ).strip()


def api(path: str, *, binary: bool = False, repository: str = REPOSITORY):
    repositories = {record["repository"] for record in load_dependency_contract().values()}
    require(repository in repositories, "unapproved repository authority")
    result = subprocess.check_output(
        ["gh", "api", f"repos/{repository}/{path}"],
        cwd=ROOT,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    return result if binary else json.loads(result)


def verify_digest(data: bytes, digest: str) -> None:
    require(
        digest == "sha256:" + hashlib.sha256(data).hexdigest(),
        "Actions artifact digest mismatch",
    )


def validate_run(run: dict, source_sha: str) -> None:
    require(run.get("head_sha") == source_sha, "Actions run source SHA mismatch")
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success",
        "Actions run is not successful",
    )
    require(
        run.get("event") in ("pull_request", "push", "workflow_dispatch"),
        "untrusted Actions event",
    )
    require(run.get("path") == WORKFLOW, "unexpected evidence workflow")
    require(
        run.get("head_repository", {}).get("full_name") == REPOSITORY,
        "fork evidence is not accepted",
    )


def validate_bundle(data: bytes, source_sha: str) -> dict:
    """Validate downloaded evidence in memory; never extract archive paths."""
    require(bool(SHA.fullmatch(source_sha)), "full lowercase source SHA required")
    require(len(data) <= MAX_ARCHIVE, "artifact exceeds size limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        require(len(names) == len(set(names)), "duplicate archive entries")
        require(
            sum(entry.file_size for entry in entries) <= MAX_ARCHIVE,
            "expanded artifact exceeds size limit",
        )
        require(
            all(
                not name.startswith("/") and ".." not in name.split("/")
                for name in names
            ),
            "unsafe archive path",
        )
        require(
            {"manifest.json", "results.xml"} <= set(names),
            "missing manifest or JUnit evidence",
        )
        manifest = json.loads(archive.read("manifest.json"))
        require(isinstance(manifest, dict), "manifest must be an object")
        require(
            manifest.get("source_sha") == source_sha, "artifact source SHA mismatch"
        )
        dependencies = manifest.get("dependencies")
        expected_dependencies = load_dependency_contract()
        require(
            dependencies == expected_dependencies,
            "artifact dependency handoffs do not match the pinned contract",
        )
        scenarios = manifest.get("scenarios")
        require(
            isinstance(scenarios, dict) and set(scenarios) == set(SCENARIOS),
            "incomplete scenario coverage",
        )
        xml = archive.read("results.xml")
        require(
            b"<!DOCTYPE" not in xml.upper() and b"<!ENTITY" not in xml.upper(),
            "DTD/entity declarations forbidden",
        )
        root = ET.fromstring(xml)
        require(root.tag in ("testsuite", "testsuites"), "invalid JUnit root")
        require(
            not list(root.iter("failure"))
            and not list(root.iter("error"))
            and not list(root.iter("skipped")),
            "failed, errored or skipped evidence",
        )
        for suite in root.iter():
            if suite.tag in ("testsuite", "testsuites"):
                for counter in ("failures", "errors", "skipped", "disabled"):
                    require(
                        suite.get(counter, "0") == "0",
                        "nonzero or invalid JUnit failure/skip counter",
                    )
        tests = list(root.iter("testcase"))
        require(bool(tests), "empty JUnit evidence")
        ids = [f"{case.get('classname')}::{case.get('name')}" for case in tests]
        require(len(ids) == len(set(ids)), "duplicate JUnit test identities")
        used = set()
        for scenario, record in scenarios.items():
            require(isinstance(record, dict), f"{scenario}: invalid record")
            test_id = record.get("test")
            require(
                isinstance(test_id, str) and test_id in ids and test_id not in used,
                f"{scenario}: missing or reused test",
            )
            used.add(test_id)
            path = record.get("evidence")
            require(
                isinstance(path, str) and path in names,
                f"{scenario}: missing observation evidence",
            )
            observed = json.loads(archive.read(path))
            require(
                isinstance(observed, dict)
                and observed.get("source_sha") == source_sha
                and observed.get("scenario") == scenario
                and observed.get("result") == "pass",
                f"{scenario}: invalid observation binding",
            )
            observations = observed.get("observations")
            generic_claims = {
                "pass",
                "passed",
                "success",
                "successful",
                "ok",
                "all passed",
                "everything passed",
                "all tests passed",
            }
            require(
                isinstance(observations, list)
                and bool(observations)
                and all(
                    isinstance(item, str)
                    and item.strip()
                    and item.strip().lower() not in generic_claims
                    for item in observations
                ),
                f"{scenario}: empty or generic observations",
            )
        return manifest


def protected_ci(source_sha: str) -> dict:
    """Check effective protection and check runs live; API denial blocks release."""
    from scripts.validate_repository_governance import (
        EXPECTED_REQUIRED_STATUS_CHECKS,
        REQUIRED_CHECK_APP_ID,
    )

    rules = api("rules/branches/main")
    required = set()
    for rule in rules:
        if rule.get("type") == "required_status_checks":
            parameters = rule["parameters"]
            require(
                parameters.get("strict_required_status_checks_policy") is True,
                "protection must require up-to-date branches",
            )
            for check in parameters["required_status_checks"]:
                require(
                    check.get("integration_id") == REQUIRED_CHECK_APP_ID,
                    "required check app is not pinned",
                )
                required.add(check["context"])
    require(
        EXPECTED_REQUIRED_STATUS_CHECKS <= required,
        "effective main protection is incomplete",
    )
    checks = []
    page = 1
    while True:
        batch = api(
            f"commits/{source_sha}/check-runs?per_page=100&page={page}&filter=latest"
        )["check_runs"]
        checks.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    for name in required:
        candidates = [
            check
            for check in checks
            if check.get("name") == name
            and check.get("app", {}).get("id") == REQUIRED_CHECK_APP_ID
        ]
        require(len(candidates) == 1, f"{name}: missing or ambiguous protected check")
        check = candidates[0]
        require(
            check.get("head_sha") == source_sha
            and check.get("status") == "completed"
            and check.get("conclusion") == "success",
            f"{name}: exact-SHA protected check is not successful",
        )
    statuses = api(f"commits/{source_sha}/status?per_page=100")
    require(
        statuses.get("total_count", 0) <= 100, "status listing exceeds supported bound"
    )
    exact = [
        item
        for item in statuses["statuses"]
        if item.get("context") == "codestra/required-ci"
    ]
    require(
        len(exact) == 1
        and exact[0].get("state") == "success"
        and exact[0].get("creator", {}).get("login") == "github-actions[bot]",
        "required exact-SHA Actions status is missing or not successful",
    )
    return {"required_checks": sorted(required), "source_sha": source_sha}


def certify(source_sha: str, run_id: int) -> dict:
    require(bool(SHA.fullmatch(source_sha)), "full lowercase source SHA required")
    require(
        command("git", "branch", "--show-current") == BRANCH, "wrong mission branch"
    )
    require(
        command("git", "rev-parse", "HEAD") == source_sha,
        "local HEAD differs from requested SHA",
    )
    require(
        not command("git", "status", "--porcelain", "--untracked-files=all"),
        "working tree must be clean including untracked files",
    )
    remote = command(
        "git", "ls-remote", "--exit-code", "origin", f"refs/heads/{BRANCH}"
    )
    require(remote.split()[0] == source_sha, "local SHA differs from remote branch")
    governance = protected_ci(source_sha)
    run = api(f"actions/runs/{run_id}")
    validate_run(run, source_sha)
    payload = api(f"actions/runs/{run_id}/artifacts?per_page=100")
    require(
        payload.get("total_count", 0) <= 100, "artifact listing exceeds supported bound"
    )
    artifacts = [
        item
        for item in payload["artifacts"]
        if item["name"] == "mcr-m-certification-evidence"
    ]
    require(len(artifacts) == 1, "one MCR certification evidence artifact required")
    artifact = artifacts[0]
    require(artifact.get("expired") is False, "artifact is expired")
    require(
        artifact.get("workflow_run", {}).get("head_sha") == source_sha
        and artifact.get("workflow_run", {}).get("id") == run_id,
        "artifact run binding mismatch",
    )
    require(
        artifact.get("created_at", "") >= run["run_started_at"],
        "artifact belongs to an earlier run attempt",
    )
    data = api(f"actions/artifacts/{artifact['id']}/zip", binary=True)
    verify_digest(data, artifact.get("digest", ""))
    manifest = validate_bundle(data, source_sha)
    for dependency, record in manifest["dependencies"].items():
        repository = record["repository"]
        sha = record["sha"]
        if repository == REPOSITORY:
            require(
                command("git", "cat-file", "-t", sha) == "commit",
                f"{dependency}: SHA is not a Middleware commit",
            )
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", sha, source_sha],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
        else:
            commit = api(f"commits/{sha}", repository=repository)
            require(
                commit.get("sha") == sha,
                f"{dependency}: external dependency SHA is unavailable",
            )
    # Re-read mutable state after downloading and validating evidence.
    require(
        command("git", "rev-parse", "HEAD") == source_sha
        and not command("git", "status", "--porcelain", "--untracked-files=all"),
        "checkout changed during certification",
    )
    require(
        command(
            "git", "ls-remote", "--exit-code", "origin", f"refs/heads/{BRANCH}"
        ).split()[0]
        == source_sha,
        "remote changed during certification",
    )
    latest = api(f"actions/runs/{run_id}")
    validate_run(latest, source_sha)
    require(
        latest.get("run_attempt") == run.get("run_attempt"),
        "Actions run changed during certification",
    )
    protected_ci(source_sha)
    return {
        "status": "CERTIFIED",
        "source_sha": source_sha,
        "dependencies": manifest["dependencies"],
        "scenarios": list(SCENARIOS),
        "governance": governance,
        "run_id": run_id,
        "artifact_id": artifact["id"],
        "artifact_digest": artifact["digest"],
        "deployment_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    args = parser.parse_args()
    try:
        require(args.run_id > 0, "positive Actions run ID required")
        report = certify(args.source_sha, args.run_id)
    except (
        ValueError,
        OSError,
        subprocess.SubprocessError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        zipfile.BadZipFile,
        ET.ParseError,
    ) as exc:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "source_sha": args.source_sha,
                    "deployment_authorized": False,
                    "reason": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
