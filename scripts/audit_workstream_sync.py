#!/usr/bin/env python3
"""Audit whether every workstream contains the selected main branch commit.

The script is read-only. It expects remote-tracking refs to have been fetched by
an operator or CI job before execution.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config" / "integration-branches.json"


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def resolve_ref(candidates: list[str]) -> tuple[str, str] | None:
    for candidate in candidates:
        result = git("rev-parse", "--verify", candidate, check=False)
        if result.returncode == 0:
            return candidate, result.stdout.strip()
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--base", default="main")
    parser.add_argument(
        "--require-exact",
        action="store_true",
        help="Require every workstream tip to equal the selected base SHA.",
    )
    args = parser.parse_args()

    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load workstream manifest: {exc}", file=sys.stderr)
        return 1

    workstreams = manifest.get("workstreams")
    if not isinstance(workstreams, list):
        print("ERROR: workstreams is not an array", file=sys.stderr)
        return 1

    base = resolve_ref(
        [f"refs/remotes/{args.remote}/{args.base}", f"refs/heads/{args.base}"]
    )
    if base is None:
        print(
            "ERROR: base ref is unavailable; fetch remote branches before auditing",
            file=sys.stderr,
        )
        return 1

    base_ref, base_sha = base
    failures = 0
    exact = 0
    ahead = 0

    print(f"BASE_REF={base_ref}")
    print(f"BASE_SHA={base_sha}")

    for item in workstreams:
        if not isinstance(item, dict) or not isinstance(item.get("branch"), str):
            print("ERROR: invalid workstream entry", file=sys.stderr)
            failures += 1
            continue

        branch = item["branch"]
        resolved = resolve_ref(
            [f"refs/remotes/{args.remote}/{branch}", f"refs/heads/{branch}"]
        )
        if resolved is None:
            print(f"MISSING\t{branch}")
            failures += 1
            continue

        branch_ref, branch_sha = resolved
        ancestor = git(
            "merge-base", "--is-ancestor", base_sha, branch_sha, check=False
        ).returncode == 0

        if not ancestor:
            print(f"BEHIND_OR_DIVERGED\t{branch}\t{branch_sha}\t{branch_ref}")
            failures += 1
            continue

        if branch_sha == base_sha:
            print(f"EXACT\t{branch}\t{branch_sha}")
            exact += 1
        else:
            print(f"CONTAINS_MAIN\t{branch}\t{branch_sha}\t{branch_ref}")
            ahead += 1
            if args.require_exact:
                failures += 1

    print(f"WORKSTREAMS_EXACT={exact}")
    print(f"WORKSTREAMS_AHEAD_WITH_MAIN_ANCESTOR={ahead}")
    print(f"WORKSTREAM_SYNC_FAILURES={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
