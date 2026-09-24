#!/usr/bin/env python3
"""Read-only audit that all base and supplemental workstream branches contain main."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from architecture.site_architecture import (  # noqa: E402
    workstreams as supplemental_workstreams,
)

BASE_MANIFEST = ROOT / "config" / "integration-branches.json"


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def resolve(candidates: list[str]) -> tuple[str, str] | None:
    for candidate in candidates:
        result = git("rev-parse", "--verify", candidate, check=False)
        if result.returncode == 0:
            return candidate, result.stdout.strip()
    return None


def load_branches() -> list[str]:
    base = json.loads(BASE_MANIFEST.read_text(encoding="utf-8"))
    values: list[str] = []
    for item in base.get("workstreams", []):
        if isinstance(item, dict) and isinstance(item.get("branch"), str):
            values.append(item["branch"])
    for item in supplemental_workstreams():
        values.append(item["branch"])
    if len(values) != len(set(values)):
        raise ValueError("base and supplemental registries contain duplicate branches")
    return sorted(values)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--base", default="main")
    parser.add_argument("--require-exact", action="store_true")
    args = parser.parse_args()

    try:
        branches = load_branches()
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: cannot load workstream registries: {exc}", file=sys.stderr)
        return 1

    base = resolve([f"refs/remotes/{args.remote}/{args.base}", f"refs/heads/{args.base}"])
    if base is None:
        print("ERROR: base ref unavailable; fetch all branches first", file=sys.stderr)
        return 1
    base_ref, base_sha = base

    failures = exact = ahead = 0
    print(f"BASE_REF={base_ref}")
    print(f"BASE_SHA={base_sha}")
    print(f"DECLARED_WORKSTREAMS={len(branches)}")

    for branch in branches:
        resolved = resolve([f"refs/remotes/{args.remote}/{branch}", f"refs/heads/{branch}"])
        if resolved is None:
            print(f"MISSING\t{branch}")
            failures += 1
            continue
        branch_ref, branch_sha = resolved
        ancestor = git("merge-base", "--is-ancestor", base_sha, branch_sha, check=False).returncode == 0
        if not ancestor:
            print(f"BEHIND_OR_DIVERGED\t{branch}\t{branch_sha}\t{branch_ref}")
            failures += 1
        elif branch_sha == base_sha:
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
