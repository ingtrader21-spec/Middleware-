#!/usr/bin/env python3
"""Fetch an exact immutable release commit without broadening the checkout."""

from __future__ import annotations

import re
import subprocess
import sys

VALID_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, text=True, capture_output=True)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <release_sha> [remote]", file=sys.stderr)
        return 2

    release_sha = argv[1]
    remote = argv[2] if len(argv) > 2 else "origin"

    if not VALID_SHA_RE.fullmatch(release_sha):
        print("invalid release SHA format", file=sys.stderr)
        return 64

    fetch = _run(["git", "fetch", "--no-tags", "--depth=1", remote, release_sha])
    if fetch.returncode != 0:
        if fetch.stdout:
            print(fetch.stdout, file=sys.stderr, end="")
        if fetch.stderr:
            print(fetch.stderr, file=sys.stderr, end="")
        return fetch.returncode

    fetched = _run(["git", "rev-parse", "--verify", "FETCH_HEAD^{commit}"])
    fetched_sha = fetched.stdout.strip()
    if fetched.returncode != 0:
        if fetched.stdout:
            print(fetched.stdout, file=sys.stderr, end="")
        if fetched.stderr:
            print(fetched.stderr, file=sys.stderr, end="")
        return fetched.returncode

    if fetched_sha != release_sha:
        print("fetched commit does not match requested release SHA", file=sys.stderr)
        return 65

    commit_check = _run(["git", "cat-file", "-e", f"{release_sha}^{{commit}}"])
    if commit_check.returncode != 0:
        if commit_check.stdout:
            print(commit_check.stdout, file=sys.stderr, end="")
        if commit_check.stderr:
            print(commit_check.stderr, file=sys.stderr, end="")
        return commit_check.returncode

    print(fetched_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
