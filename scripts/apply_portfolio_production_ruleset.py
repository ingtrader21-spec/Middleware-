#!/usr/bin/env python3
"""Validate, apply, or verify the Codestra portfolio production ruleset."""
from __future__ import annotations

from typing import TYPE_CHECKING

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

if TYPE_CHECKING:
    from scripts.portfolio_ruleset.common import (
        DEFAULT_EVIDENCE_DIR,
        RolloutError,
        TOKEN_ENV,
        load_policy,
    )
else:
    from portfolio_ruleset.common import (
        DEFAULT_EVIDENCE_DIR,
        RolloutError,
        TOKEN_ENV,
        load_policy,
    )
if TYPE_CHECKING:
    from scripts.portfolio_ruleset.rollout import execute, write_evidence
else:
    from portfolio_ruleset.rollout import execute, write_evidence


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode", choices=("validate", "dry-run", "apply", "verify"), default="validate"
    )
    parser.add_argument("--confirm", default="")
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    owner = "unknown"
    ruleset_name = "unknown"
    try:
        portfolio, ruleset = load_policy()
        owner = str(portfolio["owner"])
        ruleset_name = str(ruleset["name"])
        if args.mode == "validate":
            print(
                f"PORTFOLIO_POLICY=PASS repositories={len(portfolio['known_active_repositories'])}"
            )
            print(f"RULESET_POLICY=PASS name={ruleset_name}")
            return 0
        document = execute(
            mode=args.mode,
            token=os.environ.get(TOKEN_ENV, ""),
            confirmation=args.confirm,
            evidence_dir=args.evidence_dir,
            portfolio=portfolio,
            desired=ruleset,
        )
        print(
            "PORTFOLIO_PRODUCTION_RULESET="
            f"{document['overall_result']} selected={document['repositories_selected']} "
            f"verified={document['repositories_verified']} failures={document['failure_count']}"
        )
        return 0 if document["overall_result"] == "PASS" else 1
    except RolloutError as exc:
        failure = {
            "schema_version": "1.0",
            "generated_at": dt.datetime.now(dt.UTC).isoformat(),
            "mode": args.mode,
            "owner": owner,
            "ruleset_name": ruleset_name,
            "overall_result": "FAIL",
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "repositories_discovered": 0,
            "repositories_selected": 0,
            "repositories_verified": 0,
            "failure_count": 1,
            "results": [],
            "errors": [str(exc)],
        }
        write_evidence(args.evidence_dir, failure)
        print(f"PORTFOLIO_PRODUCTION_RULESET=FAIL reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
