#!/usr/bin/env python3
"""Run the read-only monitoring collector once and write a redacted report.

    python -m scripts.monitoring_collector --config /abs/collector.json --output /abs/0700/dir [--no-post]

Reads the active configuration and freshness of every monitoring component,
posts ``config`` observations and service observed state to Middleware
(``--no-post`` only renders the report), and writes ``collector-report.json``
plus the Section 10 ``target-records.md``. Exit 0 = report written and every
post accepted; exit 2 = at least one component failed (report still written);
exit 3 = fail closed (Middleware unavailable, bad config, secret-shaped output).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.monitoring.collector import CollectorConfig, CollectorError, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--config",
        required=True,
        help="absolute path to the collector configuration JSON",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="absolute output directory for the redacted report",
    )
    parser.add_argument(
        "--no-post",
        action="store_true",
        help="read and report only; do not post to Middleware",
    )
    args = parser.parse_args(argv)
    config_path, output = Path(args.config), Path(args.output)
    if not config_path.is_absolute() or not output.is_absolute():
        print(
            "MONITORING_COLLECTOR=FAIL reason=paths-must-be-absolute", file=sys.stderr
        )
        return 3
    try:
        config = CollectorConfig.load(config_path)
        report = run(config, output, post=not args.no_post)
    except CollectorError as exc:
        print(f"MONITORING_COLLECTOR=FAIL reason={exc}", file=sys.stderr)
        return 3
    failed = sorted(
        name
        for name, reading in report["components"].items()
        if reading["status"] != "observed"
    )
    rejected = [
        p
        for p in report["posted"]
        if isinstance(p.get("http_status"), int) and p["http_status"] >= 400
    ]
    summary = {
        "components": len(report["components"]),
        "failed_components": failed,
        "posted": len(report["posted"]),
        "rejected_posts": len(rejected),
        "targets": len(report["targets"]),
        "correlation_id": report["correlation_id"],
    }
    print(
        "MONITORING_COLLECTOR="
        + ("PASS" if not failed and not rejected else "DEGRADED")
        + " "
        + json.dumps(summary, sort_keys=True)
    )
    return 0 if not failed and not rejected else 2


if __name__ == "__main__":
    sys.exit(main())
