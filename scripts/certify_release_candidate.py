#!/usr/bin/env python3
"""Offline, read-only release certification over an evidence directory.

Evaluates ``release_candidate.json``, ``backup.json``, ``restore_rehearsal.json``,
``rollback.json`` and ``seal.json`` with the same fail-closed rules the private
``/internal/v1/release/*`` API uses, prints the machine-readable decision and
exits non-zero unless the chain is CERTIFIED. ``--write-schema`` / ``--check-schema``
maintain the committed JSON Schema. Nothing is deployed, signed, restored or
rolled back.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import release_certification as certification  # noqa: E402

SCHEMA_PATH = ROOT / "schemas" / "release-certification-evidence.v1.schema.json"


def _render_schema() -> str:
    return json.dumps(certification.json_schema(), indent=2, sort_keys=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", nargs="?", type=Path)
    parser.add_argument("--expected-schema-head", default=None)
    parser.add_argument("--max-backup-age-hours", type=int, default=24)
    parser.add_argument("--write-schema", action="store_true")
    parser.add_argument("--check-schema", action="store_true")
    args = parser.parse_args(argv)

    if args.write_schema:
        SCHEMA_PATH.write_text(_render_schema(), encoding="utf-8")
        return 0
    if args.check_schema:
        if not SCHEMA_PATH.is_file() or SCHEMA_PATH.read_text(encoding="utf-8") != _render_schema():
            print(f"stale: {SCHEMA_PATH.relative_to(ROOT)}", file=sys.stderr)
            return 1
        return 0
    if args.evidence_dir is None:
        parser.error("evidence_dir is required")
    if args.max_backup_age_hours < 1:
        parser.error("--max-backup-age-hours must be >= 1")

    bundle = certification.load_evidence_dir(args.evidence_dir)
    result = certification.evaluate(
        bundle,
        expected_schema_head=args.expected_schema_head,
        max_backup_age=timedelta(hours=args.max_backup_age_hours),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["certified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
