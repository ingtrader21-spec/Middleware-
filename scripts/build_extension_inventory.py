#!/usr/bin/env python3
"""Build a complete fail-closed extension inventory from sanitized source JSON."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from app.core.telephony import AUTHORITATIVE_SOURCES, audit_extension


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    document = json.loads(args.evidence.read_text())
    if not isinstance(document, dict):
        raise SystemExit("evidence must be keyed by extension")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "extension", "classification", "evidence_hash",
            "missing_source_count", "collision_sources",
        ])
        for extension in list(range(6100, 6600)) + list(range(6900, 7000)):
            result = audit_extension(extension, document.get(str(extension), {}))
            writer.writerow([
                extension, result.classification, result.evidence_hash,
                len(result.missing_sources), ";".join(result.collision_sources),
            ])
    print(f"wrote 600 extension rows; required sources={len(AUTHORITATIVE_SOURCES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
