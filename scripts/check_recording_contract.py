#!/usr/bin/env python3
"""Fail CI unless all six schemas match PR A exact head byte-for-byte."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas" / "recording"
MANIFEST = SCHEMAS / "contract-manifest-v1.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    if manifest != {
        "contract_version": "1.0",
        "source_repository": "Codestra-SRL/telephony-event-gateway",
        "source_pull_request": 20,
        "source_head": "ae92b95240a5ff638837121bc2773545bfbf6fdc",
        "schemas": manifest["schemas"],
    }:
        raise SystemExit("canonical recording provenance drifted")
    expected_names = {
        "recording-contract-v1.json",
        "recording-reservation-v1.json",
        "recording-completion-v1.json",
        "recording-status-v1.json",
        "recording-event-v1.json",
        "recording-n8n-event-v1.json",
    }
    if set(manifest["schemas"]) != expected_names:
        raise SystemExit("canonical six-schema set drifted")
    for name, expected in manifest["schemas"].items():
        actual = hashlib.sha256((SCHEMAS / name).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"{name}: PR A exact-head SHA-256 mismatch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
