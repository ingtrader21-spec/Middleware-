#!/usr/bin/env python3
"""Generate or verify deterministic connector desired-state artifacts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from middleware.connector_sdk.generation import (  # noqa: E402
    build_generated_artifacts,
    render_generated_artifact,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed generated files without writing",
    )
    args = parser.parse_args()

    manifest_dir = ROOT / "connectors" / "manifests"
    output_dir = ROOT / "connectors" / "generated"
    artifacts = build_generated_artifacts(manifest_dir)
    errors: list[str] = []

    if args.check:
        for name, data in artifacts.items():
            path = output_dir / name
            expected = render_generated_artifact(data)
            if not path.is_file():
                errors.append(f"missing generated artifact: {path}")
                continue
            if path.read_text(encoding="utf-8") != expected:
                errors.append(f"stale generated artifact: {path}")
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        for name, data in artifacts.items():
            path = output_dir / name
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_text(
                render_generated_artifact(data),
                encoding="utf-8",
            )
            temporary.replace(path)

    if errors:
        print("CONNECTOR_ARTIFACT_GENERATION=FAIL", file=sys.stderr)
        for error in errors:
            print(f"ERROR={error}", file=sys.stderr)
        return 1

    action = "CHECK" if args.check else "WRITE"
    print(
        f"CONNECTOR_ARTIFACT_GENERATION={action}_PASS "
        f"FILES={len(artifacts)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
