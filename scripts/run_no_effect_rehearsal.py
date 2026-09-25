#!/usr/bin/env python3
"""Run the V3 kernel no-effect rehearsal in-process and emit its report.

The same :class:`app.platform.rehearsal.NoEffectRehearsal` that serves
``POST /platform/v1/rehearsals/no-effect`` runs here against a runtime
container built from the process configuration (``role=worker``: the same
pool, kernel, gates, registry and reconciler as the deployed processes, no
bearer verification). It never writes the live ledger, the outbox or a
provider. Exit status 0 means verdict PASS; 1 means FAIL; 2 means the
runtime could not be assembled.

    python -m scripts.run_no_effect_rehearsal \\
        --reason "release rehearsal" \\
        --expected-source-sha "$SOURCE_SHA" \\
        --expected-schema-head 0067_service_catalog_monitoring_state \\
        --output evidence/rehearsal.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SERVICE_ID = "middleware-rehearsal-runner"


async def rehearse(args: argparse.Namespace) -> dict[str, Any]:
    from app.core.config import settings
    from app.core.runtime import build_runtime_container
    from app.platform.api import _public_contract_digest
    from app.platform.rehearsal import NoEffectRehearsal, RehearsalRequest
    from app.storage import RUNTIME_SCHEMA_VERSION

    runtime = await build_runtime_container(settings, role="worker", service_id=SERVICE_ID)
    try:
        runner = NoEffectRehearsal(runtime, runtime_schema_version=RUNTIME_SCHEMA_VERSION, contract_digest=_public_contract_digest())
        return await runner.run(
            RehearsalRequest(
                requested_by=args.operator,
                correlation_id=args.correlation_id or f"rehearsal-{uuid4().hex[:16]}",
                reason=args.reason,
                expected_source_sha=args.expected_source_sha,
                expected_schema_head=args.expected_schema_head,
            )
        )
    finally:
        await runtime.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--operator", default="rehearsal-runner")
    parser.add_argument("--correlation-id")
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-schema-head")
    parser.add_argument("--output", type=Path, help="also write the report JSON here")
    args = parser.parse_args(argv)
    try:
        report = asyncio.run(rehearse(args))
    except Exception as exc:  # noqa: BLE001 - surfaced as a runner failure, never a traceback with config
        print(json.dumps({"verdict": "ERROR", "error": type(exc).__name__}), file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    print(f"REHEARSAL_VERDICT={report['verdict']} REHEARSAL_ID={report['rehearsal_id']} REPORT_SHA256={report['report_sha256']}", file=sys.stderr)
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
