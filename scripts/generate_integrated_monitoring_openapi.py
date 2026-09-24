"""Export the implemented API with required replay/signature headers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def document():
    from fastapi import FastAPI
    from app.monitoring.routes import router

    app = FastAPI(title="Integrated monitoring API", version="1.0.0")
    app.include_router(router)
    result = app.openapi()
    catalog = json.loads(
        (ROOT / "contracts/observability/integrated-monitoring.v1.json").read_text()
    )
    for item in catalog["operations"]:
        operation = result["paths"][item["path"]][item["method"].lower()]
        operation["summary"] = item["purpose"]
        operation["x-required-authority"] = item["authorization"]
        operation["description"] = (
            "Runtime coverage requires fresh evidence. See INTEGRATED-MONITORING-DESIGN.md and app/monitoring/README.md."
        )
        if item["method"] == "POST":
            names = ["Idempotency-Key", "X-Correlation-ID"]
            if item["path"].endswith("/github/events"):
                names = ["X-Hub-Signature-256", "X-GitHub-Event", "X-GitHub-Delivery"]
            operation.setdefault("parameters", []).extend(
                [
                    {
                        "name": name,
                        "in": "header",
                        "required": True,
                        "schema": {"type": "string", "maxLength": 256},
                    }
                    for name in names
                ]
            )
        for status in (401, 403, 404, 409, 413, 422, 502, 503):
            operation["responses"].setdefault(
                str(status),
                {
                    "description": {
                        401: "Missing authenticated identity",
                        403: "Authority denied",
                        404: "Scoped resource not found",
                        409: "Revision, ordering or replay conflict",
                        413: "Payload budget exceeded",
                        422: "Invalid request or unapproved template",
                        502: "Backend response exceeds contract budget",
                        503: "Identity, persistence or backend configuration unavailable",
                    }[status]
                },
            )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "contracts/observability/integrated-monitoring.openapi.json"
    content = json.dumps(document(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not target.exists() or target.read_text() != content:
            raise SystemExit(
                "Integrated monitoring OpenAPI drift; regenerate the contract"
            )
        print("INTEGRATED_MONITORING_OPENAPI=PASS OPERATIONS=36")
    else:
        target.write_text(content)
