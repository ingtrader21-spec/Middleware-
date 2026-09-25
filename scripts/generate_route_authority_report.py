#!/usr/bin/env python3
"""Generate the machine-readable route authority report (V3, Phase 34).

Walks the canonical integration application (the deployed 8095 service) and
classifies every operation:

* ``READ_ONLY`` — GET/HEAD/OPTIONS, and POSTs that only compute (policy
  decisions, idempotency checks, lookups);
* ``KERNEL_WRAPPER`` — the handler delegates to the one command kernel /
  command ledger (``kernel_delegate`` names the call);
* ``INTERNAL_EVENT_INGRESS`` — inbound events, callbacks, provider/adapter
  reported state and Middleware-internal state mutations that never reach an
  external provider;
* ``DURABLE_OUTBOX_INTENT`` — the handler persists a durable intent (the
  runtime ``middleware_outbox`` or the ORM ``outbox_event``) that a worker
  executes under the same Settings effect gates; effectful, asynchronous,
  but not yet a CommandEnvelope through the kernel (convergence pending);
* ``DIRECT_INTERNAL_SERVICE`` — a synchronous call to a Codestra-internal
  control service (identity/session issuance); not an external provider
  effect, listed so the gap is visible and never silently widened;
* ``DENIED_LEGACY`` — paths the edge contract denies (never mounted on the
  integration profile; reported from the contract for completeness).

Classification is derived from the handler source (kernel calls, outbound
transports) with the reviewed overrides in
``config/route-authority-overrides.v1.json``. ``DIRECT_EFFECT_BYPASSES``
counts mutating operations that reach an external provider outside the
kernel; the report is committed as ``config/route-authority-report.v1.json`` and
``tests/test_route_authority_report.py`` fails when it drifts or the bypass
count is not zero.
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ALLOW_IN_MEMORY_STORAGE", "true")

OUTPUT = ROOT / "config" / "route-authority-report.v1.json"
OVERRIDES = ROOT / "config" / "route-authority-overrides.v1.json"
EDGE_CONTRACT = ROOT / "deploy" / "public-api-route-contract.json"

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
KERNEL_CALLS = (
    ("submit_crm_command(", "app.api.v1.crm_common.submit_crm_command -> CommandKernel.submit"),
    ("platform.kernel.submit(", "CommandKernel.submit"),
    ("platform.kernel.cancel(", "CommandKernel.cancel -> CommandStore.mutate_operation"),
    ("platform.kernel.replay(", "CommandKernel.replay"),
    ("platform.kernel.get(", "CommandKernel.get"),
    ("platform.kernel.timeline(", "CommandKernel.timeline"),
    ("commands.submit(", "CommandService.submit"),
    ("commands.mutate_operation(", "CommandService.mutate_operation"),
    (".mutate_operation(", "CommandStore.mutate_operation"),
    ("active.commands", "CommandService"),
)
INGRESS_PATTERNS = (
    r"/events(/|$)",
    r"/webhooks?(/|$)",
    r"/callbacks?(/|$)",
    r"/results(/|$)",
    r"/progress$",
    r"/observations$",
    r"/heartbeats$",
    r"/kyqra/",
    r"/inbox(/|$)",
    r"/quarantine(/|$)",
    r"/transitions$",
    r"/dead-letter",
    r"/errors$",
    r"/reconciliation",
)
READ_ONLY_POSTS = (
    r"/policy/decisions$",
    r"/policy-check$",
    r"/idempotency/check$",
    r"/authorization/check$",
    r"/resolve$",
    r"/search$",
    r"/context/select$",
    r"/audit$",
    # The no-effect rehearsal runs in an in-memory sandbox; the live ledger,
    # outbox and providers are never written (app.platform.rehearsal).
    r"^/platform/v1/rehearsals/no-effect$",
)


def _routes(app):
    from fastapi.routing import APIRoute

    def walk(routes, prefix: str = ""):
        for route in routes:
            original = getattr(route, "original_router", None)
            if original is not None:
                context = getattr(route, "include_context", None)
                yield from walk(original.routes, prefix + (getattr(context, "prefix", "") or ""))
                continue
            if isinstance(route, APIRoute):
                yield prefix + route.path_format, route

    return list(walk(app.routes))


def _source(endpoint) -> str:
    """The handler source plus the same-module helpers it calls (one level),
    so a handler that delegates its outbox write or kernel call to a private
    helper is classified by what the helper does."""
    try:
        own = inspect.getsource(endpoint)
    except (OSError, TypeError):
        return ""
    module = sys.modules.get(getattr(endpoint, "__module__", ""))
    if module is None:
        return own
    parts = [own]
    for name in sorted(set(re.findall(r"(?<![\w.])(_?[a-z][a-z0-9_]*)\(", own))):
        helper = getattr(module, name, None)
        if helper is endpoint or not callable(helper) or getattr(helper, "__module__", None) != module.__name__:
            continue
        try:
            parts.append(inspect.getsource(helper))
        except (OSError, TypeError):
            continue
    return chr(10).join(parts)


def classify(method: str, path: str, route, overrides: dict[str, Any]) -> dict[str, Any]:
    endpoint = route.endpoint
    module = getattr(endpoint, "__module__", "")
    source = _source(endpoint)
    key = f"{method} {path}"
    row: dict[str, Any] = {
        "method": method,
        "path": path,
        "owner": module,
        "handler": getattr(endpoint, "__name__", ""),
        "classification": None,
        "kernel_delegate": None,
        "effectful": False,
        "provider": None,
        "scope": None,
        "capability": None,
        "adapter": None,
        "deprecation": "active",
        "justification": None,
    }
    override = overrides.get(key)
    if override:
        row.update({k: v for k, v in override.items() if k in row})
        row["source"] = "override"
        return row
    row["source"] = "derived"
    if method in READ_METHODS:
        row["classification"] = "READ_ONLY"
        return row
    for needle, delegate in KERNEL_CALLS:
        if needle in source:
            row["classification"] = "KERNEL_WRAPPER"
            row["kernel_delegate"] = delegate
            row["effectful"] = True
            if path.startswith("/platform/v1/commands") or path.startswith("/platform/v1/operations"):
                row["scope"] = "platform.command.replay" if path.endswith("/replay") else "platform.command"
            return row
    if any(re.search(pattern, path) for pattern in READ_ONLY_POSTS):
        row["classification"] = "READ_ONLY"
        row["justification"] = "computes or looks up; no durable mutation"
        return row
    if any(needle in source for needle in ("OutboxEvent(", "INSERT INTO middleware_outbox", "await _enqueue(", ".enqueue(")):
        row["classification"] = "DURABLE_OUTBOX_INTENT"
        row["effectful"] = True
        row["justification"] = "persists a durable outbox intent executed by a worker under the Settings effect gates; kernel convergence pending"
        return row
    if "_provisioning_call(" in source:
        row["classification"] = "DIRECT_INTERNAL_SERVICE"
        row["effectful"] = True
        row["provider"] = "provisioning-service"
        row["justification"] = "synchronous browser session issuance against the Codestra provisioning service (internal control service, not an external provider); convergence onto the kernel needs a product decision because the browser needs the credential in the response"
        return row
    if any(re.search(pattern, path) for pattern in INGRESS_PATTERNS):
        row["classification"] = "INTERNAL_EVENT_INGRESS"
        return row
    if "httpx" in source or "smtplib" in source or "aiosmtplib" in source:
        row["classification"] = "UNCLASSIFIED_OUTBOUND"
        row["effectful"] = True
        return row
    # A POST/PUT/PATCH/DELETE that mutates Middleware-owned state only.
    row["classification"] = "INTERNAL_EVENT_INGRESS"
    row["justification"] = "mutates Middleware-owned durable state; no provider transport in the handler"
    return row


def build() -> dict[str, Any]:
    from app.application import AppProfile, create_app

    overrides = json.loads(OVERRIDES.read_text(encoding="utf-8"))["routes"] if OVERRIDES.exists() else {}
    app = create_app(profile=AppProfile.INTEGRATION)
    rows: list[dict[str, Any]] = []
    for path, route in _routes(app):
        for method in sorted(route.methods or ()):
            rows.append(classify(method, path, route, overrides))
    edge = json.loads(EDGE_CONTRACT.read_text(encoding="utf-8")) if EDGE_CONTRACT.exists() else {"routes": []}
    for item in edge.get("routes", []):
        if item.get("classification") == "denied":
            rows.append(
                {
                    "method": item["method"],
                    "path": item["path"],
                    "owner": "deploy/public-api-route-contract.json",
                    "handler": None,
                    "classification": "DENIED_LEGACY",
                    "kernel_delegate": None,
                    "effectful": False,
                    "provider": None,
                    "scope": None,
                    "capability": None,
                    "adapter": None,
                    "deprecation": "denied",
                    "justification": "edge contract denies the path; never mounted on the integration profile",
                    "source": "edge-contract",
                }
            )
    rows.sort(key=lambda row: (row["path"], row["method"]))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    bypasses = [
        f"{row['method']} {row['path']}"
        for row in rows
        if row["effectful"] and row["classification"] not in {"KERNEL_WRAPPER", "DURABLE_OUTBOX_INTENT", "DIRECT_INTERNAL_SERVICE"}
    ]
    internal_direct = [f"{row['method']} {row['path']}" for row in rows if row["classification"] == "DIRECT_INTERNAL_SERVICE"]
    pending = [f"{row['method']} {row['path']}" for row in rows if row["classification"] == "DURABLE_OUTBOX_INTENT"]
    return {
        "schema": "codestra.middleware.route-authority.v1",
        "service": "middleware-integration-api",
        "listener_port": 8095,
        "profile": "integration",
        "summary": {
            "operations": len(rows),
            "by_classification": dict(sorted(counts.items())),
            "DIRECT_EFFECT_BYPASSES": len(bypasses),
            "direct_effect_bypasses": bypasses,
            "DIRECT_INTERNAL_SERVICE_CALLS": len(internal_direct),
            "direct_internal_service_calls": internal_direct,
            "KERNEL_CONVERGENCE_PENDING": len(pending),
            "kernel_convergence_pending": pending,
        },
        "routes": rows,
    }


def render(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when the committed report differs")
    parser.add_argument("--write", action="store_true", help="write config/route-authority-report.v1.json")
    args = parser.parse_args()
    report = build()
    text = render(report)
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != text:
            print("ROUTE_AUTHORITY=STALE", file=sys.stderr)
            return 1
        print(f"ROUTE_AUTHORITY=MATCH operations={report['summary']['operations']} DIRECT_EFFECT_BYPASSES={report['summary']['DIRECT_EFFECT_BYPASSES']}")
        return 0
    if args.write:
        OUTPUT.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
