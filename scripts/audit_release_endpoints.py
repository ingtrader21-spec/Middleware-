"""Fail-closed public-route and configured-upstream release audit.

The source mode is safe for CI. Runtime mode resolves and connects to every
configured URL-valued setting while printing only setting name, host and port.
Credentials and URL paths are never emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
from pathlib import Path
from urllib.parse import urlsplit

from app.core import route_policy
from app.core.config import settings
from app.entrypoints.integration_api import app

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "deploy/public-api-route-contract.json"
URL_SCHEMES = {
    "http": 80,
    "https": 443,
    "postgres": 5432,
    "postgresql": 5432,
    "postgresql+asyncpg": 5432,
    "redis": 6379,
    "rediss": 6379,
}


CONTRACT_HASH = ROOT / "deploy/public-api-route-contract.sha256"
# Handler-authenticated in both guards, but whether Kong/Caddy expose them is
# a separate edge decision. Listed here so the audit reports them instead of
# silently treating them as declared or as forbidden.
EDGE_EXPOSURE_UNDECIDED = frozenset(
    {
        ("POST", "/api/v1/campaign-designs/preview"),
        ("POST", "/api/v1/campaign-designs/approvals"),
    }
)


def contract_sha256(contract: dict) -> str:
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def source_audit() -> list[str]:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["schema"] == "codestra.middleware.public-api-route-contract.v2"
    assert contract["service"] == "middleware-integration-api"
    assert contract["listener_port"] == 8095
    digest = contract_sha256(contract)
    pinned = CONTRACT_HASH.read_text(encoding="utf-8").strip()
    if pinned != digest:
        raise SystemExit(
            f"public API route contract hash drift: pinned {pinned} computed {digest}"
        )
    actual: set[tuple[str, str]] = set()

    def walk(routes, prefix: str = "") -> None:
        for route in routes:
            original = getattr(route, "original_router", None)
            if original is not None:
                context = getattr(route, "include_context", None)
                walk(original.routes, prefix + (getattr(context, "prefix", "") or ""))
                continue
            path = getattr(route, "path", None)
            if path is None:
                continue
            for method in getattr(route, "methods", None) or ():
                actual.add((method.upper(), prefix + path))

    walk(app.routes)
    expected = {
        (row["method"], row["path"])
        for row in contract["routes"]
        if row["classification"] == "shared_edge"
    }
    denied = {
        (row["method"], row["path"])
        for row in contract["routes"]
        if row["classification"] == "denied"
    }
    missing = sorted(expected - actual)
    if missing:
        raise SystemExit(f"public API route contract missing routes: {missing}")
    exposed_denied = sorted(denied & actual)
    if exposed_denied:
        raise SystemExit(f"denied public API routes are mounted: {exposed_denied}")
    # Edge exposure and the in-process guard must agree route by route: every
    # contract route that names a service-JWT auth class is handler
    # authenticated, and every handler-authenticated service-JWT route is in
    # the contract (so Kong/Caddy cannot expose an unguarded path, nor hide an
    # approved one).
    for row in contract["routes"]:
        if row["classification"] != "shared_edge" or row["auth"] not in {
            "callback-jwt",
            "n8n-service-jwt",
            "odoo-service-jwt",
        }:
            continue
        sample = row["path"].replace("{campaign_id}", "CMP-PROBE").replace("{event_id}", "EVT-PROBE")
        if not route_policy.handler_authenticated(row["method"], sample):
            raise SystemExit(f"contract route is not handler authenticated: {row['method']} {row['path']}")
    policy_rows = {(r["method"], r["path"]) for r in route_policy.service_jwt_route_contract()}
    undeclared = sorted(policy_rows - expected - EDGE_EXPOSURE_UNDECIDED)
    if undeclared:
        raise SystemExit(f"service-JWT routes missing from the edge contract: {undeclared}")
    warnings = [
        f"ROUTE={method}|{path}|EDGE_EXPOSURE_UNDECIDED"
        for method, path in sorted(policy_rows & EDGE_EXPOSURE_UNDECIDED)
    ]
    for row in contract["routes"]:
        if row["classification"] != "shared_edge":
            continue
        policy = next(
            (r for r in route_policy.service_jwt_route_contract() if (r["method"], r["path"]) == (row["method"], row["path"])),
            None,
        )
        if policy and policy.get("scope") and policy["scope"] != row.get("scope"):
            raise SystemExit(f"scope drift for {row['method']} {row['path']}: contract {row.get('scope')} policy {policy['scope']}")
    return [f"ROUTE_CONTRACT_SHA256={digest}"] + [
        f"ROUTE={method}|{path}|PASS" for method, path in sorted(expected)
    ] + warnings


def configured_upstreams() -> list[tuple[str, str, int]]:
    rows: set[tuple[str, str, int]] = set()
    for name, value in settings.model_dump().items():
        if not isinstance(value, str) or not value or "://" not in value:
            continue
        if "url" not in name:
            continue
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.scheme not in URL_SCHEMES:
            raise SystemExit(f"unsupported configured upstream setting: {name}")
        port = parsed.port or URL_SCHEMES[parsed.scheme]
        rows.add((name, parsed.hostname, port))
    return sorted(rows)


def runtime_audit(timeout: float) -> list[str]:
    output: list[str] = []
    failures: list[str] = []
    for name, host, port in configured_upstreams():
        try:
            socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            with socket.create_connection((host, port), timeout=timeout):
                pass
            output.append(f"UPSTREAM={name}|{host}|{port}|DNS=PASS|TCP=PASS")
        except OSError as exc:
            output.append(
                f"UPSTREAM={name}|{host}|{port}|DNS_OR_TCP=FAIL|"
                f"ERROR={type(exc).__name__}"
            )
            failures.append(name)
    if failures:
        print("\n".join(output))
        raise SystemExit("configured upstream audit failed: " + ",".join(failures))
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    rows = source_audit()
    if args.runtime:
        rows.extend(runtime_audit(args.timeout))
    print("\n".join(rows))


if __name__ == "__main__":
    main()
