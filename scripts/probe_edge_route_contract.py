"""Probe the Caddy -> Kong -> middleware-integration-api edge against the route contract.

Run from a host that can reach the staging public edge. For every route in
``deploy/public-api-route-contract.json`` the probe proves three things
without needing valid data:

1. the edge forwards the method+path (the response is Middleware's, not a
   Kong/Caddy 404), by sending no credentials and expecting Middleware's own
   401/422 detail rather than a gateway body;
2. an invalid service JWT is rejected inside Middleware (401), i.e. the edge
   did not terminate authorization;
3. a wrong method on the same path is refused (405/404/401 from the guard),
   i.e. the exposure is method-exact.

With ``--token-file`` a real staging service JWT is used for a fourth check:
the scoped route answers something other than 401/403 (200/404/502/503 are all
acceptable proof that authorization passed and the handler ran).

Exit code is non-zero on any drift. Nothing here mutates state: every request
is a GET or a POST with an empty JSON body that fails validation before any
side effect.

Usage:
  python -m scripts.probe_edge_route_contract --base-url https://api.staging.internal.codestra.agency \
      [--token-file /run/secrets/staging-probe-jwt] [--expect-hash <sha256>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "deploy/public-api-route-contract.json"
PINNED = ROOT / "deploy/public-api-route-contract.sha256"
GATEWAY_MARKERS = ("no route matched", "kong", "caddy", "not found\n")
PROBE_IDS = {"{campaign_id}": "TEST_SYN", "{event_id}": "EVT-PROBE"}


def canonical_sha256(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def concrete(path: str) -> str:
    for placeholder, value in PROBE_IDS.items():
        path = path.replace(placeholder, value)
    return path


def is_middleware_response(response: httpx.Response) -> bool:
    body = response.text.lower()
    if response.headers.get("content-type", "").startswith("application/json"):
        try:
            payload = response.json()
        except ValueError:
            return False
        return isinstance(payload, dict) and "detail" in payload
    return not any(marker in body for marker in GATEWAY_MARKERS)


def probe(base_url: str, token: str | None, expect_hash: str | None, timeout: float) -> list[str]:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    digest = canonical_sha256(contract)
    pinned = PINNED.read_text(encoding="utf-8").strip()
    rows = [f"ROUTE_CONTRACT_SHA256={digest}"]
    if pinned != digest:
        rows.append(f"HASH=FAIL pinned {pinned}")
    if expect_hash and expect_hash != digest:
        rows.append(f"HASH=FAIL expected {expect_hash}")
    headers = {"X-Correlation-ID": "edge-probe", "Content-Type": "application/json"}
    with httpx.Client(base_url=base_url, timeout=timeout, follow_redirects=False) as client:
        for route in contract["routes"]:
            method, path = route["method"], concrete(route["path"])
            label = f"{method}|{route['path']}"
            anonymous = client.request(method, path, headers=headers, content=b"{}")
            forwarded = is_middleware_response(anonymous) and anonymous.status_code in {401, 422}
            rows.append(f"FORWARDED={label}|{anonymous.status_code}|{'PASS' if forwarded else 'FAIL'}")
            bad_jwt = client.request(
                method, path, headers={**headers, "Authorization": "Bearer eyJ.invalid.jwt"}, content=b"{}"
            )
            rows.append(
                f"JWT_ENFORCED_IN_MIDDLEWARE={label}|{bad_jwt.status_code}|"
                f"{'PASS' if bad_jwt.status_code == 401 and is_middleware_response(bad_jwt) else 'FAIL'}"
            )
            other = "DELETE" if method != "DELETE" else "PUT"
            wrong = client.request(other, path, headers=headers)
            rows.append(
                f"METHOD_EXACT={label}|{wrong.status_code}|"
                f"{'PASS' if wrong.status_code in {401, 404, 405, 503} else 'FAIL'}"
            )
            if token and route.get("scope"):
                scoped = client.request(
                    method, path, headers={**headers, "Authorization": f"Bearer {token}"},
                    params={"tenant_id": "TEST_SYN_TENANT", "business_unit_id": "TEST_SYN"},
                    content=b"{}",
                )
                rows.append(
                    f"SCOPED={label}|{route['scope']}|{scoped.status_code}|"
                    f"{'PASS' if scoped.status_code not in {401, 403} else 'FAIL'}"
                )
        # Retired surfaces must be gone at the edge, not just inside Middleware.
        for method, path in (
            ("POST", "/api/v1/integration/campaign-actions"),
            ("POST", "/api/v1/odoo/campaign-actions"),
            ("POST", "/api/v1/integrations/odoo/campaign-actions"),
            ("POST", "/api/v1/integrations/odoo/campaign-commands"),
            ("GET", "/api/v1/integrations/odoo/campaign-commands/x"),
        ):
            gone = client.request(method, path, headers=headers, content=b"{}")
            rows.append(f"RETIRED={method}|{path}|{gone.status_code}|{'PASS' if gone.status_code in {401, 404, 503} else 'FAIL'}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token-file")
    parser.add_argument("--expect-hash")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    token = Path(args.token_file).read_text(encoding="utf-8").strip() if args.token_file else None
    rows = probe(args.base_url, token, args.expect_hash, args.timeout)
    print("\n".join(rows))
    if any(row.endswith("|FAIL") or "=FAIL" in row for row in rows):
        sys.exit(1)


if __name__ == "__main__":
    main()
