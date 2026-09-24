"""Fail-closed Keycloak -> Caddy -> Kong -> Middleware edge certification runner.

Proves service identity, edge routing, authorization, scope isolation and
handler execution through the real deployed path for the four canonical
integration routes, in staging, against campaign ``TEST_SYN`` only.

Phases (each one is fail-closed; a failed phase blocks the next):

1. ``static``  - cross-repository contract validation. No network traffic.
2. ``live``    - Keycloak token minting, redacted claim matrix, the complete
                 HTTP matrix through the staging Caddy hostname, one unique
                 ``X-Correlation-ID`` per request.
3. ``logs``    - routing proof: the correlation ids must be found in the Caddy,
                 Kong, Middleware and Odoo logs, the legacy fallback must have
                 received zero test requests, and no credential may appear.
4. ``restart`` - ``--baseline-report`` compares a post-restart run against the
                 pre-restart report (contract hash, routes, scopes, results).

Credentials are read only from ``*_FILE`` environment references (a path to a
secret file). Raw secrets in the environment are refused. Tokens, client
secrets and shared secrets are never printed and never written to the report;
the report stores a SHA-256 of every response body and only redacted claims.

Exit codes: ``0`` GO, ``1`` NO_GO, ``2`` refused (preconditions not met).

Usage (from a host that can reach the staging edge):

  CERTIFY_ENVIRONMENT=staging CERTIFY_CAMPAIGN_ID=TEST_SYN \\
  CERTIFY_EDGE_BASE_URL=https://<staging-caddy-host> \\
  CERTIFY_KEYCLOAK_ISSUER=https://auth-staging.codestra.co/realms/codestra \\
  CERTIFY_EXPECTED_AUDIENCE=middleware-api \\
  CERTIFY_CLIENT_SECRET_FILE_N8N_SUBMIT=/run/secrets/test-syn-n8n-submit ... \\
  python -m scripts.certify_edge_integration --report certification.json

  python -m scripts.certify_edge_integration --static-only --report static.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "deploy/public-api-route-contract.json"
PINNED = ROOT / "deploy/public-api-route-contract.sha256"
COMPOSE = ROOT / "deploy/compose.runtime.yaml"
MAIN_SOURCE = ROOT / "app/main.py"
RUNTIME_SOURCE = ROOT / "app/entrypoints/runtime.py"
# The single request guard both entry modules install (app.application and
# app.entrypoints.runtime.add_api_runtime); it owns the route matcher.
GUARD_SOURCE = ROOT / "app/core/request_guard.py"
INTEGRATIONS_SOURCE = ROOT / "app/api/v1/integrations.py"
KEYCLOAK_DESIRED_STATE = ROOT / "deploy/keycloak/campaign-control-service-clients.v1.json"

REQUIRED_ENVIRONMENT = "staging"
REQUIRED_CAMPAIGN = "TEST_SYN"
INGRESS_SCOPES = ("n8n.results.submit", "n8n.results.read", "odoo.campaigns.read")
OUTBOUND_SCOPE = "odoo.campaign.control.read"
FORBIDDEN_SCOPE = "odoo.campaign.control.write"
PRODUCTION_HOSTS = frozenset({"api.codestra.co", "auth.codestra.co"})
PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"

# The canonical routes this mission certifies: method, path template, scope.
CANONICAL_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("POST", "/api/v1/integrations/n8n/results", "n8n.results.submit"),
    ("GET", "/api/v1/integrations/n8n/results/{event_id}", "n8n.results.read"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}", "odoo.campaigns.read"),
    (
        "GET",
        "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state",
        "odoo.campaigns.read",
    ),
)
RETIRED_PATHS: tuple[tuple[str, str], ...] = (
    ("POST", "/api/v1/integration/campaign-actions"),
    ("POST", "/api/v1/odoo/campaign-actions"),
    ("POST", "/api/v1/integrations/odoo/campaign-actions"),
    ("POST", "/api/v1/integrations/odoo/campaign-commands"),
    ("GET", "/api/v1/integrations/odoo/campaign-commands/x"),
)

# Test identities and the exact scope each one may hold.
IDENTITIES: dict[str, tuple[str, ...]] = {
    "n8n_submit": ("n8n.results.submit",),
    "n8n_read": ("n8n.results.read",),
    "odoo_reader": ("odoo.campaigns.read",),
    "wrong_audience": (),
}
OPTIONAL_IDENTITIES = ("wrong_tenant", "foreign_issuer")
DEFAULT_CLIENT_IDS = {
    "n8n_submit": "test-syn-n8n-submit",
    "n8n_read": "test-syn-n8n-read",
    "odoo_reader": "test-syn-odoo-reader",
    "wrong_audience": "test-syn-wrong-audience",
    "wrong_tenant": "test-syn-wrong-tenant",
    "foreign_issuer": "test-syn-foreign-issuer",
}

MIDDLEWARE_GUARD_DETAILS = frozenset({"unauthorized", "authentication unavailable"})
MIDDLEWARE_JWT_DETAILS = frozenset(
    {
        "bearer token required",
        "token validation failed",
        "authorized party denied",
        "required scope denied",
        "environment denied",
        "required role denied",
        "business unit denied",
        "campaign denied",
        "business-unit or service-account claim required",
        "campaign reader client is not configured",
        "Keycloak validation is not configured",
    }
)
MIDDLEWARE_SCOPE_DETAILS = frozenset(
    {"campaign scope denied", "tenant scope denied", "business-unit scope denied"}
)
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
REDACTED_CLAIMS = (
    "iss",
    "aud",
    "azp",
    "exp",
    "nbf",
    "iat",
    "scope",
    "environment",
    "tenant_id",
    "campaigns",
    "business_units",
    "typ",
)


class Refused(SystemExit):
    """Preconditions are not met; nothing was executed."""

    def __init__(self, reason: str) -> None:
        super().__init__(2)
        self.reason = reason


@dataclass
class Check:
    phase: str
    name: str
    status: str  # PASS | FAIL | SKIP
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.status == "PASS"


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    static: dict[str, Any] = field(default_factory=dict)
    tokens: dict[str, Any] = field(default_factory=dict)
    matrix: list[dict[str, Any]] = field(default_factory=list)
    routing: dict[str, Any] = field(default_factory=dict)
    restart: dict[str, Any] = field(default_factory=dict)

    def add(self, phase: str, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(phase, name, "PASS" if ok else "FAIL", detail))
        return ok

    def skip(self, phase: str, name: str, detail: str) -> None:
        # A skipped check can never certify: it is reported and counts as NO_GO.
        self.checks.append(Check(phase, name, "SKIP", detail))

    def failures(self) -> list[Check]:
        return [check for check in self.checks if check.status != "PASS"]

    def verdict(self) -> str:
        return "GO" if not self.failures() else "NO_GO"

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "codestra.middleware.edge-certification-report.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verdict": self.verdict(),
            "environment": REQUIRED_ENVIRONMENT,
            "campaign_id": REQUIRED_CAMPAIGN,
            "totals": {
                "checks": len(self.checks),
                "passed": sum(1 for c in self.checks if c.status == "PASS"),
                "failed": sum(1 for c in self.checks if c.status == "FAIL"),
                "skipped": sum(1 for c in self.checks if c.status == "SKIP"),
            },
            "checks": [check.__dict__ for check in self.checks],
            "static": self.static,
            "tokens": self.tokens,
            "matrix": self.matrix,
            "routing": self.routing,
            "restart": self.restart,
        }


# --- helpers -----------------------------------------------------------------


def canonical_sha256(document: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_text(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def redact(text: str) -> str:
    return JWT_PATTERN.sub("<redacted-jwt>", text)


def read_secret_file(reference: str, label: str) -> str:
    path = Path(reference)
    if not path.is_file():
        raise Refused(f"{label}: secret file reference is not a readable file")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise Refused(f"{label}: secret file is empty")
    return value


def concrete(template: str, campaign_id: str, event_id: str) -> str:
    return template.replace("{campaign_id}", campaign_id).replace("{event_id}", event_id)


def find_hash_pins(repo: Path, digest: str) -> list[str]:
    """Relative paths of tracked files that reference the contract digest."""
    hits: list[str] = []
    for path in repo.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix.lower() not in {".json", ".yaml", ".yml", ".sha256", ".md", ".txt", ".env", ".lua", ".caddy", ".py", ""}:
            continue
        try:
            if digest in path.read_text(encoding="utf-8", errors="ignore"):
                hits.append(path.relative_to(repo).as_posix())
        except OSError:
            continue
    return sorted(hits)


# --- preconditions -------------------------------------------------------------


@dataclass
class Settings:
    environment: str
    campaign_id: str
    tenant_id: str
    business_unit_id: str
    base_url: str
    issuer: str
    audience: str
    seeded_event_id: str
    kong_repo: Path | None
    caddy_repo: Path | None
    keycloak_repo: Path | None
    client_ids: dict[str, str]
    client_secrets: dict[str, str]
    foreign_issuer: str
    shared_secret: str | None
    expired_token: str | None
    logs: dict[str, Path]
    timeout: float
    wait_for_expiry: bool


def load_settings(env: dict[str, str], *, static_only: bool, wait_for_expiry: bool) -> Settings:
    environment = env.get("CERTIFY_ENVIRONMENT", "")
    if environment != REQUIRED_ENVIRONMENT:
        raise Refused(f"CERTIFY_ENVIRONMENT must be '{REQUIRED_ENVIRONMENT}' (got {environment!r})")
    campaign_id = env.get("CERTIFY_CAMPAIGN_ID", "")
    if campaign_id != REQUIRED_CAMPAIGN:
        raise Refused(f"CERTIFY_CAMPAIGN_ID must be '{REQUIRED_CAMPAIGN}' (got {campaign_id!r})")
    # Raw secrets in the environment are never an approved source.
    raw = sorted(
        name
        for name in env
        if name.startswith("CERTIFY_")
        and any(marker in name for marker in ("SECRET", "TOKEN", "PASSWORD"))
        and "_FILE" not in name
    )
    if raw:
        raise Refused("raw credentials in the environment are refused; use *_FILE references: " + ",".join(raw))

    base_url = env.get("CERTIFY_EDGE_BASE_URL", "").rstrip("/")
    issuer = env.get("CERTIFY_KEYCLOAK_ISSUER", "").rstrip("/")
    if not static_only:
        host = urlsplit(base_url).hostname or ""
        if not base_url.startswith("https://") or not host:
            raise Refused("CERTIFY_EDGE_BASE_URL must be an https:// staging edge URL")
        if host in PRODUCTION_HOSTS or "staging" not in host:
            raise Refused(f"CERTIFY_EDGE_BASE_URL host {host!r} is not a staging edge hostname")
        if not issuer.startswith("https://") or issuer == PRODUCTION_ISSUER or "staging" not in issuer:
            raise Refused("CERTIFY_KEYCLOAK_ISSUER must be the staging realm issuer")

    def repo(name: str) -> Path | None:
        value = env.get(name, "")
        if not value:
            return None
        path = Path(value)
        return path if path.is_dir() else None

    client_ids = {
        key: env.get(f"CERTIFY_CLIENT_ID_{key.upper()}", DEFAULT_CLIENT_IDS[key])
        for key in (*IDENTITIES, *OPTIONAL_IDENTITIES)
    }
    client_secrets: dict[str, str] = {}
    if not static_only:
        for key in IDENTITIES:
            reference = env.get(f"CERTIFY_CLIENT_SECRET_FILE_{key.upper()}", "")
            if not reference:
                raise Refused(f"CERTIFY_CLIENT_SECRET_FILE_{key.upper()} is required")
            client_secrets[key] = read_secret_file(reference, key)
        for key in OPTIONAL_IDENTITIES:
            reference = env.get(f"CERTIFY_CLIENT_SECRET_FILE_{key.upper()}", "")
            if reference:
                client_secrets[key] = read_secret_file(reference, key)

    shared = env.get("CERTIFY_SHARED_SECRET_FILE", "")
    expired = env.get("CERTIFY_EXPIRED_TOKEN_FILE", "")
    logs = {
        name: Path(env[f"CERTIFY_{name.upper()}_LOG"])
        for name in ("caddy", "kong", "middleware", "odoo")
        if env.get(f"CERTIFY_{name.upper()}_LOG")
    }
    return Settings(
        environment=environment,
        campaign_id=campaign_id,
        tenant_id=env.get("CERTIFY_TENANT_ID", "TEST_SYN_TENANT"),
        business_unit_id=env.get("CERTIFY_BUSINESS_UNIT_ID", "TEST_SYN"),
        base_url=base_url,
        issuer=issuer,
        audience=env.get("CERTIFY_EXPECTED_AUDIENCE", "middleware-api"),
        seeded_event_id=env.get("CERTIFY_SEEDED_EVENT_ID", ""),
        kong_repo=repo("CERTIFY_KONG_REPO"),
        caddy_repo=repo("CERTIFY_CADDY_REPO"),
        keycloak_repo=repo("CERTIFY_KEYCLOAK_REPO"),
        client_ids=client_ids,
        client_secrets=client_secrets,
        foreign_issuer=env.get("CERTIFY_FOREIGN_KEYCLOAK_ISSUER", "").rstrip("/"),
        shared_secret=read_secret_file(shared, "shared secret") if shared else None,
        expired_token=read_secret_file(expired, "expired token") if expired else None,
        logs=logs,
        timeout=float(env.get("CERTIFY_HTTP_TIMEOUT", "10")),
        wait_for_expiry=wait_for_expiry,
    )


# --- phase 1: static contract validation -------------------------------------


def static_middleware(report: Report) -> str | None:
    phase = "static.middleware"
    if not report.add(phase, "contract_present", CONTRACT.is_file() and PINNED.is_file(), str(CONTRACT)):
        return None
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    digest = canonical_sha256(contract)
    pinned = PINNED.read_text(encoding="utf-8").strip()
    report.static["middleware"] = {"contract_sha256": digest, "pinned_sha256": pinned}
    report.add(phase, "contract_hash_pinned", pinned == digest, f"pinned={pinned} computed={digest}")

    rows = {(r["method"], r["path"]): r.get("scope") for r in contract["routes"]}
    for method, path, scope in CANONICAL_ROUTES:
        report.add(
            phase,
            f"contract_route:{method} {path}",
            rows.get((method, path)) == scope,
            f"expected scope {scope}, contract has {rows.get((method, path))!r}",
        )
    report.add(
        phase,
        "contract_has_no_write_scope",
        FORBIDDEN_SCOPE not in json.dumps(contract),
        FORBIDDEN_SCOPE,
    )

    compose = COMPOSE.read_text(encoding="utf-8") if COMPOSE.is_file() else ""
    report.add(
        phase,
        "compose_deploys_integration_api",
        "app.entrypoints.integration_api" in compose and "middleware-integration-api:" in compose,
        str(COMPOSE),
    )
    main_src = MAIN_SOURCE.read_text(encoding="utf-8")
    runtime_src = RUNTIME_SOURCE.read_text(encoding="utf-8")
    guard_src = GUARD_SOURCE.read_text(encoding="utf-8") if GUARD_SOURCE.is_file() else ""
    shared_call = "route_policy.handler_authenticated(method, path)"
    report.add(
        phase,
        "both_entrypoints_share_route_matcher",
        "from app.core import route_policy" in guard_src
        and shared_call in guard_src
        and "def install_request_guard(" in guard_src
        # Both entry modules build on the single guard and keep no matcher.
        and "from app.application import" in main_src
        and "install_request_guard(" in runtime_src
        and not any(
            marker in src
            for src in (main_src, runtime_src, guard_src)
            for marker in ("N8N_SERVICE_JWT_ROUTES = ", "INTEGRATION_SERVICE_JWT_ROUTES = ", "CALLBACK_JWT_PATH = ")
        )
        and not any("verify_bearer(" in src for src in (main_src, runtime_src)),
        "app.core.request_guard must be the single guard, import app.core.route_policy and keep no local copy",
    )
    report.add(
        phase,
        "retired_paths_absent_from_sources",
        not any(
            marker in src for src in (main_src, runtime_src) for marker in ("campaign-actions", "campaign-commands")
        ),
        "campaign-actions / campaign-commands",
    )
    # The n8n service-JWT validator must accept staging-minted tokens and the
    # separate submit/read identities this certification uses.
    integrations_src = INTEGRATIONS_SOURCE.read_text(encoding="utf-8") if INTEGRATIONS_SOURCE.is_file() else ""
    n8n_block = integrations_src.split("def _authenticate_n8n", 1)[-1].split("def ", 1)[0]
    report.add(
        phase,
        "n8n_validator_environment_not_hardcoded_production",
        'required_environment="production"' not in n8n_block,
        "_authenticate_n8n pins required_environment=\"production\"; staging tokens (environment=staging) are refused with 401 environment denied",
    )
    report.add(
        phase,
        "n8n_validator_accepts_separate_submit_and_read_identities",
        "frozenset({settings.n8n_campaign_service_client_id})" not in n8n_block,
        "_authenticate_n8n authorizes exactly one azp (n8n_campaign_service_client_id); test-syn-n8n-submit and test-syn-n8n-read cannot both be authorized",
    )

    # Route policy and the deployed application factory agree with the contract.
    try:
        from app.core import route_policy  # noqa: WPS433 (runtime import keeps --static-only light)
        from app.entrypoints.integration_api import app as integration_app
        from app.main import app as main_app
    except Exception as exc:  # pragma: no cover - import failure is itself a finding
        report.add(phase, "application_import", False, f"{type(exc).__name__}: {exc}")
        return digest
    policy_rows = {(r["method"], r["path"]): r.get("scope") for r in route_policy.service_jwt_route_contract()}
    for method, path, scope in CANONICAL_ROUTES:
        report.add(
            phase,
            f"route_policy:{method} {path}",
            policy_rows.get((method, path), None) in (scope, None) and (method, path) in policy_rows,
            f"policy scope {policy_rows.get((method, path))!r}",
        )

    def route_table(application: Any) -> set[tuple[str, str]]:
        table: set[tuple[str, str]] = set()

        def walk(routes: Any, prefix: str = "") -> None:
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
                    table.add((method.upper(), prefix + path))

        walk(application.routes)
        return table

    tables = {"integration_api": route_table(integration_app), "main": route_table(main_app)}
    for name, table in tables.items():
        for method, path, _scope in CANONICAL_ROUTES:
            report.add(phase, f"{name}_declares:{method} {path}", (method, path) in table)
        report.add(
            phase,
            f"{name}_has_no_retired_paths",
            not any("campaign-actions" in p or "campaign-commands" in p for _m, p in table),
        )

    # Every integration route is classified. shared_edge = in the edge
    # contract; denied = retired surface; private_only = everything else.
    classification: dict[str, str] = {}
    contract_paths = {(m, p) for m, p in rows}
    for method, path in sorted(tables["integration_api"] | tables["main"]):
        if not path.startswith("/api/v1/integrations/"):
            continue
        if "campaign-actions" in path or "campaign-commands" in path:
            classification[f"{method} {path}"] = "denied"
        elif (method, path) in contract_paths:
            classification[f"{method} {path}"] = "shared_edge"
        else:
            classification[f"{method} {path}"] = "private_only"
    report.static["middleware"]["integration_route_classification"] = classification
    report.add(
        phase,
        "every_integration_route_classified",
        all(v in {"shared_edge", "private_only", "denied"} for v in classification.values())
        and not any(v == "denied" for v in classification.values()),
        f"{len(classification)} integration routes classified; denied routes must not exist in the app",
    )
    return digest


def static_kong(report: Report, repo: Path | None, digest: str | None) -> None:
    phase = "static.kong"
    if repo is None:
        report.skip(phase, "repository", "CERTIFY_KONG_REPO not set or not a directory")
        return
    pins = find_hash_pins(repo, digest) if digest else []
    report.static["kong"] = {"repo": str(repo), "contract_hash_pins": pins}
    report.add(phase, "edge_contract_hash_pinned", bool(pins), f"files referencing {digest}: {pins or 'none'}")

    canonical = repo / "config/kong-canonical-middleware-routes.json"
    if not report.add(phase, "canonical_routes_present", canonical.is_file(), str(canonical)):
        return
    document = json.loads(canonical.read_text(encoding="utf-8"))
    declared: dict[tuple[str, str], dict[str, Any]] = {}
    for route in document.get("contractRoutes", []):
        authority = repo / route.get("securityAuthority", "")
        scope = None
        if authority.is_file():
            manifest = json.loads(authority.read_text(encoding="utf-8"))
            for row in manifest.get("routes", []):
                same_path = row.get("path") in route.get("paths", []) or (
                    row.get("path") == route.get("pathTemplate")
                )
                same_method = row.get("method") in (None, *route.get("methods", []))
                if same_path and same_method:
                    scope = row.get("scope")
        for method in route.get("methods", []):
            for path in route.get("paths", []):
                # Path-parameter routes are regex paths in Kong (~/.../[...]$) and
                # carry the Middleware template alongside so the two can be matched.
                template = route.get("pathTemplate", path)
                declared[(method, template)] = {
                    "name": route.get("name"),
                    "kong_path": path,
                    "service": f"{route.get('serviceHost')}:{route.get('servicePort')}",
                    "scope": scope,
                    "plugins": route.get("requiredPlugins", []),
                }
    report.static["kong"]["declared_routes"] = {f"{m} {p}": v for (m, p), v in declared.items()}

    for method, template, scope in CANONICAL_ROUTES:
        entry = declared.get((method, template))
        ok = entry is not None and entry.get("scope") == scope
        report.add(
            phase,
            f"declares:{method} {template}",
            ok,
            "absent" if not entry else f"scope={entry.get('scope')!r} service={entry.get('service')} plugins={entry.get('plugins')}",
        )
        if entry:
            kong_path = entry["kong_path"]
            sample = concrete(template, "TEST_SYN", "EVT-TEST-SYN-0001")
            if kong_path.startswith("~"):
                pattern = re.compile(kong_path[1:])
                exact = pattern.fullmatch(sample) is not None and all(
                    pattern.fullmatch(extra) is None for extra in (sample + "/other", sample + "/", sample.rsplit("/", 1)[0] + "/")
                )
            else:
                exact = kong_path == template
            report.add(
                phase,
                f"path_is_exact:{method} {template}",
                exact,
                f"kong path {kong_path!r} must admit {sample} and nothing longer or shorter",
            )
            report.add(
                phase,
                f"jwt_and_scope_guard:{method} {template}",
                {"post-function", "correlation-id"}
                <= set(entry.get("plugins", []))
                and bool(
                    {"jwt", "openid-connect"}
                    & set(entry.get("plugins", []))
                ),
                str(entry.get("plugins")),
            )
    certified_keys = {(method, path) for method, path, _scope in CANONICAL_ROUTES}
    services = {
        entry["service"]
        for key, entry in declared.items()
        if key in certified_keys
    }
    report.add(
        phase,
        "campaign_routes_share_one_middleware_service",
        len(services) == 1,
        f"services={sorted(services)}",
    )
    report.add(
        phase,
        "no_retired_paths_declared",
        not any("campaign-actions" in p or "campaign-commands" in p for _m, p in declared),
    )


UPSTREAM_LABELS = {
    "CADDY_KONG_UPSTREAM": "kong",
    "CADDY_LEGACY_API_UPSTREAM": "legacy_fallback",
    "CADDY_REALTIME_UPSTREAM": "realtime",
}


def parse_caddy_site(site_source: str) -> tuple[dict[str, dict[str, list[str]]], list[tuple[str | None, str | None]]]:
    """Named matchers (single-line and block form) and ordered ``handle`` blocks.

    Returns ``({matcher: {"path": [...], "method": [...]}}, [(matcher, upstream_var)])``
    where a ``None`` matcher is the unconditional fallback ``handle {``.
    """
    matchers: dict[str, dict[str, list[str]]] = {}
    handles: list[list[str | None]] = []
    block: str | None = None
    for raw in site_source.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if block is not None:
            if line == "}":
                block = None
                continue
            inline = re.match(r"(path|method)\s+(.+)$", line)
            if inline:
                matchers[block].setdefault(inline.group(1), []).extend(inline.group(2).split())
            continue
        single = re.match(r"@([A-Za-z0-9_]+)\s+(path|method)\s+(.+)$", line)
        if single:
            matchers.setdefault(single.group(1), {}).setdefault(single.group(2), []).extend(single.group(3).split())
            continue
        opened = re.match(r"@([A-Za-z0-9_]+)\s*\{$", line)
        if opened:
            block = opened.group(1)
            matchers.setdefault(block, {})
            continue
        handle = re.match(r"handle(?:\s+@([A-Za-z0-9_]+))?\s*\{$", line)
        if handle:
            handles.append([handle.group(1), None])
            continue
        proxy = re.match(r"reverse_proxy\s+\{\$([A-Za-z0-9_]+)\}", line)
        if proxy and handles and handles[-1][1] is None:
            handles[-1][1] = proxy.group(1)
    return matchers, [(name, upstream) for name, upstream in handles]


def caddy_path_matches(tokens: list[str], path: str) -> bool:
    lowered = path.lower()
    for token in tokens:
        pattern = token.lower()
        if (pattern.endswith("*") and lowered.startswith(pattern[:-1])) or lowered == pattern:
            return True
    return False


def caddy_decision(site_source: str, method: str, path: str) -> tuple[str, str | None, bool]:
    """(upstream label, matcher name, matcher declares a method list) for a request."""
    matchers, handles = parse_caddy_site(site_source)
    for name, upstream in handles:
        if name is None:
            return UPSTREAM_LABELS.get(upstream or "", upstream or "unrouted"), None, False
        matcher = matchers.get(name, {})
        paths = matcher.get("path")
        methods = matcher.get("method")
        if paths and not caddy_path_matches(paths, path):
            continue
        if methods and method.upper() not in {m.upper() for m in methods}:
            continue
        return UPSTREAM_LABELS.get(upstream or "", upstream or "unrouted"), name, bool(methods)
    return "unrouted", None, False


def caddy_upstream(site_source: str, method: str, path: str) -> str:
    return caddy_decision(site_source, method, path)[0]


def static_caddy(report: Report, repo: Path | None, digest: str | None, campaign_id: str) -> None:
    phase = "static.caddy"
    if repo is None:
        report.skip(phase, "repository", "CERTIFY_CADDY_REPO not set or not a directory")
        return
    pins = find_hash_pins(repo, digest) if digest else []
    report.static["caddy"] = {"repo": str(repo), "contract_hash_pins": pins}
    report.add(phase, "edge_contract_hash_pinned", bool(pins), f"files referencing {digest}: {pins or 'none'}")
    site = repo / "sites/api.codestra.co.caddy"
    if not report.add(phase, "shared_edge_site_present", site.is_file(), str(site)):
        return
    source = site.read_text(encoding="utf-8")
    decisions: dict[str, str] = {}
    for method, template, _scope in CANONICAL_ROUTES:
        path = concrete(template, campaign_id, "EVT-TEST-SYN-PROBE")
        decision, matcher, has_methods = caddy_decision(source, method, path)
        decisions[f"{method} {template}"] = decision
        report.add(phase, f"forwards_to_kong:{method} {template}", decision == "kong", f"caddy -> {decision} via @{matcher}")
        report.add(
            phase,
            f"matcher_declares_method:{method} {template}",
            decision == "kong" and has_methods,
            f"@{matcher} must include an HTTP method matcher",
        )
        wrong = "DELETE"
        decisions[f"{wrong} {template}"] = caddy_upstream(source, wrong, path)
        report.add(
            phase,
            f"wrong_method_never_reaches_legacy:{wrong} {template}",
            decisions[f"{wrong} {template}"] != "legacy_fallback",
            f"caddy -> {decisions[f'{wrong} {template}']}",
        )
    for method, path in RETIRED_PATHS:
        decision = caddy_upstream(source, method, path)
        decisions[f"{method} {path}"] = decision
        report.add(phase, f"retired_never_reaches_legacy:{method} {path}", decision != "legacy_fallback", f"caddy -> {decision}")
    report.static["caddy"]["decisions"] = decisions
    _matchers, handles = parse_caddy_site(source)
    kong_positions = [i for i, (name, upstream) in enumerate(handles) if name and upstream == "CADDY_KONG_UPSTREAM"]
    fallback_positions = [i for i, (name, _u) in enumerate(handles) if name is None]
    report.add(
        phase,
        "kong_handles_precede_legacy_fallback",
        bool(kong_positions) and (not fallback_positions or max(kong_positions) < min(fallback_positions)),
        f"kong handles at {kong_positions}, fallback at {fallback_positions}",
    )
    report.add(
        phase,
        "access_log_drops_authorization_header",
        "request>headers>Authorization delete" in source,
    )


def static_keycloak(
    report: Report,
    repo: Path | None,
    digest: str | None,
    client_ids: dict[str, str],
    audience: str,
) -> None:
    phase = "static.keycloak"
    if repo is None:
        report.skip(phase, "repository", "CERTIFY_KEYCLOAK_REPO not set or not a directory")
        return
    pins = find_hash_pins(repo, digest) if digest else []
    report.static["keycloak"] = {"repo": str(repo), "contract_hash_pins": pins}
    report.add(phase, "edge_contract_hash_pinned", bool(pins), f"files referencing {digest}: {pins or 'none'}")

    scopes_defined: dict[str, list[str]] = {scope: [] for scope in INGRESS_SCOPES}
    clients: dict[str, dict[str, Any]] = {}
    for path in sorted((repo / "config").rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        relative = path.relative_to(repo).as_posix()
        text = json.dumps(document)
        for scope in INGRESS_SCOPES:
            if scope in text:
                scopes_defined[scope].append(relative)
        if isinstance(document, dict) and "clientId" in document:
            clients[document["clientId"]] = document
    report.static["keycloak"]["ingress_scope_definitions"] = scopes_defined
    for scope in INGRESS_SCOPES:
        report.add(phase, f"scope_defined:{scope}", bool(scopes_defined[scope]), f"defined in {scopes_defined[scope] or 'nothing'}")

    def granted_scopes(client: dict[str, Any]) -> set[str]:
        granted: set[str] = set(client.get("defaultClientScopes", []) or [])
        for mapper in client.get("protocolMappers", []) or []:
            config = mapper.get("config", {})
            if config.get("claim.name") == "scope":
                granted |= set(str(config.get("claim.value", "")).split())
        return granted

    def granted_audiences(client: dict[str, Any]) -> set[str]:
        return {
            str(mapper.get("config", {}).get("included.custom.audience"))
            for mapper in client.get("protocolMappers", []) or []
            if mapper.get("protocolMapper") == "oidc-audience-mapper"
            and mapper.get("config", {}).get("included.custom.audience")
        }

    for key, expected in IDENTITIES.items():
        client_id = client_ids[key]
        client = clients.get(client_id)
        if client is None:
            report.add(phase, f"client_defined:{client_id}", False, "absent from config/clients")
            continue
        granted = granted_scopes(client)
        report.add(
            phase,
            f"client_scopes_exact:{client_id}",
            granted & set(INGRESS_SCOPES) == set(expected) and FORBIDDEN_SCOPE not in granted,
            f"granted ingress scopes {sorted(granted & set(INGRESS_SCOPES))}, expected {list(expected)}",
        )
        report.add(
            phase,
            f"client_is_confidential_service_account:{client_id}",
            client.get("serviceAccountsEnabled") is True
            and client.get("publicClient") is False
            and client.get("fullScopeAllowed") is False
            and not client.get("standardFlowEnabled")
            and not client.get("directAccessGrantsEnabled"),
        )
        audiences = granted_audiences(client)
        audience_is_correct = (
            len(audiences) == 1 and audience not in audiences
            if key == "wrong_audience"
            else audiences == {audience}
        )
        report.add(
            phase,
            f"client_audience_exact:{client_id}",
            audience_is_correct,
            f"granted audiences {sorted(audiences)}, canonical {audience!r}; "
            f"negative client must have exactly one non-canonical audience",
        )
    realm = repo / "config/realms/codestra.json"
    if realm.is_file():
        realm_document = json.loads(realm.read_text(encoding="utf-8"))
        realm_defaults = set(realm_document.get("defaultDefaultClientScopes", []) or []) | set(
            realm_document.get("defaultOptionalClientScopes", []) or []
        )
        report.add(
            phase,
            "no_realm_wide_ingress_scope",
            not (realm_defaults & set(INGRESS_SCOPES)),
            f"realm default scopes {sorted(realm_defaults)}",
        )
    report.add(
        phase,
        "no_client_holds_forbidden_write_scope",
        not any(FORBIDDEN_SCOPE in granted_scopes(c) for c in clients.values()),
        FORBIDDEN_SCOPE,
    )


def static_desired_state(report: Report, settings: Settings) -> None:
    phase = "static.desired_state"
    if not KEYCLOAK_DESIRED_STATE.is_file():
        report.skip(phase, "middleware_keycloak_desired_state", str(KEYCLOAK_DESIRED_STATE))
        return
    document = json.loads(KEYCLOAK_DESIRED_STATE.read_text(encoding="utf-8"))
    staging = document.get("environments", {}).get("staging", {})
    report.add(
        phase,
        "forbidden_write_grant_declared",
        any(f.get("scope") == FORBIDDEN_SCOPE for f in document.get("forbidden_grants", [])),
    )
    report.add(
        phase,
        "no_staging_client_holds_write_scope",
        not any(FORBIDDEN_SCOPE in c.get("scopes", []) for c in staging.get("clients", [])),
    )
    report.add(
        phase,
        "outbound_scope_is_separate_direction",
        all(
            OUTBOUND_SCOPE not in c.get("scopes", []) or c.get("direction") == "middleware_to_odoo"
            for c in staging.get("clients", [])
        ),
        f"{OUTBOUND_SCOPE} only on middleware_to_odoo clients",
    )
    if settings.issuer:
        report.add(
            phase,
            "desired_state_issuer_matches_certified_issuer",
            staging.get("issuer", "").rstrip("/") == settings.issuer,
            f"desired-state {staging.get('issuer')!r} vs certified {settings.issuer!r}",
        )
    report.add(
        phase,
        "desired_state_audience_matches_canonical_audience",
        {
            client.get("audience")
            for client in staging.get("clients", [])
            if client.get("direction")
            in {"n8n_to_middleware", "caller_to_middleware"}
        }
        == {settings.audience}
        and {
            staging.get("middleware_settings", {}).get("N8N_SERVICE_AUDIENCE"),
            staging.get("middleware_settings", {}).get("KEYCLOAK_AUDIENCE"),
        }
        == {settings.audience},
        f"canonical Middleware audience must be exactly {settings.audience!r}",
    )


def run_static(report: Report, settings: Settings) -> None:
    digest = static_middleware(report)
    static_kong(report, settings.kong_repo, digest)
    static_caddy(report, settings.caddy_repo, digest, settings.campaign_id)
    static_keycloak(
        report,
        settings.keycloak_repo,
        digest,
        settings.client_ids,
        settings.audience,
    )
    static_desired_state(report, settings)
    hashes = {
        name: (report.static.get(name, {}).get("contract_hash_pins") or None)
        for name in ("kong", "caddy", "keycloak")
    }
    report.add(
        "static",
        "all_four_components_pin_identical_contract_hash",
        bool(digest) and all(hashes.values()),
        f"middleware={digest} pins={hashes}",
    )


# --- phase 2: tokens -----------------------------------------------------------


class TokenError(RuntimeError):
    pass


def mint_token(client: Any, issuer: str, client_id: str, secret: str, timeout: float) -> str:
    response = client.post(
        f"{issuer}/protocol/openid-connect/token",
        data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret},
        timeout=timeout,
    )
    if response.status_code != 200:
        raise TokenError(f"{client_id}: token endpoint answered {response.status_code}")
    token = response.json().get("access_token", "")
    if not token or token.count(".") != 2:
        raise TokenError(f"{client_id}: token endpoint returned no access token")
    return token


def decode_claims(token: str, jwks_url: str | None) -> dict[str, Any]:
    import jwt  # PyJWT

    if jwks_url:
        key = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300).get_signing_key_from_jwt(token)
        return jwt.decode(token, key.key, algorithms=["RS256"], options={"verify_aud": False, "verify_exp": False})
    return jwt.decode(token, options={"verify_signature": False})


def redacted_claims(claims: dict[str, Any]) -> dict[str, Any]:
    view = {name: claims.get(name) for name in REDACTED_CLAIMS if name in claims}
    if "sub" in claims:
        view["sub_sha256"] = sha256_text(str(claims["sub"]))[:16]
    return view


def tamper(token: str) -> str:
    head, body, signature = token.split(".")
    flipped = ("A" if signature[-1] != "A" else "B") + signature[1:]
    return f"{head}.{body}.{flipped[::-1]}"


def mint_all(report: Report, settings: Settings, client: Any) -> dict[str, str]:
    phase = "tokens"
    tokens: dict[str, str] = {}
    jwks = f"{settings.issuer}/protocol/openid-connect/certs"
    now = int(time.time())
    for key, expected_scopes in IDENTITIES.items():
        client_id = settings.client_ids[key]
        try:
            token = mint_token(client, settings.issuer, client_id, settings.client_secrets[key], settings.timeout)
            claims = decode_claims(token, jwks)
        except Exception as exc:  # noqa: BLE001 - every failure is a certification finding
            report.add(phase, f"mint:{client_id}", False, redact(f"{type(exc).__name__}: {exc}"))
            continue
        tokens[key] = token
        view = redacted_claims(claims)
        report.tokens[client_id] = view
        audiences = claims.get("aud")
        audiences = audiences if isinstance(audiences, list) else [audiences]
        granted = set(str(claims.get("scope", "")).split())
        report.add(phase, f"iss:{client_id}", claims.get("iss") == settings.issuer, str(view.get("iss")))
        if key == "wrong_audience":
            report.add(phase, f"aud_excludes_middleware:{client_id}", settings.audience not in audiences, str(audiences))
        else:
            report.add(phase, f"aud_includes_middleware:{client_id}", settings.audience in audiences, str(audiences))
        report.add(
            phase,
            f"exp_nbf_valid:{client_id}",
            int(claims.get("exp", 0)) > now and int(claims.get("nbf", 0)) <= now + 5,
            f"exp-now={int(claims.get('exp', 0)) - now}s nbf={claims.get('nbf')}",
        )
        report.add(
            phase,
            f"scope_exact:{client_id}",
            granted & set(INGRESS_SCOPES) == set(expected_scopes) and FORBIDDEN_SCOPE not in granted,
            f"ingress scopes granted {sorted(granted & set(INGRESS_SCOPES))}, expected {list(expected_scopes)}",
        )
        report.add(phase, f"azp:{client_id}", claims.get("azp") == client_id, str(claims.get("azp")))
    for key in OPTIONAL_IDENTITIES:
        if key not in settings.client_secrets:
            continue
        issuer = settings.foreign_issuer if key == "foreign_issuer" else settings.issuer
        if not issuer:
            report.skip(phase, f"mint:{settings.client_ids[key]}", "CERTIFY_FOREIGN_KEYCLOAK_ISSUER not set")
            continue
        try:
            tokens[key] = mint_token(client, issuer, settings.client_ids[key], settings.client_secrets[key], settings.timeout)
            report.tokens[settings.client_ids[key]] = redacted_claims(decode_claims(tokens[key], None))
        except Exception as exc:  # noqa: BLE001
            report.add(phase, f"mint:{settings.client_ids[key]}", False, redact(f"{type(exc).__name__}: {exc}"))
    return tokens


# --- phase 3: live matrix ------------------------------------------------------


@dataclass
class Case:
    name: str
    method: str
    path: str
    expected: tuple[int, ...]
    token: str | None  # key into the token map, "shared_secret", "expired", "tampered", or None
    expected_layers: tuple[str, ...]
    body: dict[str, Any] | None = None
    params: dict[str, str] | None = None
    compare_body_to: str | None = None


def attribute_layer(status: int, headers: dict[str, str], body: str) -> str:
    """Decide which layer produced a response from its headers and body shape."""
    lowered = {k.lower(): v for k, v in headers.items()}
    kong = "x-kong-request-id" in lowered or "x-kong-response-latency" in lowered
    kong_upstream = "x-kong-upstream-latency" in lowered or "x-kong-proxy-latency" in lowered
    try:
        payload = json.loads(body) if body else None
    except ValueError:
        payload = None
    detail = payload.get("detail") if isinstance(payload, dict) else None
    detail_text = detail if isinstance(detail, str) else json.dumps(detail) if detail is not None else None
    if isinstance(payload, dict) and detail_text is not None and (kong_upstream or "x-correlation-id" in lowered):
        if detail_text in MIDDLEWARE_GUARD_DETAILS:
            return "middleware.shared_secret_guard"
        if detail_text in MIDDLEWARE_JWT_DETAILS:
            return "middleware.jwt"
        if detail_text in MIDDLEWARE_SCOPE_DETAILS:
            return "middleware.scope"
        return "middleware.handler"
    if kong and not kong_upstream:
        if isinstance(payload, dict) and "error" in payload:
            return "kong.scope_guard" if payload.get("error") in {"insufficient_scope", "service_identity_denied"} else "kong.jwt"
        if isinstance(payload, dict) and payload.get("message") == "Unauthorized":
            return "kong.jwt"
        if isinstance(payload, dict) and "no route matched" in str(payload.get("message", "")).lower():
            return "kong.no_route"
        return "kong"
    if kong_upstream:
        return "middleware.handler"
    if "via" in lowered and "caddy" in lowered["via"].lower():
        return "caddy"
    return "legacy_or_unknown"


def build_matrix(settings: Settings, event_id: str, submit_event_id: str) -> list[Case]:
    submit_body = {
        "event_id": submit_event_id,
        "correlation_id": f"certify-{submit_event_id}",
        "idempotency_key": f"result:{submit_event_id}:1",
        "workflow_key": "test_syn_certification",
        "execution_id": f"exec-{submit_event_id}",
        "status": "COMPLETED",
        "actions": [],
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    campaign = settings.campaign_id
    params = {"tenant_id": settings.tenant_id, "business_unit_id": settings.business_unit_id}
    results = "/api/v1/integrations/n8n/results"
    read = f"{results}/{event_id}"
    campaign_read = f"/api/v1/integrations/odoo/campaigns/{campaign}"
    desired = f"{campaign_read}/desired-state"
    handler = ("middleware.handler",)
    jwt_layers = ("kong.jwt", "middleware.jwt")
    scope_layers = ("kong.scope_guard", "middleware.jwt", "middleware.scope")
    return [
        Case("submit_n8n_result", "POST", results, (202,), "n8n_submit", handler, submit_body),
        Case("read_seeded_result", "GET", read, (200,), "n8n_read", handler),
        Case("read_missing_result", "GET", f"{results}/EVT-MISSING-{uuid4().hex[:8]}", (404,), "n8n_read", handler),
        Case("submit_token_reads_result", "GET", read, (403,), "n8n_submit", scope_layers),
        Case("read_token_submits_result", "POST", results, (403,), "n8n_read", scope_layers, submit_body),
        Case("read_campaign", "GET", campaign_read, (200,), "odoo_reader", handler, None, params),
        Case("read_desired_state", "GET", desired, (200,), "odoo_reader", handler, None, params),
        Case("n8n_token_reads_campaign", "GET", campaign_read, (403,), "n8n_read", scope_layers, None, params),
        Case("odoo_token_reads_n8n_result", "GET", read, (403,), "odoo_reader", scope_layers),
        Case("missing_token", "GET", read, (401,), None, jwt_layers),
        Case("shared_secret_only", "GET", read, (401,), "shared_secret", jwt_layers),
        Case("expired_token", "GET", read, (401,), "expired", jwt_layers),
        Case("tampered_token", "GET", read, (401,), "tampered", jwt_layers),
        Case("wrong_issuer", "GET", read, (401,), "foreign_issuer", jwt_layers),
        Case("wrong_audience", "GET", read, (401,), "wrong_audience", jwt_layers),
        Case("cross_tenant_event", "GET", read, (404,), "wrong_tenant", handler, compare_body_to="read_missing_result"),
        Case("cross_tenant_campaign", "GET", campaign_read, (403, 404), "wrong_tenant", ("middleware.scope", "middleware.handler"), None, params),
        Case("wrong_method_on_get_route", "DELETE", read, (404, 405), "n8n_read", ("kong.no_route", "kong", "middleware.handler")),
        Case("retired_campaign_actions", "POST", "/api/v1/integrations/odoo/campaign-actions", (404,), "n8n_submit", ("kong.no_route", "kong", "middleware.handler"), {}),
        Case("retired_campaign_commands", "POST", "/api/v1/integrations/odoo/campaign-commands", (404,), "n8n_submit", ("kong.no_route", "kong", "middleware.handler"), {}),
    ]


def run_matrix(report: Report, settings: Settings, client: Any, tokens: dict[str, str], cases: list[Case]) -> None:
    phase = "live"
    bodies: dict[str, str] = {}
    if "n8n_submit" in tokens:
        tokens = {**tokens, "tampered": tamper(tokens["n8n_submit"])}
    if settings.expired_token:
        tokens = {**tokens, "expired": settings.expired_token}
    for case in cases:
        correlation_id = str(uuid4())
        headers = {"X-Correlation-ID": correlation_id, "Accept": "application/json"}
        if case.token == "shared_secret":
            if not settings.shared_secret:
                report.skip(phase, case.name, "CERTIFY_SHARED_SECRET_FILE not provided")
                continue
            headers["Authorization"] = f"Bearer {settings.shared_secret}"
        elif case.token is not None:
            if case.token not in tokens:
                report.skip(phase, case.name, f"no token for identity {case.token!r}")
                continue
            headers["Authorization"] = f"Bearer {tokens[case.token]}"
        started = time.perf_counter()
        try:
            response = client.request(
                case.method,
                f"{settings.base_url}{case.path}",
                headers=headers,
                params=case.params,
                json=case.body,
                timeout=settings.timeout,
            )
        except Exception as exc:  # noqa: BLE001
            report.matrix.append({"test": case.name, "correlation_id": correlation_id, "error": redact(f"{type(exc).__name__}: {exc}")})
            report.add(phase, case.name, False, redact(f"transport error {type(exc).__name__}"))
            continue
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        text = response.text
        layer = attribute_layer(response.status_code, dict(response.headers), text)
        echoed = response.headers.get("X-Correlation-ID", "")
        row = {
            "test": case.name,
            "method": case.method,
            "path": case.path,
            "credential": case.token or "none",
            "correlation_id": correlation_id,
            "expected": list(case.expected),
            "status": response.status_code,
            "layer": layer,
            "expected_layers": list(case.expected_layers),
            "latency_ms": latency_ms,
            "body_sha256": sha256_text(text),
            "correlation_echoed": echoed == correlation_id,
            "kong_request_id": response.headers.get("X-Kong-Request-Id", ""),
        }
        bodies[case.name] = text
        ok = response.status_code in case.expected and layer in case.expected_layers
        if case.compare_body_to and case.compare_body_to in bodies:
            same = bodies[case.compare_body_to] == text
            row["body_matches"] = case.compare_body_to
            ok = ok and same
        report.matrix.append(row)
        report.add(phase, case.name, ok, f"status={response.status_code} expected={case.expected} layer={layer}")
    report.add(
        phase,
        "no_legacy_fallback_response",
        not any(r.get("layer") == "legacy_or_unknown" for r in report.matrix),
        "every response must be attributable to Kong or Middleware",
    )
    report.add(
        phase,
        "successful_requests_traversed_kong",
        all(r.get("kong_request_id") for r in report.matrix if r.get("status") in {200, 202}),
        "X-Kong-Request-Id must be present on every 2xx",
    )


# --- phase 4: routing proof ----------------------------------------------------


def run_log_proof(report: Report, settings: Settings) -> None:
    phase = "routing"
    correlation_ids = [r["correlation_id"] for r in report.matrix if "status" in r]
    successes = [r for r in report.matrix if r.get("status") in {200, 202}]
    campaign_reads = [r for r in successes if "/odoo/campaigns/" in r["path"]]
    expected_logs = {"caddy": successes, "kong": successes, "middleware": successes, "odoo": campaign_reads}
    proof: dict[str, Any] = {}
    for name, rows in expected_logs.items():
        path = settings.logs.get(name)
        if path is None or not path.is_file():
            report.skip(phase, f"{name}_log", f"CERTIFY_{name.upper()}_LOG not provided; the selected route cannot be proven")
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        found = {r["correlation_id"]: (r["correlation_id"] in text) for r in rows}
        proof[name] = {"found": sum(found.values()), "expected": len(found)}
        report.add(phase, f"{name}_log_has_every_success_correlation_id", all(found.values()), json.dumps(proof[name]))
        report.add(phase, f"{name}_log_has_no_jwt", not JWT_PATTERN.search(text), "no complete JWT may appear in logs")
        if name == "kong":
            report.add(
                phase,
                "kong_log_names_middleware_service_for_every_success",
                all(
                    re.search(rf"{re.escape(cid)}.*(middleware|integration-api)", text, re.IGNORECASE | re.DOTALL) is not None
                    for cid in found
                ),
            )
    legacy = settings.logs.get("legacy")
    if legacy and legacy.is_file():
        text = legacy.read_text(encoding="utf-8", errors="ignore")
        hits = [cid for cid in correlation_ids if cid in text]
        report.add(phase, "legacy_fallback_received_zero_requests", not hits, f"hits={len(hits)}")
    else:
        # Without a legacy log, fall back to per-response attribution.
        report.add(
            phase,
            "legacy_fallback_received_zero_requests",
            bool(report.matrix) and not any(r.get("layer") == "legacy_or_unknown" for r in report.matrix),
            "attributed from response headers only; supply CERTIFY_LEGACY_LOG for log-level proof",
        )
    report.routing = proof


# --- phase 5: restart comparison ---------------------------------------------


def run_restart_comparison(report: Report, baseline_path: Path) -> None:
    phase = "restart"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    before = baseline.get("static", {}).get("middleware", {}).get("contract_sha256")
    after = report.static.get("middleware", {}).get("contract_sha256")
    report.add(phase, "contract_hash_unchanged", bool(before) and before == after, f"before={before} after={after}")
    before_rows = {r["test"]: [r.get("status"), r.get("layer")] for r in baseline.get("matrix", []) if "status" in r}
    after_rows = {r["test"]: [r.get("status"), r.get("layer")] for r in report.matrix if "status" in r}
    drift = {name: {"before": before_rows[name], "after": after_rows[name]} for name in before_rows if name in after_rows and before_rows[name] != after_rows[name]}
    report.add(phase, "matrix_results_unchanged", not drift, json.dumps(drift))
    report.add(
        phase,
        "static_checks_unchanged",
        {c["name"] for c in baseline.get("checks", []) if c["phase"].startswith("static") and c["status"] == "PASS"}
        <= {c.name for c in report.checks if c.phase.startswith("static") and c.status == "PASS"},
    )
    report.restart = {"baseline": str(baseline_path), "drift": drift}


# --- entrypoint --------------------------------------------------------------


def main(argv: list[str] | None = None, env: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", type=Path, required=True, help="redacted JSON certification report")
    parser.add_argument("--static-only", action="store_true", help="run phase 1 only; no network traffic")
    parser.add_argument("--baseline-report", type=Path, help="pre-restart report to compare against (phase 5)")
    parser.add_argument("--wait-for-expiry", action="store_true", help="hold a minted token until it expires for the expired-token test")
    parser.add_argument(
        "--restart-subset",
        action="store_true",
        help="run only the post-restart subset: readback, campaign read, desired state, missing token, wrong scope",
    )
    args = parser.parse_args(argv)
    environment = dict(os.environ if env is None else env)

    report = Report()
    try:
        settings = load_settings(environment, static_only=args.static_only, wait_for_expiry=args.wait_for_expiry)
    except Refused as refusal:
        print(f"REFUSED={refusal.reason}")
        return 2

    run_static(report, settings)
    static_failed = [c for c in report.checks if c.status != "PASS"]
    if args.static_only or static_failed:
        if static_failed and not args.static_only:
            report.add("live", "matrix", False, f"blocked: {len(static_failed)} static contract check(s) did not pass")
        write_report(report, args.report)
        return 0 if report.verdict() == "GO" else 1

    import httpx

    with httpx.Client(follow_redirects=False) as client:
        tokens = mint_all(report, settings, client)
        if not settings.seeded_event_id:
            report.add("live", "seeded_event_id", False, "CERTIFY_SEEDED_EVENT_ID is required for readback tests")
        submit_event_id = f"EVT-TEST-SYN-{uuid4().hex[:12]}"
        cases = build_matrix(settings, settings.seeded_event_id or "EVT-UNSEEDED", submit_event_id)
        if args.restart_subset:
            keep = {"read_seeded_result", "read_campaign", "read_desired_state", "missing_token", "submit_token_reads_result"}
            cases = [case for case in cases if case.name in keep]
        if "expired" not in tokens and settings.expired_token is None and settings.wait_for_expiry and "n8n_read" in tokens:
            claims = decode_claims(tokens["n8n_read"], None)
            wait = int(claims.get("exp", 0)) - int(time.time()) + 5
            if 0 < wait <= 900:
                held = tokens["n8n_read"]
                time.sleep(wait)
                settings.expired_token = held
                tokens["n8n_read"] = mint_token(client, settings.issuer, settings.client_ids["n8n_read"], settings.client_secrets["n8n_read"], settings.timeout)
        run_matrix(report, settings, client, tokens, cases)
    run_log_proof(report, settings)
    if args.baseline_report:
        run_restart_comparison(report, args.baseline_report)
    write_report(report, args.report)
    return 0 if report.verdict() == "GO" else 1


def write_report(report: Report, path: Path) -> None:
    document = report.to_json()
    serialized = json.dumps(document, indent=2, sort_keys=True)
    if JWT_PATTERN.search(serialized):
        raise SystemExit("refusing to write a report that contains a JWT")
    path.write_text(serialized + "\n", encoding="utf-8")
    for check in report.checks:
        print(f"{check.phase}|{check.name}|{check.status}|{redact(check.detail)}")
    print(f"VERDICT={document['verdict']} CHECKS={document['totals']}")
    for check in report.failures():
        print(f"NO_GO_REASON={check.phase}|{check.name}|{check.status}|{redact(check.detail)}")


if __name__ == "__main__":
    sys.exit(main())
