"""Shared route authentication policy for every API entrypoint.

Both ``app.main`` (monolith) and ``app.entrypoints.runtime.add_api_runtime``
(deployed ``integration_api``) decide here whether the shared-secret bearer
guard runs or the handler authenticates its own service JWT. Keeping one
implementation prevents the two guards from drifting apart.

Every route listed here still verifies signature, issuer, audience, scope and
tenant inside its handler; the guard exemption only stops the static
``middleware_secret`` check from running first. Entries are exact
method + path (or a fullmatch pattern for path parameters); nothing here is
prefix-based.
"""

from __future__ import annotations

import re
from typing import Iterable

PUBLIC_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"

# n8n / control-plane service JWT (exact method + path).
N8N_SERVICE_JWT_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/v1/automation/policy-check"),
        ("POST", "/api/v1/campaign-designs/preview"),
        ("POST", "/api/v1/campaign-designs/approvals"),
        ("POST", "/api/v1/integrations/n8n/results"),
    }
)

ODOO_SERVICE_JWT_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {("POST", "/api/v1/odoo/events")}
)

# Integration service JWT routes with path parameters. The scope column is
# what the handler enforces; it is exported so the edge-route contract and
# the Keycloak desired state can be checked against the same table.
INTEGRATION_SERVICE_JWT_ROUTES: tuple[tuple[str, str, re.Pattern[str], str, str], ...] = (
    (
        "GET",
        "/api/v1/integrations/odoo/campaigns/{campaign_id}",
        re.compile(rf"^/api/v1/integrations/odoo/campaigns/{PUBLIC_ID}$"),
        "odoo-service-jwt",
        "odoo.campaigns.read",
    ),
    (
        "GET",
        "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state",
        re.compile(rf"^/api/v1/integrations/odoo/campaigns/{PUBLIC_ID}/desired-state$"),
        "odoo-service-jwt",
        "odoo.campaigns.read",
    ),
    (
        "GET",
        "/api/v1/integrations/n8n/results/{event_id}",
        re.compile(rf"^/api/v1/integrations/n8n/results/{PUBLIC_ID}$"),
        "n8n-service-jwt",
        "n8n.results.read",
    ),
)

CALLBACK_JWT_PATH = re.compile(r"^/api/v1/(?:control/)?callbacks(?:/.*)?$")


def is_n8n_service_jwt_route(method: str, path: str) -> bool:
    return (method.upper(), path) in N8N_SERVICE_JWT_ROUTES


def is_integration_service_jwt_route(method: str, path: str) -> bool:
    upper = method.upper()
    return any(
        upper == route_method and pattern.fullmatch(path) is not None
        for route_method, _template, pattern, _auth, _scope in INTEGRATION_SERVICE_JWT_ROUTES
    )


def is_callback_jwt_path(path: str) -> bool:
    return CALLBACK_JWT_PATH.fullmatch(path) is not None


def handler_authenticated(method: str, path: str) -> bool:
    """True when the handler, not the shared-secret guard, authenticates the request."""
    return (
        is_n8n_service_jwt_route(method, path)
        or (method.upper(), path) in ODOO_SERVICE_JWT_ROUTES
        or is_integration_service_jwt_route(method, path)
        or is_callback_jwt_path(path)
    )


def service_jwt_route_contract() -> list[dict[str, str]]:
    """Rows for the edge-route contract: method, path template, auth, scope."""
    rows = [
        {"method": method, "path": path, "auth": "n8n-service-jwt"}
        for method, path in sorted(N8N_SERVICE_JWT_ROUTES)
    ]
    rows.extend(
        {"method": method, "path": template, "auth": auth, "scope": scope}
        for method, template, _pattern, auth, scope in INTEGRATION_SERVICE_JWT_ROUTES
    )
    rows.extend(
        {
            "method": method,
            "path": path,
            "auth": "odoo-service-jwt",
            "scope": "odoo.events.publish",
        }
        for method, path in sorted(ODOO_SERVICE_JWT_ROUTES)
    )
    return rows


def templates(routes: Iterable[tuple[str, str, re.Pattern[str], str, str]]) -> set[tuple[str, str]]:
    return {(method, template) for method, template, _p, _a, _s in routes}
