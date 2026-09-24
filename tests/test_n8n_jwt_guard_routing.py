"""The single request guard delegates service-JWT exemptions to one shared policy."""

from pathlib import Path

from app.core import route_policy

ROOT = Path(__file__).resolve().parents[1]
GUARD = (ROOT / "app/core/request_guard.py").read_text(encoding="utf-8")
MAIN = (ROOT / "app/main.py").read_text(encoding="utf-8")
RUNTIME = (ROOT / "app/entrypoints/runtime.py").read_text(encoding="utf-8")

APPROVED_N8N_ROUTES = {
    ("POST", "/api/v1/automation/policy-check"),
    ("POST", "/api/v1/campaign-designs/preview"),
    ("POST", "/api/v1/campaign-designs/approvals"),
    ("POST", "/api/v1/integrations/n8n/results"),
}
APPROVED_INTEGRATION_ROUTES = {
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}", "odoo.campaigns.read"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state", "odoo.campaigns.read"),
    ("GET", "/api/v1/integrations/n8n/results/{event_id}", "n8n.results.read"),
}
# Odoo event ingress authenticates its own odoo-integration service JWT in the
# handler; the shared-secret guard must never run first on this route.
APPROVED_ODOO_ROUTES = {
    ("POST", "/api/v1/odoo/events", "odoo.events.publish"),
}


def test_shared_policy_is_exactly_the_approved_route_set():
    assert set(route_policy.N8N_SERVICE_JWT_ROUTES) == APPROVED_N8N_ROUTES
    assert {
        (method, template, scope)
        for method, template, _pattern, _auth, scope in route_policy.INTEGRATION_SERVICE_JWT_ROUTES
    } == APPROVED_INTEGRATION_ROUTES
    assert {(m, p) for m, p, _s in APPROVED_ODOO_ROUTES} == set(
        route_policy.ODOO_SERVICE_JWT_ROUTES
    )


def test_the_single_guard_delegates_to_the_shared_policy_and_keeps_no_local_copy():
    assert "route_policy.handler_authenticated(method, path)" in GUARD
    assert "verify_bearer(" in GUARD
    for source in (GUARD, MAIN, RUNTIME):
        assert "N8N_SERVICE_JWT_ROUTES = " not in source
        assert "CALLBACK_JWT_PATH = " not in source
        assert "INTEGRATION_SERVICE_JWT_ROUTES = " not in source
        assert "campaign-actions" not in source
        assert "campaign-commands" not in source
    # Neither entry module carries a guard of its own any more.
    for source in (MAIN, RUNTIME):
        assert "verify_bearer(" not in source
        assert '@app.middleware("http")' not in source or "worker_app" in source


def test_exemptions_are_exact_method_and_path_not_prefixes():
    ok = route_policy.handler_authenticated
    assert ok("POST", "/api/v1/integrations/n8n/results")
    assert not ok("GET", "/api/v1/integrations/n8n/results")
    assert not ok("POST", "/api/v1/integrations/n8n/results/")
    assert not ok("POST", "/api/v1/integrations/n8n/results/anything")
    assert ok("GET", "/api/v1/integrations/n8n/results/event-1")
    assert not ok("POST", "/api/v1/integrations/n8n/results/event-1")
    assert not ok("GET", "/api/v1/integrations/n8n/results/event-1/extra")
    assert ok("GET", "/api/v1/integrations/odoo/campaigns/CMP-MBL")
    assert ok("GET", "/api/v1/integrations/odoo/campaigns/CMP-MBL/desired-state")
    assert not ok("GET", "/api/v1/integrations/odoo/campaigns/CMP-MBL/other")
    assert not ok("GET", "/api/v1/integrations/odoo/campaigns/")
    assert not ok("POST", "/api/v1/integrations/odoo/campaigns/CMP-MBL")
    assert not ok("GET", "/api/v1/integrations/odoo/campaign-commands/x")
    assert not ok("POST", "/api/v1/integration/campaign-actions")
    assert ok("POST", "/api/v1/callbacks/anything")
    assert ok("POST", "/api/v1/odoo/events")
    assert not ok("GET", "/api/v1/odoo/events")
    assert not ok("POST", "/api/v1/odoo/events/")
    assert not ok("POST", "/api/v1/odoo/events/anything")


def test_contract_rows_expose_auth_and_scope_for_every_exempt_route():
    rows = route_policy.service_jwt_route_contract()
    assert {(r["method"], r["path"]) for r in rows} == APPROVED_N8N_ROUTES | {
        (m, p) for m, p, _s in APPROVED_INTEGRATION_ROUTES | APPROVED_ODOO_ROUTES
    }
    assert all(r["auth"] in {"n8n-service-jwt", "odoo-service-jwt"} for r in rows)
    assert {r["scope"] for r in rows if "scope" in r} == {
        "odoo.campaigns.read",
        "n8n.results.read",
        "odoo.events.publish",
    }
    assert {r["auth"] for r in rows if r["path"] == "/api/v1/odoo/events"} == {"odoo-service-jwt"}
