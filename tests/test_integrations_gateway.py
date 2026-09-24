from app.main import app


def test_explicit_odoo_n8n_gateway_routes_exist():
    paths = set(app.openapi()["paths"])
    assert {
        "/api/v1/events/odoo",
        "/api/v1/integrations/runtime",
        "/api/v1/integrations/odoo/commands",
        "/api/v1/integrations/odoo/commands/{command_id}",
        "/api/v1/integrations/n8n/dispatch",
        "/api/v1/integrations/n8n/results",
        "/api/v1/integrations/n8n/errors",
        "/api/v1/integrations/n8n/progress",
        "/api/v1/integrations/n8n/dead-letter",
        "/api/v1/integrations/n8n/reconciliation",
        "/api/v1/orchestration/commands/{command_id}/start",
        "/api/v1/orchestration/commands/{command_id}/progress",
        "/api/v1/orchestration/commands/{command_id}/result",
        "/api/v1/orchestration/commands/{command_id}/error",
        "/api/v1/orchestration/commands/{command_id}/dead-letter",
        "/api/v1/orchestration/commands/{command_id}/reconcile",
    } <= paths
