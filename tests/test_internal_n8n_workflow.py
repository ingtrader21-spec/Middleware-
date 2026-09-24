import json
from pathlib import Path

WORKFLOW = Path("deploy/n8n/cod-reconciliation-event-v1.workflow.json")
PRIVATE_CADDY = Path("deploy/internal-n8n/Caddyfile")
ODOO_PRIVATE_CADDY = Path("deploy/internal-odoo/Caddyfile")
ODOO_PRIVATE_COMPOSE = Path("deploy/internal-odoo/compose.internal-odoo.yaml")
INVENTORY = Path("deploy/internal-n8n/production-workflow-inventory.json")


def test_production_workflow_is_inactive_scoped_and_credential_referenced():
    document = json.loads(WORKFLOW.read_text())
    assert document["active"] is False
    assert document["meta"]["business_unit_allowlist"] == ["BU-400-COD"]
    assert document["meta"]["campaign_allowlist"] == ["CMP-400-COD"]
    assert document["meta"]["event_type_allowlist"] == ["reconciliation.run"]
    assert document["meta"]["destination_class"] == (
        "INTERNAL_MIDDLEWARE_N8N_TEST_SINK"
    )
    assert document["meta"]["kill_switch"] == "N8N_PRODUCTION_WORKFLOWS_ENABLED"


def test_production_workflow_has_authenticated_webhook_registration_and_ack():
    document = json.loads(WORKFLOW.read_text())
    nodes = {node["name"]: node for node in document["nodes"]}
    webhook = nodes["Authenticated Event Webhook"]
    assert webhook["parameters"]["path"] == "codestra/v1/events"
    assert webhook["parameters"]["authentication"] == "jwtAuth"
    register = nodes["Middleware Execution Registration"]
    acknowledge = nodes["Middleware Durable Acknowledgement"]
    assert register["credentials"] == {"oAuth2Api": {"name": "codestra-n8n-production"}}
    assert acknowledge["credentials"] == {
        "oAuth2Api": {"name": "codestra-n8n-production"}
    }


def test_production_workflow_contains_no_direct_write_or_customer_nodes():
    document = json.loads(WORKFLOW.read_text())
    prohibited = {
        "n8n-nodes-base.postgres",
        "n8n-nodes-base.mySql",
        "n8n-nodes-base.emailSend",
        "n8n-nodes-base.twilio",
    }
    assert prohibited.isdisjoint({node["type"] for node in document["nodes"]})
    serialized = json.dumps(document).lower()
    assert "vicidial" not in serialized
    assert "asterisk" not in serialized


def test_private_proxy_exposes_only_canonical_governed_odoo_result_route():
    source = PRIVATE_CADDY.read_text()
    assert "reverse_proxy /api/v1/integration/results odoo:8069" in source
    assert "reverse_proxy /web/health odoo:8069" in source
    assert "/codestra/integration/v1/results" not in source
    assert "\tabort\n" in source
    assert "\tbind 0.0.0.0\n" not in source


def test_dedicated_odoo_proxy_is_internal_only_and_path_restricted():
    caddy = ODOO_PRIVATE_CADDY.read_text()
    compose = ODOO_PRIVATE_COMPOSE.read_text()
    assert "method POST" in caddy
    assert "path /api/v1/integration/results" in caddy
    assert "remote_ip {$INTEGRATION_CIDR:10.254.41.0/28}" in caddy
    assert "http://codestra-odoo-1:8069" in caddy
    assert "/codestra/integration/v1/results" not in caddy
    assert "ports:" not in compose
    assert 'expose:\n      - "443"' in compose
    assert "odoo.internal.codestra.agency" in compose
    assert "codestra-internal-integration" in compose
    assert "codestra_backend" in compose


def test_production_inventory_does_not_self_authorize_workflows():
    document = json.loads(INVENTORY.read_text())
    classifications = {
        item["workflow_id"]: item["classification"]
        for item in document["workflows"]
    }
    assert classifications["CodReconciliationEventV1"] == "INACTIVE_UNCLASSIFIED"
    assert classifications["TEST_SYN_RUNTIME_V1"] == "TEST_SYN_ONLY"
    assert all(
        item["classification"] != "APPROVED_PRODUCTION"
        for item in document["workflows"]
    )
