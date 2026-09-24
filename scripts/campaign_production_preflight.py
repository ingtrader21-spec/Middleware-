#!/usr/bin/env python3
"""Read-only, sanitized production campaign acceptance preflight.

Never changes flags, workflows, campaigns, databases, or secret configuration.
A blocked preflight is NOT an end-to-end test.
"""

import json
import subprocess


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=15)


def inspect(name):
    value = json.loads(docker("inspect", name))[0]
    env = dict(
        item.split("=", 1) for item in value["Config"].get("Env", []) if "=" in item
    )
    return value, env


def scalar(db, query):
    sql = "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; " + query + " ROLLBACK;"
    return docker(
        "exec",
        "--user",
        "postgres",
        "codestra-postgres-1",
        "psql",
        "-X",
        "-q",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        db,
        "-c",
        sql,
    ).strip()


def main():
    failures = []
    result = {"production_execution": "NOT_RUN", "external_effects_performed": False}
    odoo, odoo_env = inspect("codestra-odoo-1")
    n8n, n8n_env = inspect("codestra-n8n-1")
    result["odoo_health"] = odoo["State"].get("Health", {}).get("Status", "unknown")
    result["n8n_health"] = n8n["State"].get("Health", {}).get("Status", "unknown")
    fields = int(
        scalar(
            "codestra_odoo",
            "SELECT count(*) FROM information_schema.columns WHERE table_name='call_center_campaign' AND column_name IN ('automatic_design_managed','provisioning_environment','design_input_json');",
        )
    )
    result["automatic_campaign_fields_present"] = fields == 3
    if fields != 3:
        failures.append("ODOO_AUTOMATIC_DESIGN_RELEASE_NOT_DEPLOYED")
    result["odoo_design_endpoint_configured"] = bool(
        odoo_env.get("CODESTRA_MIDDLEWARE_CAMPAIGN_DESIGN_URL")
    )
    result["odoo_design_credential_reference_configured"] = bool(
        odoo_env.get("CODESTRA_MIDDLEWARE_TOKEN_FILE")
    )
    if not result["odoo_design_endpoint_configured"]:
        failures.append("ODOO_CAMPAIGN_DESIGN_ENDPOINT_UNBOUND")
    if not result["odoo_design_credential_reference_configured"]:
        failures.append("ODOO_CAMPAIGN_DESIGN_CREDENTIAL_UNBOUND")
    try:
        tenant_map = json.loads(
            odoo_env.get("CODESTRA_MIDDLEWARE_CAMPAIGN_TENANTS", "{}")
        )
    except ValueError:
        tenant_map = None
    result["odoo_campaign_tenant_mapping_configured"] = isinstance(
        tenant_map, dict
    ) and bool(tenant_map)
    if not result["odoo_campaign_tenant_mapping_configured"]:
        failures.append("ODOO_CAMPAIGN_TENANT_BINDING_UNBOUND")
    result["live_flags"] = {
        key: n8n_env.get(key, "MISSING")
        for key in ("LIVE_EMAIL_DELIVERY", "LIVE_SMS_DELIVERY", "LIVE_PSTN_DIALING")
    }
    if any(v != "false" for v in result["live_flags"].values()):
        failures.append("EXTERNAL_DELIVERY_FLAGS_NOT_CLOSED")
    result["campaigns"] = json.loads(
        scalar(
            "codestra_odoo",
            "SELECT json_build_object('total',count(*),'active',count(*) FILTER(WHERE active)) FROM call_center_campaign;",
        )
    )
    result["n8n_workflows"] = json.loads(
        scalar(
            "codestra_n8n",
            "SELECT json_build_object('total',count(*),'active',count(*) FILTER(WHERE active)) FROM workflow_entity;",
        )
    )
    result["n8n_campaign_router_active"] = (
        int(
            scalar(
                "codestra_n8n",
                "SELECT count(*) FROM workflow_entity WHERE active AND name IN ('CDST_CampaignRouter_v2','CDST_EventRouter_v2');",
            )
        )
        > 0
    )
    if not result["n8n_campaign_router_active"]:
        failures.append("CAMPAIGN_AUTOMATION_WORKFLOW_NOT_ACTIVE")
    if result["odoo_health"] != "healthy" or result["n8n_health"] != "healthy":
        failures.append("APPLICATION_HEALTH_NOT_READY")
    result["blockers"] = failures
    result["status"] = (
        "BLOCKED" if failures else "REQUIRES_SIGNED_RELEASE_AND_CANARY_BINDING"
    )
    print(json.dumps(result, sort_keys=True, indent=2))
    # A preflight can never certify unexecuted signed-release/canary gates.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
