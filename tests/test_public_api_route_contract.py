"""The public API route contract, its pinned hash, the shared policy and both apps agree."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from app.core import route_policy
from app.appolon_factory import create_app as create_appolon_app
from app.core.config import Settings as AppolonSettings
from app.entrypoints.integration_api import app as integration_app
from app.main import app as main_app

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "deploy/public-api-route-contract.json"
PINNED = ROOT / "deploy/public-api-route-contract.sha256"
DESIRED_STATE = ROOT / "deploy/keycloak/campaign-control-service-clients.v1.json"
COMPOSE = ROOT / "deploy/compose.runtime.yaml"
AUTOMATION_POLICY = ROOT / "contracts/automation/operation-policy.v2.json"
PLATFORM_OPENAPI = ROOT / "contracts/platform/integration-fabric-api.v2.yaml"

REQUIRED_OPERATION_FIELDS = {
    "operation_id",
    "method",
    "path",
    "classification",
    "calling_client",
    "audience",
    "scope",
    "request_schema",
    "response_schema",
    "idempotency",
    "correlation_fields",
    "echo_fields",
    "error_statuses",
    "owner",
    "upstream",
}

CANONICAL = {
    ("POST", "/api/v1/integrations/n8n/results"): "n8n.results.submit",
    ("GET", "/api/v1/integrations/n8n/results/{event_id}"): "n8n.results.read",
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}"): "odoo.campaigns.read",
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state"): "odoo.campaigns.read",
}
INGRESS_SCOPES = set(CANONICAL.values())
OUTBOUND_SCOPE = "odoo.campaign.control.read"
FORBIDDEN_SCOPE = "odoo.campaign.control.write"
# Handler-authenticated but not yet an accepted edge exposure (mirrors
# scripts/audit_release_endpoints.py EDGE_EXPOSURE_UNDECIDED).
EDGE_EXPOSURE_UNDECIDED = {
    ("POST", "/api/v1/campaign-designs/preview"),
    ("POST", "/api/v1/campaign-designs/approvals"),
}


def contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def route_table(application) -> set[tuple[str, str]]:
    table: set[tuple[str, str]] = set()

    def walk(routes, prefix=""):
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


def test_contract_hash_is_pinned_and_canonical():
    canonical = json.dumps(contract(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert PINNED.read_text(encoding="utf-8").strip() == hashlib.sha256(canonical).hexdigest()


def test_contract_covers_every_required_operation_with_complete_metadata():
    document = contract()
    rows = {(row["method"], row["path"]): row for row in document["routes"]}
    automation = json.loads(AUTOMATION_POLICY.read_text(encoding="utf-8"))
    expected_automation = {
        (operation["method"], operation["path"])
        for operation in automation["operations"]
    }
    openapi = yaml.safe_load(PLATFORM_OPENAPI.read_text(encoding="utf-8"))
    expected_platform = {
        (method.upper(), path)
        for path, path_item in openapi["paths"].items()
        if path.startswith("/platform/v1/")
        for method in path_item
        if method in {"get", "post", "put", "patch", "delete"}
    }
    expected_ingress = expected_automation | expected_platform | {
        ("POST", "/api/v1/odoo/events"),
        *CANONICAL,
    }
    assert not (expected_ingress - set(rows))
    assert {rows[key]["classification"] for key in expected_ingress} == {"shared_edge"}

    expected_private = {
        ("POST", "/api/v1/integration/automation-results"),
        ("POST", "/api/v1/integration/campaigns/actual-state"),
    }
    assert {rows[key]["classification"] for key in expected_private} == {"private_only"}

    expected_denied = {
        ("POST", "/api/v1/integration/campaign-actions"),
        ("POST", "/api/v1/integrations/odoo/campaign-actions"),
        ("POST", "/api/v1/integrations/odoo/campaign-commands"),
        ("POST", "/v1/integrations/n8n/commands"),
    }
    assert {rows[key]["classification"] for key in expected_denied} == {"denied"}

    for key, row in rows.items():
        assert REQUIRED_OPERATION_FIELDS <= row.keys(), key
        assert row["method"] == row["method"].upper(), key
        assert row["path"].startswith("/"), key
        assert row["classification"] in {"shared_edge", "private_only", "denied"}, key
        assert row["calling_client"], key
        assert row["audience"], key
        assert row["scope"], key
        assert row["request_schema"], key
        assert row["response_schema"], key
        assert isinstance(row["idempotency"], dict), key
        assert row["correlation_fields"], key
        assert row["echo_fields"], key
        assert set(row["error_statuses"]) <= {400, 401, 403, 404, 405, 409, 413, 415, 422, 429, 500, 502, 503}, key
        assert row["owner"], key
        assert row["upstream"], key

    for key in expected_ingress:
        assert rows[key]["audience"] == "middleware-api", key
        assert rows[key]["upstream"] == "middleware-integration-api:8095", key


def test_contract_declares_the_four_canonical_routes_with_exact_scopes():
    rows = {(r["method"], r["path"]): r.get("scope") for r in contract()["routes"]}
    for key, scope in CANONICAL.items():
        assert rows.get(key) == scope, key
    assert contract()["service"] == "middleware-integration-api"
    assert contract()["listener_port"] == 8095
    assert FORBIDDEN_SCOPE not in CONTRACT.read_text(encoding="utf-8")


def test_kernel_operational_routes_use_kernel_clients_and_scopes():
    rows = {(r["method"], r["path"]): r for r in contract()["routes"]}
    read_paths = (
        "/platform/v1/adapters",
        "/platform/v1/adapters/{adapter_id}",
        "/platform/v1/connectors",
        "/platform/v1/connectors/{connector_id}",
        "/platform/v1/dead-letters",
        "/platform/v1/dead-letters/{operation_id}",
        "/platform/v1/reconciliation",
        "/platform/v1/reconciliation/{operation_id}",
    )
    replay_paths = (
        "/platform/v1/dead-letters/{operation_id}/replay",
        "/platform/v1/reconciliation/{operation_id}/readback",
        "/platform/v1/reconciliation/{operation_id}/resolve",
    )
    for path in read_paths:
        row = rows[("GET", path)]
        assert row["calling_client"] == "platform-command-client"
        assert row["scope"] == "platform.command.read"
    for path in replay_paths:
        row = rows[("POST", path)]
        assert row["calling_client"] == "platform-command-client"
        assert row["scope"] == "platform.command.replay"


def test_contract_and_shared_route_policy_are_the_same_table():
    rows = {
        (r["method"], r["path"]): r.get("scope")
        for r in contract()["routes"]
        if r["classification"] == "shared_edge"
    }
    policy = {(r["method"], r["path"]): r.get("scope") for r in route_policy.service_jwt_route_contract()}
    assert set(policy) - EDGE_EXPOSURE_UNDECIDED <= set(rows)
    for key, scope in policy.items():
        if key in EDGE_EXPOSURE_UNDECIDED:
            continue
        # Exact-path n8n rows carry their scope only in the contract; path-parameter
        # rows carry it in both places and must not drift.
        if scope is not None:
            assert rows[key] == scope, key


APPOLON_APP = create_appolon_app(
    settings=AppolonSettings.from_env(
        {"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}
    )
)


@pytest.mark.parametrize(
    "name,application",
    [
        ("integration_api", integration_app),
        ("main", main_app),
        ("appolon_factory", APPOLON_APP),
    ],
)
def test_both_apps_declare_every_contract_route_with_the_exact_method(name, application):
    table = route_table(application)
    for row in contract()["routes"]:
        if row["classification"] != "shared_edge":
            continue
        assert (row["method"], row["path"]) in table, (name, row)
    for method, path in CANONICAL:
        other_methods = {m for m, p in table if p == path} - {method}
        assert not (other_methods - {"HEAD", "OPTIONS"}), (name, path, other_methods)


# Deprecated aliases that only the in-process monolith may still mount until
# their published sunset. Kong and Caddy answer 404 for them and the deployed
# entrypoint never mounts them (scripts/audit_release_endpoints.py fails
# closed otherwise).
LEGACY_MONOLITH_ALIASES = {
    ("POST", "/v1/integrations/n8n/commands"),
    ("GET", "/v1/integrations/n8n/operations"),
    ("GET", "/v1/integrations/n8n/operations/{command_id}"),
    ("POST", "/v1/integrations/n8n/operations/{command_id}/cancel"),
    ("POST", "/v1/integrations/n8n/operations/{command_id}/reconcile"),
}


def _denied_rows() -> set[tuple[str, str]]:
    return {
        (row["method"], row["path"])
        for row in contract()["routes"]
        if row["classification"] == "denied"
    }


@pytest.mark.parametrize("application", [integration_app, main_app, APPOLON_APP])
def test_retired_campaign_paths_are_absent(application):
    assert not [
        path
        for _method, path in route_table(application)
        if "campaign-actions" in path or "campaign-commands" in path
    ]


def test_deployed_entrypoint_mounts_no_denied_route():
    assert not (_denied_rows() & route_table(integration_app))


@pytest.mark.parametrize("application", [main_app, APPOLON_APP])
def test_monolith_mounts_only_documented_deprecated_aliases(application):
    denied = _denied_rows()
    assert LEGACY_MONOLITH_ALIASES <= denied
    mounted = denied & route_table(application)
    assert mounted <= LEGACY_MONOLITH_ALIASES, mounted - LEGACY_MONOLITH_ALIASES
    paths = application.openapi()["paths"]
    for method, template in mounted:
        # The monolith's operation ids use {operation_id} for the mutation aliases.
        candidates = [template, template.replace("{command_id}", "{operation_id}")]
        operation = next(
            (paths[c][method.lower()] for c in candidates if c in paths and method.lower() in paths[c]),
            None,
        )
        assert operation is not None, (method, template)
        assert operation.get("deprecated") is True, (method, template)


def test_every_integration_route_is_classified():
    shared_edge = {
        (r["method"], r["path"])
        for r in contract()["routes"]
        if r["classification"] == "shared_edge"
    }
    classification: dict[tuple[str, str], str] = {}
    for key in route_table(integration_app) | route_table(main_app):
        if not key[1].startswith("/api/v1/integrations/"):
            continue
        if "campaign-actions" in key[1] or "campaign-commands" in key[1]:
            classification[key] = "denied"
        elif key in shared_edge:
            classification[key] = "shared_edge"
        else:
            classification[key] = "private_only"
    assert set(classification.values()) <= {"shared_edge", "private_only", "denied"}
    assert {k for k, v in classification.items() if v == "shared_edge"} == set(CANONICAL)
    assert not [k for k, v in classification.items() if v == "denied"]
    # Private-only routes stay behind the shared-secret guard.
    for method, path in classification:
        if classification[(method, path)] == "private_only":
            sample = path.replace("{command_id}", "x").replace("{provider}", "odoo").replace("{post_id}", "x").replace("{action}", "x")
            assert not route_policy.handler_authenticated(method, sample), (method, path)


def test_compose_deploys_the_integration_api_entrypoint():
    compose = COMPOSE.read_text(encoding="utf-8")
    assert "middleware-integration-api:" in compose
    assert "app.entrypoints.integration_api" in compose


def test_keycloak_desired_state_separates_ingress_and_outbound_scopes():
    document = json.loads(DESIRED_STATE.read_text(encoding="utf-8"))
    assert any(f["scope"] == FORBIDDEN_SCOPE for f in document["forbidden_grants"])
    for environment, state in document["environments"].items():
        for client in state["clients"]:
            scopes = set(client["scopes"])
            assert FORBIDDEN_SCOPE not in scopes, (environment, client["client_id"])
            if OUTBOUND_SCOPE in scopes:
                assert client["direction"] == "middleware_to_odoo", (environment, client["client_id"])
                assert not (scopes & INGRESS_SCOPES), (environment, client["client_id"])
            if scopes & INGRESS_SCOPES:
                assert client["audience"] == "middleware-api", (environment, client["client_id"])
                assert client["interactive_flows_enabled"] is False
                assert client["service_accounts_enabled"] is True
    staging = document["environments"]["staging"]
    for client in staging["clients"]:
        if client["direction"] == "certification_negative":
            # Negative identities prove denial: wrong audience carries no ingress
            # scope; wrong tenant never holds TEST_SYN.
            assert not (set(client["scopes"]) & INGRESS_SCOPES) or "TEST_SYN" not in client["campaigns"]
        else:
            assert client["campaigns"] == ["TEST_SYN"], client["client_id"]
    ids = {c["client_id"] for c in staging["clients"]}
    assert {"test-syn-n8n-submit", "test-syn-n8n-read", "test-syn-odoo-reader", "test-syn-wrong-audience"} <= ids
