"""Keycloak desired state agrees with the Odoo catalog, the edge contract, and settings."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from app.adapters.odoo.campaign_control import load_catalog
from app.core import route_policy
from app.core.config import settings

ROOT = Path(__file__).resolve().parents[1]
GRANTS = json.loads(
    (ROOT / "deploy/keycloak/campaign-control-service-clients.v1.json").read_text(encoding="utf-8")
)
EDGE = json.loads((ROOT / "deploy/public-api-route-contract.json").read_text(encoding="utf-8"))
FORBIDDEN = "odoo.campaign.control.write"
INGRESS_SCOPES = {
    "n8n.results.submit",
    "n8n.results.read",
    "odoo.campaigns.read",
}


def _migration():
    path = ROOT / "migrations/versions/0066_reconcile_odoo_campaign_scope.py"
    spec = importlib.util.spec_from_file_location("migration_0066", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


NEGATIVE = "certification_negative"


def _clients(environment: str, *, include_negative: bool = False) -> dict[str, dict]:
    return {
        c["client_id"]: c
        for c in GRANTS["environments"][environment]["clients"]
        if include_negative or c["direction"] != NEGATIVE
    }


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_middleware_never_holds_the_desired_state_write_scope(environment):
    for client in _clients(environment, include_negative=True).values():
        assert FORBIDDEN not in client["scopes"], client["client_id"]
    assert {g["scope"] for g in GRANTS["forbidden_grants"]} == {FORBIDDEN}
    assert {g["client_id"] for g in GRANTS["forbidden_grants"]} == {settings.odoo_results_client_id}


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_middleware_to_odoo_client_scopes_equal_registered_route_scopes(environment):
    client = _clients(environment)[settings.odoo_results_client_id]
    registered = {
        spec["scope"]
        for spec in load_catalog()["operations"].values()
        if spec["registered_by"] in {"0050", "0066"}
    }
    assert set(client["scopes"]) == registered
    assert client["direction"] == "middleware_to_odoo"
    assert client["interactive_flows_enabled"] is False


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_credential_and_audience_match_the_registry_rows(environment):
    migration = _migration()
    env_row = next(row for row in migration.ENVIRONMENTS if row[0] == environment)
    _env, _base_url, credential, audience = env_row[:4]
    client = _clients(environment)[settings.odoo_results_client_id]
    assert client["credential_reference_id"] == credential
    assert client["audience"] == audience


def test_staging_grants_are_bound_to_the_test_syn_triple_only():
    migration = _migration()
    organization, business_unit, campaign = migration.TEST_SYN_BINDING
    for client in _clients("staging").values():
        assert client["organizations"] == [organization]
        assert client["business_units"] == [business_unit]
        assert client["campaigns"] == [campaign]


def test_negative_certification_identities_hold_no_outbound_or_forbidden_scope():
    negatives = {
        cid: c for cid, c in _clients("staging", include_negative=True).items() if c["direction"] == NEGATIVE
    }
    assert set(negatives) == {"test-syn-wrong-audience", "test-syn-wrong-tenant"}
    outbound = set(_clients("staging")[settings.odoo_results_client_id]["scopes"])
    assert negatives["test-syn-wrong-audience"]["scopes"] == []
    assert negatives["test-syn-wrong-audience"]["audience"] != "middleware-api"
    assert set(negatives["test-syn-wrong-tenant"]["scopes"]) == {"n8n.results.read", "odoo.campaigns.read"}
    assert negatives["test-syn-wrong-tenant"]["organizations"] == ["TEST_SYN_OTHER_TENANT"]
    for client in negatives.values():
        assert not outbound & set(client["scopes"])
        assert FORBIDDEN not in client["scopes"]


def test_staging_middleware_settings_admit_exactly_the_certification_identities():
    staging = GRANTS["environments"]["staging"]
    listed = {c["client_id"] for c in staging["clients"]}
    n8n = set(staging["middleware_settings"]["N8N_CAMPAIGN_SERVICE_CLIENT_IDS"].split(","))
    readers = set(staging["middleware_settings"]["ODOO_CAMPAIGN_READER_CLIENT_IDS"].split(","))
    assert n8n == {"test-syn-n8n-submit", "test-syn-n8n-read", "test-syn-wrong-tenant"}
    assert readers == {"test-syn-odoo-reader", "test-syn-wrong-tenant"}
    assert (n8n | readers) <= listed
    assert "test-syn-wrong-audience" not in n8n | readers
    assert staging["middleware_settings"]["N8N_SERVICE_AUDIENCE"] == settings.n8n_service_audience
    assert staging["middleware_settings"]["N8N_SERVICE_ISSUER"] == staging["issuer"]


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_every_edge_contract_scope_is_granted_to_exactly_one_direction(environment):
    clients = _clients(environment)
    by_scope: dict[str, set[str]] = {}
    for client in clients.values():
        for scope in client["scopes"]:
            by_scope.setdefault(scope, set()).add(client["direction"])
    for row in EDGE["routes"]:
        if row["classification"] != "shared_edge" or row["scope"] not in INGRESS_SCOPES:
            continue
        scope = row.get("scope")
        if scope:
            assert by_scope.get(scope), f"{scope} not granted in {environment}"
            assert len(by_scope[scope]) == 1, f"{scope} granted to several directions"
    # Inbound scopes the handlers enforce (route policy) must be granted to the
    # inbound directions, never to the Middleware->Odoo client.
    outbound = set(clients[settings.odoo_results_client_id]["scopes"])
    for scope in {"odoo.campaigns.read", "n8n.results.read", "n8n.results.submit"}:
        assert scope not in outbound
        assert scope in by_scope


def test_n8n_client_ids_and_scopes_match_the_middleware_validator():
    production = _clients("production")
    n8n = production[settings.n8n_campaign_service_client_id]
    assert set(n8n["scopes"]) == {"n8n.results.submit", "n8n.results.read"}
    assert n8n["audience"] == settings.n8n_service_audience
    staging = _clients("staging")
    assert staging["test-syn-n8n-submit"]["scopes"] == ["n8n.results.submit"]
    assert staging["test-syn-n8n-read"]["scopes"] == ["n8n.results.read"]
    assert set(staging["test-syn-odoo-reader"]["scopes"]) == {"odoo.campaigns.read"}
    reader_scopes = {
        scope for _m, _t, _p, auth, scope in route_policy.INTEGRATION_SERVICE_JWT_ROUTES if auth == "odoo-service-jwt"
    }
    assert reader_scopes == {"odoo.campaigns.read"}
    assert set(production["codestra-odoo-campaign-reader-production"]["scopes"]) == reader_scopes


def test_production_declaration_states_no_activation():
    assert "not authorized" in GRANTS["environments"]["production"]["activation"]
