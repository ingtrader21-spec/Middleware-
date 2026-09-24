"""scripts/certify_edge_integration.py is fail-closed, redacting, and detects contract drift."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scripts import certify_edge_integration as certify

DIGEST = certify.canonical_sha256(json.loads(certify.CONTRACT.read_text(encoding="utf-8")))
FAKE_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ." + "a" * 40 + "." + "b" * 40
BASE_ENV = {"CERTIFY_ENVIRONMENT": "staging", "CERTIFY_CAMPAIGN_ID": "TEST_SYN"}


# --- preconditions -------------------------------------------------------------


@pytest.mark.parametrize(
    "env,reason",
    [
        ({}, "CERTIFY_ENVIRONMENT"),
        ({"CERTIFY_ENVIRONMENT": "production", "CERTIFY_CAMPAIGN_ID": "TEST_SYN"}, "CERTIFY_ENVIRONMENT"),
        ({"CERTIFY_ENVIRONMENT": "staging", "CERTIFY_CAMPAIGN_ID": "MOY-SHIPPER-OUT"}, "CERTIFY_CAMPAIGN_ID"),
        ({**BASE_ENV, "CERTIFY_CLIENT_SECRET_N8N_SUBMIT": "raw"}, "raw credentials"),
        ({**BASE_ENV, "CERTIFY_STAGING_TOKEN": "raw"}, "raw credentials"),
    ],
)
def test_refuses_without_staging_test_syn_and_file_backed_secrets(env, reason):
    with pytest.raises(certify.Refused) as refusal:
        certify.load_settings(env, static_only=True, wait_for_expiry=False)
    assert reason in refusal.value.reason
    assert refusal.value.code == 2


@pytest.mark.parametrize(
    "base_url,issuer",
    [
        ("https://api.codestra.co", "https://auth-staging.codestra.co/realms/codestra"),
        ("http://api-staging.codestra.co", "https://auth-staging.codestra.co/realms/codestra"),
        ("https://api-preprod.codestra.co", "https://auth-staging.codestra.co/realms/codestra"),
        ("https://api-staging.codestra.co", "https://auth.codestra.co/realms/codestra"),
        ("https://api-staging.codestra.co", ""),
    ],
)
def test_live_mode_refuses_production_or_non_staging_edges(base_url, issuer):
    env = {**BASE_ENV, "CERTIFY_EDGE_BASE_URL": base_url, "CERTIFY_KEYCLOAK_ISSUER": issuer}
    with pytest.raises(certify.Refused):
        certify.load_settings(env, static_only=False, wait_for_expiry=False)


def test_live_mode_requires_every_identity_secret_file(tmp_path):
    env = {
        **BASE_ENV,
        "CERTIFY_EDGE_BASE_URL": "https://api-staging.codestra.co",
        "CERTIFY_KEYCLOAK_ISSUER": "https://auth-staging.codestra.co/realms/codestra",
    }
    with pytest.raises(certify.Refused) as refusal:
        certify.load_settings(env, static_only=False, wait_for_expiry=False)
    assert "CERTIFY_CLIENT_SECRET_FILE_N8N_SUBMIT" in refusal.value.reason
    for key in certify.IDENTITIES:
        secret = tmp_path / key
        secret.write_text("client-secret-value\n", encoding="utf-8")
        env[f"CERTIFY_CLIENT_SECRET_FILE_{key.upper()}"] = str(secret)
    settings = certify.load_settings(env, static_only=False, wait_for_expiry=False)
    assert set(settings.client_secrets) == set(certify.IDENTITIES)
    assert settings.client_ids["n8n_submit"] == "test-syn-n8n-submit"


def test_main_returns_2_and_writes_nothing_when_refused(tmp_path, capsys):
    report = tmp_path / "report.json"
    assert certify.main(["--static-only", "--report", str(report)], env={}) == 2
    assert not report.exists()
    assert "REFUSED=" in capsys.readouterr().out


# --- redaction ------------------------------------------------------------------


def test_redact_masks_complete_jwts():
    assert certify.redact(f"error for {FAKE_JWT} done") == "error for <redacted-jwt> done"


def test_write_report_refuses_to_persist_a_jwt(tmp_path):
    report = certify.Report()
    report.add("live", "leak", True, FAKE_JWT)
    with pytest.raises(SystemExit):
        certify.write_report(report, tmp_path / "report.json")
    assert not (tmp_path / "report.json").exists()


def test_redacted_claims_keep_only_the_matrix_columns():
    view = certify.redacted_claims(
        {"iss": "i", "aud": "a", "sub": "service-account-x", "scope": "s", "email": "x@y", "exp": 1}
    )
    assert "email" not in view and "sub" not in view
    assert view["sub_sha256"] and len(view["sub_sha256"]) == 16


def test_tamper_changes_only_the_signature():
    tampered = certify.tamper(FAKE_JWT)
    assert tampered != FAKE_JWT
    assert tampered.split(".")[:2] == FAKE_JWT.split(".")[:2]


# --- layer attribution ------------------------------------------------------------


@pytest.mark.parametrize(
    "status,headers,body,layer",
    [
        (401, {"X-Kong-Request-Id": "k"}, '{"message":"Unauthorized"}', "kong.jwt"),
        (403, {"X-Kong-Request-Id": "k"}, '{"error":"insufficient_scope"}', "kong.scope_guard"),
        (404, {"X-Kong-Request-Id": "k"}, '{"message":"no Route matched with those values"}', "kong.no_route"),
        (401, {"X-Kong-Upstream-Latency": "1", "X-Correlation-ID": "c"}, '{"detail":"unauthorized"}', "middleware.shared_secret_guard"),
        (401, {"X-Kong-Upstream-Latency": "1", "X-Correlation-ID": "c"}, '{"detail":"bearer token required"}', "middleware.jwt"),
        (403, {"X-Kong-Upstream-Latency": "1", "X-Correlation-ID": "c"}, '{"detail":"campaign scope denied"}', "middleware.scope"),
        (200, {"X-Kong-Upstream-Latency": "1", "X-Correlation-ID": "c"}, '{"event_id":"e"}', "middleware.handler"),
        (404, {"Via": "1.1 Caddy"}, "not found", "caddy"),
        (404, {}, "<html>legacy</html>", "legacy_or_unknown"),
    ],
)
def test_attribute_layer(status, headers, body, layer):
    assert certify.attribute_layer(status, headers, body) == layer


# --- caddy simulation ---------------------------------------------------------------


CONFORMANT_SITE = """
api-staging.codestra.co {
\troute {
\t\t@kong_n8n_submit {
\t\t\tmethod POST
\t\t\tpath /api/v1/integrations/n8n/results
\t\t}
\t\thandle @kong_n8n_submit {
\t\t\treverse_proxy {$CADDY_KONG_UPSTREAM}
\t\t}
\t\t@kong_integrations {
\t\t\tmethod GET DELETE PUT PATCH POST
\t\t\tpath /api/v1/integrations/n8n/results* /api/v1/integrations/odoo/campaigns* /api/v1/integrations/odoo/campaign-* /api/v1/integration/campaign-* /api/v1/odoo/campaign-*
\t\t}
\t\thandle @kong_integrations {
\t\t\treverse_proxy {$CADDY_KONG_UPSTREAM}
\t\t}
\t\t@kong path /api/v1/control* /api/v1/callbacks*
\t\thandle @kong {
\t\t\treverse_proxy {$CADDY_KONG_UPSTREAM}
\t\t}
\t\thandle {
\t\t\treverse_proxy {$CADDY_LEGACY_API_UPSTREAM}
\t\t}
\t}
\tlog {
\t\tformat filter {
\t\t\trequest>headers>Authorization delete
\t\t}
\t}
}
"""


def test_caddy_decision_honours_order_methods_and_fallback():
    assert certify.caddy_decision(CONFORMANT_SITE, "POST", "/api/v1/integrations/n8n/results") == ("kong", "kong_n8n_submit", True)
    assert certify.caddy_decision(CONFORMANT_SITE, "GET", "/api/v1/integrations/n8n/results/EVT-1")[0] == "kong"
    assert certify.caddy_decision(CONFORMANT_SITE, "GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN/desired-state")[0] == "kong"
    assert certify.caddy_decision(CONFORMANT_SITE, "DELETE", "/api/v1/integrations/odoo/campaigns/TEST_SYN")[0] == "kong"
    assert certify.caddy_decision(CONFORMANT_SITE, "POST", "/api/v1/integrations/odoo/campaign-actions")[0] == "kong"
    assert certify.caddy_decision(CONFORMANT_SITE, "GET", "/api/v1/control/x") == ("kong", "kong", False)
    assert certify.caddy_decision(CONFORMANT_SITE, "GET", "/api/v1/anything-else") == ("legacy_fallback", None, False)


def test_current_caddy_source_shape_sends_path_parameter_routes_to_legacy():
    site = (
        "api.codestra.co {\n\troute {\n"
        "\t\t@kong path /api/v1/integrations/n8n/results /api/v1/callbacks*\n"
        "\t\thandle @kong {\n\t\t\treverse_proxy {$CADDY_KONG_UPSTREAM}\n\t\t}\n"
        "\t\thandle {\n\t\t\treverse_proxy {$CADDY_LEGACY_API_UPSTREAM}\n\t\t}\n"
        "\t}\n}\n"
    )
    assert certify.caddy_upstream(site, "POST", "/api/v1/integrations/n8n/results") == "kong"
    assert certify.caddy_upstream(site, "GET", "/api/v1/integrations/n8n/results/EVT-1") == "legacy_fallback"
    assert certify.caddy_upstream(site, "GET", "/api/v1/integrations/odoo/campaigns/TEST_SYN") == "legacy_fallback"


# --- static drift detection against synthetic sibling repositories ----------------


def write_json(path: Path, document) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")


def conformant_kong(root: Path) -> Path:
    repo = root / "kong"
    (repo / "config").mkdir(parents=True)
    (repo / "config/edge-contract.sha256").write_text(DIGEST + "\n", encoding="utf-8")
    write_json(
        repo / "config/kong-campaign-automation-routes.json",
        {
            "routes": [
                {"path": "/api/v1/integrations/n8n/results", "scope": "n8n.results.submit"},
                {"path": "~/api/v1/integrations/n8n/results/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", "scope": "n8n.results.read"},
                {"path": "~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", "scope": "odoo.campaigns.read"},
                {"path": "~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/desired-state$", "scope": "odoo.campaigns.read"},
            ]
        },
    )
    plugins = ["jwt", "post-function", "correlation-id", "rate-limiting", "request-size-limiting"]
    routes = []
    for method, path, _scope in certify.CANONICAL_ROUTES:
        kong_path = "~" + re.sub(r"\{[a-z_]+\}", "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", path) + "$" if "{" in path else path
        routes.append(
            {
                "name": f"codestra-campaign-{path.strip('/').replace('/', '-').replace('{', '').replace('}', '')}-{method.lower()}",
                "paths": [kong_path],
                "pathTemplate": path,
                "methods": [method],
                "serviceHost": "codestra-middleware-integration-api-1",
                "servicePort": 8095,
                "securityAuthority": "config/kong-campaign-automation-routes.json",
                "requiredPlugins": plugins,
            }
        )
    write_json(repo / "config/kong-canonical-middleware-routes.json", {"contractRoutes": routes})
    return repo


def conformant_caddy(root: Path) -> Path:
    repo = root / "caddy"
    (repo / "sites").mkdir(parents=True)
    (repo / "sites/api.codestra.co.caddy").write_text(CONFORMANT_SITE, encoding="utf-8")
    (repo / "edge-contract.sha256").write_text(DIGEST + "\n", encoding="utf-8")
    return repo


def keycloak_client(client_id: str, scopes: list[str], audience: str = "middleware-api") -> dict:
    return {
        "clientId": client_id,
        "enabled": True,
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "fullScopeAllowed": False,
        "defaultClientScopes": [],
        "protocolMappers": [
            {
                "name": "audience",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": audience},
            },
            {
                "name": "scopes",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {"claim.name": "scope", "claim.value": " ".join(scopes)},
            },
        ],
    }


def conformant_keycloak(root: Path) -> Path:
    repo = root / "keycloak"
    for scope in certify.INGRESS_SCOPES:
        write_json(repo / f"config/client-scopes/{scope}.json", {"name": scope, "protocol": "openid-connect"})
    write_json(repo / "config/clients/test-syn-n8n-submit.json", keycloak_client("test-syn-n8n-submit", ["n8n.results.submit"]))
    write_json(repo / "config/clients/test-syn-n8n-read.json", keycloak_client("test-syn-n8n-read", ["n8n.results.read"]))
    write_json(repo / "config/clients/test-syn-odoo-reader.json", keycloak_client("test-syn-odoo-reader", ["odoo.campaigns.read"]))
    write_json(repo / "config/clients/test-syn-wrong-audience.json", keycloak_client("test-syn-wrong-audience", ["health.read"], audience="other-api"))
    write_json(repo / "config/realms/codestra.json", {"realm": "codestra", "defaultDefaultClientScopes": ["profile"]})
    (repo / "config/edge-contract.sha256").write_text(DIGEST + "\n", encoding="utf-8")
    return repo


@pytest.fixture
def siblings(tmp_path):
    return {
        "kong": conformant_kong(tmp_path),
        "caddy": conformant_caddy(tmp_path),
        "keycloak": conformant_keycloak(tmp_path),
    }


def static_env(siblings) -> dict[str, str]:
    return {
        **BASE_ENV,
        "CERTIFY_KEYCLOAK_ISSUER": "https://auth-staging.codestra.co/realms/codestra",
        "CERTIFY_KONG_REPO": str(siblings["kong"]),
        "CERTIFY_CADDY_REPO": str(siblings["caddy"]),
        "CERTIFY_KEYCLOAK_REPO": str(siblings["keycloak"]),
    }


def test_default_certification_audience_is_canonical():
    settings = certify.load_settings(
        BASE_ENV,
        static_only=True,
        wait_for_expiry=False,
    )
    assert settings.audience == "middleware-api"


def run_static(siblings) -> certify.Report:
    settings = certify.load_settings(static_env(siblings), static_only=True, wait_for_expiry=False)
    report = certify.Report()
    certify.run_static(report, settings)
    return report


def failed(report: certify.Report) -> set[str]:
    return {f"{c.phase}|{c.name}" for c in report.failures()}


# Middleware-side findings the runner reports today. Fixing app/api/v1/integrations.py
# _authenticate_n8n empties this set; the assertions below only allow, never require, them.
KNOWN_MIDDLEWARE_GAPS = {
    "static.middleware|n8n_validator_environment_not_hardcoded_production",
    "static.middleware|n8n_validator_accepts_separate_submit_and_read_identities",
}


def test_static_phase_passes_against_conformant_siblings(siblings):
    report = run_static(siblings)
    assert failed(report) <= KNOWN_MIDDLEWARE_GAPS, failed(report)
    assert not [name for name in failed(report) if not name.startswith("static.middleware|")]
    if not failed(report):
        assert report.verdict() == "GO"
    assert report.static["middleware"]["contract_sha256"] == DIGEST
    assert report.static["kong"]["contract_hash_pins"] == ["config/edge-contract.sha256"]
    classification = report.static["middleware"]["integration_route_classification"]
    assert {k for k, v in classification.items() if v == "shared_edge"} == {
        f"{m} {p}" for m, p, _s in certify.CANONICAL_ROUTES
    }


def test_static_phase_counts_missing_sibling_repositories_as_no_go():
    settings = certify.load_settings(BASE_ENV, static_only=True, wait_for_expiry=False)
    report = certify.Report()
    certify.run_static(report, settings)
    skipped = {c.name for c in report.checks if c.status == "SKIP"}
    assert skipped == {"repository"}
    assert report.verdict() == "NO_GO"
    assert {f"{c.phase}|{c.name}" for c in report.checks if c.phase == "static.middleware" and c.status != "PASS"} <= KNOWN_MIDDLEWARE_GAPS


def test_kong_drift_missing_route_and_unpinned_hash(siblings):
    document = json.loads((siblings["kong"] / "config/kong-canonical-middleware-routes.json").read_text())
    document["contractRoutes"] = [r for r in document["contractRoutes"] if "desired-state" not in r["paths"][0]]
    write_json(siblings["kong"] / "config/kong-canonical-middleware-routes.json", document)
    (siblings["kong"] / "config/edge-contract.sha256").write_text("0" * 64 + "\n", encoding="utf-8")
    names = failed(run_static(siblings))
    assert "static.kong|declares:GET /api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state" in names
    assert "static.kong|edge_contract_hash_pinned" in names
    assert "static|all_four_components_pin_identical_contract_hash" in names


def test_kong_drift_wrong_scope_or_missing_scope_guard(siblings):
    authority = siblings["kong"] / "config/kong-campaign-automation-routes.json"
    document = json.loads(authority.read_text())
    document["routes"][1]["scope"] = "n8n.results.submit"
    write_json(authority, document)
    canonical = siblings["kong"] / "config/kong-canonical-middleware-routes.json"
    routes = json.loads(canonical.read_text())
    routes["contractRoutes"][2]["requiredPlugins"] = ["jwt", "correlation-id"]
    write_json(canonical, routes)
    names = failed(run_static(siblings))
    assert "static.kong|declares:GET /api/v1/integrations/n8n/results/{event_id}" in names
    assert "static.kong|jwt_and_scope_guard:GET /api/v1/integrations/odoo/campaigns/{campaign_id}" in names


def test_caddy_drift_method_matcher_and_legacy_fallback(siblings):
    site = siblings["caddy"] / "sites/api.codestra.co.caddy"
    source = site.read_text(encoding="utf-8").replace("\t\t\tmethod GET DELETE PUT PATCH POST\n", "")
    source = source.replace(" /api/v1/integrations/odoo/campaigns*", "")
    site.write_text(source, encoding="utf-8")
    names = failed(run_static(siblings))
    assert "static.caddy|matcher_declares_method:GET /api/v1/integrations/n8n/results/{event_id}" in names
    assert "static.caddy|forwards_to_kong:GET /api/v1/integrations/odoo/campaigns/{campaign_id}" in names
    assert "static.caddy|wrong_method_never_reaches_legacy:DELETE /api/v1/integrations/odoo/campaigns/{campaign_id}" in names


def test_caddy_drift_fallback_before_kong(siblings):
    site = siblings["caddy"] / "sites/api.codestra.co.caddy"
    source = site.read_text(encoding="utf-8")
    fallback = "\t\thandle {\n\t\t\treverse_proxy {$CADDY_LEGACY_API_UPSTREAM}\n\t\t}\n"
    source = source.replace(fallback, "").replace("\troute {\n", "\troute {\n" + fallback)
    site.write_text(source, encoding="utf-8")
    names = failed(run_static(siblings))
    assert "static.caddy|kong_handles_precede_legacy_fallback" in names


def test_keycloak_drift_scope_creep_and_forbidden_write(siblings):
    write_json(
        siblings["keycloak"] / "config/clients/test-syn-n8n-read.json",
        keycloak_client("test-syn-n8n-read", ["n8n.results.read", "n8n.results.submit"]),
    )
    write_json(
        siblings["keycloak"] / "config/clients/odoo-results.json",
        keycloak_client("odoo-results", ["odoo.campaign.control.write"]),
    )
    write_json(
        siblings["keycloak"] / "config/realms/codestra.json",
        {"realm": "codestra", "defaultDefaultClientScopes": ["odoo.campaigns.read"]},
    )
    names = failed(run_static(siblings))
    assert "static.keycloak|client_scopes_exact:test-syn-n8n-read" in names
    assert "static.keycloak|no_client_holds_forbidden_write_scope" in names
    assert "static.keycloak|no_realm_wide_ingress_scope" in names


def test_keycloak_drift_missing_test_identity_and_scope_definition(siblings):
    (siblings["keycloak"] / "config/clients/test-syn-odoo-reader.json").unlink()
    (siblings["keycloak"] / "config/client-scopes/odoo.campaigns.read.json").unlink()
    names = failed(run_static(siblings))
    assert "static.keycloak|client_defined:test-syn-odoo-reader" in names
    assert "static.keycloak|scope_defined:odoo.campaigns.read" in names


def test_main_static_only_blocks_live_phase_and_exits_nonzero_on_drift(tmp_path, siblings, capsys):
    (siblings["kong"] / "config/edge-contract.sha256").unlink()
    report_path = tmp_path / "report.json"
    code = certify.main(["--static-only", "--report", str(report_path)], env=static_env(siblings))
    assert code == 1
    document = json.loads(report_path.read_text(encoding="utf-8"))
    assert document["verdict"] == "NO_GO"
    assert document["matrix"] == []
    out = capsys.readouterr().out
    assert "VERDICT=NO_GO" in out
    assert "NO_GO_REASON=static.kong|edge_contract_hash_pinned|FAIL" in out


# --- live matrix mechanics (no network) -----------------------------------------


class FakeResponse:
    def __init__(self, status, body, headers):
        self.status_code = status
        self.text = body
        self.headers = headers


class FakeEdge:
    """Answers like Kong + Middleware would and records every request."""

    def __init__(self):
        self.requests = []

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        self.requests.append({"method": method, "url": url, "headers": dict(headers or {}), "params": params, "json": json})
        correlation = headers["X-Correlation-ID"]
        auth = headers.get("Authorization", "")
        base = {"X-Kong-Request-Id": "k", "X-Kong-Upstream-Latency": "1", "X-Correlation-ID": correlation}
        if "campaign-actions" in url or "campaign-commands" in url or method == "DELETE":
            return FakeResponse(404, '{"message":"no Route matched with those values"}', {"X-Kong-Request-Id": "k"})
        if not auth:
            return FakeResponse(401, '{"message":"Unauthorized"}', {"X-Kong-Request-Id": "k"})
        token = auth.removeprefix("Bearer ")
        if token in {"exp-t0ken-value", "tampered", "foreign", "wrong-aud", "shr-s3cret-value"}:
            return FakeResponse(401, '{"message":"Unauthorized"}', {"X-Kong-Request-Id": "k"})
        if "/odoo/campaigns/" in url:
            if token == "odoo-reader":
                return FakeResponse(200, '{"campaign":"TEST_SYN"}', base)
            if token == "wrong-tenant":
                return FakeResponse(403, '{"detail":"tenant scope denied"}', base)
            return FakeResponse(403, '{"error":"insufficient_scope"}', {"X-Kong-Request-Id": "k"})
        if method == "POST":
            if token == "n8n-submit":
                return FakeResponse(202, '{"accepted":"true"}', base)
            return FakeResponse(403, '{"error":"insufficient_scope"}', {"X-Kong-Request-Id": "k"})
        if token in {"n8n-read", "wrong-tenant"}:
            if "EVT-MISSING" in url or token == "wrong-tenant":
                return FakeResponse(404, '{"detail":"standard result not found"}', base)
            return FakeResponse(200, '{"event_id":"EVT-1","status":"PENDING"}', base)
        return FakeResponse(403, '{"error":"insufficient_scope"}', {"X-Kong-Request-Id": "k"})


def live_settings(tmp_path) -> certify.Settings:
    shared = tmp_path / "shared"
    shared.write_text("shr-s3cret-value\n", encoding="utf-8")
    expired = tmp_path / "expired"
    expired.write_text("exp-t0ken-value\n", encoding="utf-8")
    env = {
        **BASE_ENV,
        "CERTIFY_EDGE_BASE_URL": "https://api-staging.codestra.co",
        "CERTIFY_KEYCLOAK_ISSUER": "https://auth-staging.codestra.co/realms/codestra",
        "CERTIFY_SEEDED_EVENT_ID": "EVT-1",
        "CERTIFY_SHARED_SECRET_FILE": str(shared),
        "CERTIFY_EXPIRED_TOKEN_FILE": str(expired),
    }
    for key in certify.IDENTITIES:
        secret = tmp_path / key
        secret.write_text("secret\n", encoding="utf-8")
        env[f"CERTIFY_CLIENT_SECRET_FILE_{key.upper()}"] = str(secret)
    return certify.load_settings(env, static_only=False, wait_for_expiry=False)


def test_matrix_covers_the_mission_with_unique_correlation_ids_and_no_tokens_in_report(tmp_path, monkeypatch):
    settings = live_settings(tmp_path)
    monkeypatch.setattr(certify, "tamper", lambda _token: "tampered")
    tokens = {
        "n8n_submit": "n8n-submit",
        "n8n_read": "n8n-read",
        "odoo_reader": "odoo-reader",
        "wrong_audience": "wrong-aud",
        "wrong_tenant": "wrong-tenant",
        "foreign_issuer": "foreign",
    }
    cases = certify.build_matrix(settings, "EVT-1", "EVT-SUBMIT")
    assert [c.name for c in cases] == [
        "submit_n8n_result",
        "read_seeded_result",
        "read_missing_result",
        "submit_token_reads_result",
        "read_token_submits_result",
        "read_campaign",
        "read_desired_state",
        "n8n_token_reads_campaign",
        "odoo_token_reads_n8n_result",
        "missing_token",
        "shared_secret_only",
        "expired_token",
        "tampered_token",
        "wrong_issuer",
        "wrong_audience",
        "cross_tenant_event",
        "cross_tenant_campaign",
        "wrong_method_on_get_route",
        "retired_campaign_actions",
        "retired_campaign_commands",
    ]
    edge = FakeEdge()
    report = certify.Report()
    certify.run_matrix(report, settings, edge, tokens, cases)

    assert len(edge.requests) == 20
    correlation_ids = [r["headers"]["X-Correlation-ID"] for r in edge.requests]
    assert len(set(correlation_ids)) == 20
    assert all(r["url"].startswith("https://api-staging.codestra.co/") for r in edge.requests)
    assert failed(report) == set(), failed(report)
    rows = {r["test"]: r for r in report.matrix}
    assert rows["submit_n8n_result"]["status"] == 202 and rows["submit_n8n_result"]["layer"] == "middleware.handler"
    assert rows["missing_token"]["layer"] == "kong.jwt"
    assert rows["submit_token_reads_result"]["layer"] == "kong.scope_guard"
    assert rows["cross_tenant_event"]["body_matches"] == "read_missing_result"
    assert all({"correlation_id", "status", "expected", "latency_ms", "body_sha256", "layer"} <= set(r) for r in report.matrix)
    serialized = json.dumps(report.to_json())
    for token in tokens.values():
        assert f'"{token}"' not in serialized
    assert settings.shared_secret == "shr-s3cret-value" and "shr-s3cret-value" not in serialized
    assert settings.expired_token == "exp-t0ken-value" and "exp-t0ken-value" not in serialized
    assert not certify.JWT_PATTERN.search(serialized)


def test_matrix_fails_on_wrong_status_or_layer_and_skips_count_as_no_go(tmp_path):
    settings = live_settings(tmp_path)
    settings.shared_secret = None

    class LegacyEdge(FakeEdge):
        def request(self, method, url, **kwargs):
            if "/odoo/campaigns/" in url and kwargs["headers"].get("Authorization") == "Bearer odoo-reader":
                return FakeResponse(200, "<html>legacy</html>", {})
            return super().request(method, url, **kwargs)

    report = certify.Report()
    cases = certify.build_matrix(settings, "EVT-1", "EVT-SUBMIT")
    certify.run_matrix(report, settings, LegacyEdge(), {"n8n_read": "n8n-read", "odoo_reader": "odoo-reader"}, cases)
    names = failed(report)
    assert "live|read_campaign" in names
    assert "live|no_legacy_fallback_response" in names
    assert "live|shared_secret_only" in names  # skipped: no secret file -> NO_GO
    assert report.verdict() == "NO_GO"


def test_log_proof_requires_every_component_log_and_no_jwt(tmp_path):
    settings = live_settings(tmp_path)
    report = certify.Report()
    report.matrix = [
        {"test": "read_campaign", "path": "/api/v1/integrations/odoo/campaigns/TEST_SYN", "status": 200, "correlation_id": "cid-1", "layer": "middleware.handler"},
        {"test": "missing_token", "path": "/api/v1/integrations/n8n/results/EVT-1", "status": 401, "correlation_id": "cid-2", "layer": "kong.jwt"},
    ]
    for name in ("caddy", "kong", "middleware"):
        log = tmp_path / f"{name}.log"
        log.write_text("cid-1 service=middleware-integration-api\n", encoding="utf-8")
        settings.logs[name] = log
    odoo = tmp_path / "odoo.log"
    odoo.write_text(f"cid-1 campaigns.read {FAKE_JWT}\n", encoding="utf-8")
    settings.logs["odoo"] = odoo
    certify.run_log_proof(report, settings)
    names = failed(report)
    assert "routing|odoo_log_has_no_jwt" in names
    assert "routing|legacy_fallback_received_zero_requests" not in names
    assert {c.name for c in report.checks if c.status == "PASS"} >= {
        "caddy_log_has_every_success_correlation_id",
        "kong_log_has_every_success_correlation_id",
        "kong_log_names_middleware_service_for_every_success",
        "middleware_log_has_every_success_correlation_id",
    }


def test_restart_comparison_detects_hash_and_result_drift(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "static": {"middleware": {"contract_sha256": DIGEST}},
                "matrix": [{"test": "read_campaign", "status": 200, "layer": "middleware.handler"}],
                "checks": [{"phase": "static.middleware", "name": "contract_hash_pinned", "status": "PASS"}],
            }
        ),
        encoding="utf-8",
    )
    report = certify.Report()
    report.static["middleware"] = {"contract_sha256": DIGEST}
    report.matrix = [{"test": "read_campaign", "status": 503, "layer": "middleware.handler"}]
    report.checks.append(certify.Check("static.middleware", "contract_hash_pinned", "PASS"))
    certify.run_restart_comparison(report, baseline)
    names = failed(report)
    assert "restart|matrix_results_unchanged" in names
    assert "restart|contract_hash_unchanged" not in names
    assert report.restart["drift"] == {"read_campaign": {"before": [200, "middleware.handler"], "after": [503, "middleware.handler"]}}
