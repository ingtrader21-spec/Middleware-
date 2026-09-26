from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import app.db.session as db_session
import app.main as main_module
from app.api.v1 import integrations
from app.core.endpoint_registry import ResolutionDenied
from app.db.session import get_session
from app.entrypoints.integration_api import app as integration_app
from app.main import app


RESULT = {
    "event_id": "event-1",
    "correlation_id": "correlation-1",
    "idempotency_key": "result:event-1:1",
    "workflow_key": "moneybee_offer_sent",
    "execution_id": "execution-1",
    "status": "COMPLETED",
    "actions": [
        {
            "action_type": "CREATE_INTERNAL_SUMMARY",
            "entity_type": "crm.lead",
            "entity_id": "17",
            "values": {"summary": "offer sent"},
        }
    ],
    "completed_at": "2026-09-16T12:00:00Z",
}
HEADERS = {"Authorization": "Bearer synthetic", "Idempotency-Key": "result:event-1:1"}
CLAIMS = {"campaigns": ["CMP-MBL"], "business_units": ["MBL"], "tenant_id": "codestra"}
GUARD_REJECTIONS = {"unauthorized", "authentication unavailable"}


@pytest.fixture(autouse=True)
def canonical_runtime_environment(monkeypatch):
    """Give the split entrypoint an explicit disposable test runtime."""

    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ALLOW_IN_MEMORY_STORAGE", "true")


class FakeSession:
    def __init__(self, values):
        self.values = iter(values)
        self.added = []
        self.commits = 0

    async def scalar(self, _query):
        return next(self.values)

    async def execute(self, _query, _values=None):
        return None

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        return None


def source_event():
    return SimpleNamespace(
        id=17,
        original_event_id="event-1",
        correlation_id="correlation-1",
        idempotency_key="result:event-1:1",
        payload_json={
            "event_id": "event-1",
            "campaign_id": "CMP-MBL",
            "business_unit_id": "MBL",
        },
    )


def delivery():
    return SimpleNamespace(
        integration_event_id=17,
        result_public_id=UUID("00000000-0000-0000-0000-000000000042"),
        status="PENDING",
        attempts=0,
        delivered_at=None,
        last_error_class=None,
    )


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def integration_client():
    # The split integration runtime (app/entrypoints/integration_api.py) mounts
    # the integrations router without the orders router in front of it.
    with TestClient(integration_app) as test_client:
        yield test_client


def use_session(session):
    async def _get_session():
        yield session

    app.dependency_overrides[get_session] = _get_session


def use_session_factory(monkeypatch, session):
    # integration_api builds its app from raw router routes, which carry no
    # dependency-override provider, so get_session() is patched at its source.
    @asynccontextmanager
    async def factory():
        yield session

    monkeypatch.setattr(db_session, "SessionFactory", factory)


def iter_routes(routes, prefix=""):
    """Walk FastAPI routes, descending into lazily included routers."""
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            context = getattr(route, "include_context", None)
            yield from iter_routes(
                original.routes, prefix + (getattr(context, "prefix", "") or "")
            )
            continue
        path = getattr(route, "path", None)
        if path is not None:
            yield route, prefix + path


def resolve(application, method, path):
    """Endpoint FastAPI would dispatch to for a literal path: first match wins."""
    for route, route_path in iter_routes(application.routes):
        if route_path == path and method in (getattr(route, "methods", None) or ()):
            return getattr(route, "endpoint", None)
    return None


def n8n_auth_recorder(claims, expected_scope):
    requested = []

    def _authenticate(_authorization, required_scope):
        requested.append(required_scope)
        assert required_scope == expected_scope
        return claims

    return _authenticate, requested


# --- removed surface ---------------------------------------------------------


def test_campaign_actions_and_campaign_commands_routes_are_gone():
    paths = [path for _route, path in iter_routes(app.routes)]
    assert paths, "route walk found nothing; included routers were not expanded"
    assert not [path for path in paths if "campaign-actions" in path]
    assert not [path for path in paths if "campaign-commands" in path]
    assert "/api/v1/integrations/odoo/campaigns/{campaign_id}" in paths
    assert "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state" in paths
    assert "/api/v1/integrations/n8n/results/{event_id}" in paths


def test_main_has_no_legacy_router():
    assert not hasattr(main_module, "legacy_router")


# --- guard exemption ---------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/integrations/odoo/campaigns/CMP-MBL",
        "/api/v1/integrations/odoo/campaigns/CMP-MBL/desired-state",
        "/api/v1/integrations/n8n/results/event-1",
    ],
)
def test_integration_service_jwt_routes_bypass_shared_secret_guard(client, path):
    # Without the exemption the middleware answers 503/401 with a guard detail;
    # with it the handler itself rejects the missing bearer token or query.
    response = client.get(path)
    assert response.status_code in {401, 422}, response.text
    assert str(response.json()["detail"]) not in GUARD_REJECTIONS


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/v1/integrations/odoo/campaigns/CMP-MBL"),
        ("POST", "/api/v1/integrations/n8n/results/event-1"),
        ("GET", "/api/v1/integrations/odoo/campaigns/CMP-MBL/other"),
    ],
)
def test_guard_exemption_is_method_and_path_exact(client, method, path):
    response = client.request(method, path, json={})
    assert response.status_code in {401, 503}, response.text
    assert response.json()["detail"] in GUARD_REJECTIONS


# --- Odoo campaign reads -----------------------------------------------------


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"campaigns": ["CMP-MBL"], "business_units": ["MBL"]},
        {"campaigns": ["CMP-MBL"], "tenant_id": "codestra"},
        {"tenant_id": "codestra", "business_units": ["MBL"]},
        {"campaigns": ["OTHER"], "business_units": ["MBL"], "tenant_id": "codestra"},
    ],
)
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/integrations/odoo/campaigns/CMP-MBL",
        "/api/v1/integrations/odoo/campaigns/CMP-MBL/desired-state",
    ],
)
def test_campaign_read_fails_closed_without_explicit_scope_claims(
    client, monkeypatch, claims, path
):
    monkeypatch.setattr(integrations, "_authenticate_odoo", lambda *_: claims)

    async def unexpected_read(*_args, **_kwargs):
        raise AssertionError("Odoo must not be called without scope claims")

    monkeypatch.setattr(integrations, "_odoo_read", unexpected_read)
    response = client.get(
        path,
        params={"tenant_id": "codestra", "business_unit_id": "MBL"},
        headers=HEADERS,
    )
    assert response.status_code == 403, response.text


def test_campaign_reads_request_the_odoo_campaigns_read_scope(client, monkeypatch):
    requested = []

    def recorder(_authorization, required_scope):
        requested.append(required_scope)
        return CLAIMS

    async def fake_read(operation, payload, *, correlation_id, db):
        return {"operation": operation, **payload}

    monkeypatch.setattr(integrations, "_authenticate_odoo", recorder)
    monkeypatch.setattr(integrations, "_odoo_read", fake_read)
    params = {"tenant_id": "codestra", "business_unit_id": "MBL"}

    read = client.get(
        "/api/v1/integrations/odoo/campaigns/CMP-MBL", params=params, headers=HEADERS
    )
    desired = client.get(
        "/api/v1/integrations/odoo/campaigns/CMP-MBL/desired-state",
        params=params,
        headers=HEADERS,
    )

    assert read.status_code == 200, read.text
    assert read.json()["operation"] == "campaigns.read"
    assert desired.status_code == 200, desired.text
    assert desired.json()["operation"] == "desired_state.read"
    assert requested == ["odoo.campaigns.read", "odoo.campaigns.read"]


def test_odoo_payload_uses_registry_public_id_scope_names():
    assert integrations._odoo_payload("CMP-MBL", "codestra", "MBL") == {
        "organization_public_id": "codestra",
        "business_unit_public_id": "MBL",
        "campaign_public_id": "CMP-MBL",
    }


@pytest.mark.parametrize(
    "error,expected",
    [
        (ResolutionDenied("NO_ACTIVE_ROUTE"), 503),
        (integrations.OdooResultError("Odoo service private key is unavailable"), 503),
        (integrations.OdooCampaignAdapterError("campaigns.read rejected by Odoo"), 502),
    ],
)
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/integrations/odoo/campaigns/CMP-MBL",
        "/api/v1/integrations/odoo/campaigns/CMP-MBL/desired-state",
    ],
)
def test_campaign_read_maps_dependency_faults_to_503_and_odoo_errors_to_502(
    client, monkeypatch, error, expected, path
):
    monkeypatch.setattr(integrations, "_authenticate_odoo", lambda *_: CLAIMS)

    async def failing_read(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(integrations, "_odoo_read", failing_read)
    response = client.get(
        path,
        params={"tenant_id": "codestra", "business_unit_id": "MBL"},
        headers=HEADERS,
    )
    assert response.status_code == expected, response.text


# --- n8n readback ------------------------------------------------------------


def test_n8n_readback_reports_delivery_state_only(client, monkeypatch):
    authenticate, requested = n8n_auth_recorder(CLAIMS, "n8n.results.read")
    monkeypatch.setattr(integrations, "_authenticate_n8n", authenticate)
    use_session(FakeSession([delivery(), source_event()]))

    response = client.get("/api/v1/integrations/n8n/results/event-1", headers=HEADERS)

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "event_id",
        "receipt_id",
        "status",
        "attempts",
        "delivered_at",
        "last_error_class",
    }
    assert body == {
        "event_id": "event-1",
        "receipt_id": "00000000-0000-0000-0000-000000000042",
        "status": "PENDING",
        "attempts": 0,
        "delivered_at": None,
        "last_error_class": None,
    }
    assert requested == ["n8n.results.read"]


def test_n8n_readback_out_of_scope_is_indistinguishable_from_missing(
    client, monkeypatch
):
    missing_auth, _ = n8n_auth_recorder(CLAIMS, "n8n.results.read")
    monkeypatch.setattr(integrations, "_authenticate_n8n", missing_auth)
    use_session(FakeSession([None]))
    missing = client.get("/api/v1/integrations/n8n/results/event-1", headers=HEADERS)
    assert missing.status_code == 404

    out_of_scope_auth, requested = n8n_auth_recorder(
        {"campaigns": ["OTHER"], "business_units": ["MBL"]}, "n8n.results.read"
    )
    monkeypatch.setattr(integrations, "_authenticate_n8n", out_of_scope_auth)
    use_session(FakeSession([delivery(), source_event()]))
    hidden = client.get("/api/v1/integrations/n8n/results/event-1", headers=HEADERS)

    assert hidden.status_code == 404
    assert hidden.json() == missing.json()
    assert requested == ["n8n.results.read"]


def test_n8n_readback_hides_deliveries_outside_business_unit_scope(
    client, monkeypatch
):
    authenticate, _ = n8n_auth_recorder(
        {"campaigns": ["CMP-MBL"], "business_units": ["OTHER"]}, "n8n.results.read"
    )
    monkeypatch.setattr(integrations, "_authenticate_n8n", authenticate)
    use_session(FakeSession([delivery(), source_event()]))

    response = client.get("/api/v1/integrations/n8n/results/event-1", headers=HEADERS)

    assert response.status_code == 404


# --- n8n submit --------------------------------------------------------------


def test_n8n_submit_still_queues_a_durable_delivery(integration_client, monkeypatch):
    authenticate, requested = n8n_auth_recorder(CLAIMS, "n8n.results.submit")
    monkeypatch.setattr(integrations, "_authenticate_n8n", authenticate)
    monkeypatch.setattr(integrations.settings, "odoo_automation_writes_enabled", True)
    db = FakeSession([source_event(), None])
    use_session_factory(monkeypatch, db)

    response = integration_client.post(
        "/api/v1/integrations/n8n/results", json=RESULT, headers=HEADERS
    )

    assert response.status_code == 202, response.text
    assert response.json() == {
        "accepted": "true", "event_id": "event-1", "status": "COMPLETED",
    }
    queued = [
        item for item in db.added if isinstance(item, integrations.OdooResultDelivery)
    ]
    assert len(queued) == 1
    assert queued[0].status == "PENDING"
    assert queued[0].integration_event_id == 17
    assert queued[0].originating_outbox_public_id == "event-1"
    assert db.commits == 1
    assert requested == ["n8n.results.submit"]


def test_n8n_submit_fails_closed_when_writes_are_disabled(
    integration_client, monkeypatch
):
    authenticate, _ = n8n_auth_recorder(CLAIMS, "n8n.results.submit")
    monkeypatch.setattr(integrations, "_authenticate_n8n", authenticate)
    monkeypatch.setattr(integrations.settings, "odoo_automation_writes_enabled", False)
    db = FakeSession([source_event()])
    use_session_factory(monkeypatch, db)

    response = integration_client.post(
        "/api/v1/integrations/n8n/results", json=RESULT, headers=HEADERS
    )

    assert response.status_code == 503, response.text
    assert db.added == []


def test_split_runtime_rejects_malformed_legacy_n8n_result_with_422(
    integration_client,
):
    response = integration_client.post(
        "/api/v1/integrations/n8n/results",
        json={},
        headers={
            "Authorization": "Bearer synthetic",
            "Idempotency-Key": "malformed-result-1",
        },
    )

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert {item["loc"][-1] for item in detail} == {
        "command_id",
        "status",
        "correlation_id",
        "trace_id",
    }


def test_monolith_routes_n8n_submit_to_the_jwt_standard_result_handler(
    client, monkeypatch
):
    # KNOWN BUG (kept failing on purpose): app/main.py includes orders_router
    # (line 99) before integrations_router (line 105) and both register
    # POST /api/v1/integrations/n8n/results. FastAPI dispatches to the first
    # match, so in the composed app app.api.v1.orders.receive_result (HMAC
    # order envelope) shadows app.api.v1.integrations.n8n_result (JWT standard
    # result) and the N8N_SERVICE_JWT_ROUTES exemption in main.py guards a
    # handler that never receives the n8n standard result. The split runtime
    # (app/entrypoints/integration_api.py) is unaffected; see the tests above.
    endpoint = resolve(app, "POST", "/api/v1/integrations/n8n/results")
    assert endpoint is integrations.n8n_result, (
        f"POST /api/v1/integrations/n8n/results dispatches to "
        f"{endpoint.__module__}.{endpoint.__name__}; integrations.n8n_result is shadowed"
    )

    authenticate, _ = n8n_auth_recorder(CLAIMS, "n8n.results.submit")
    monkeypatch.setattr(integrations, "_authenticate_n8n", authenticate)
    monkeypatch.setattr(integrations.settings, "odoo_automation_writes_enabled", True)
    db = FakeSession([source_event(), None])
    use_session(db)

    response = client.post(
        "/api/v1/integrations/n8n/results", json=RESULT, headers=HEADERS
    )

    assert response.status_code == 202, response.text


# --- review findings: tenant binding and caller pinning ------------------------


@pytest.mark.parametrize("tenant_query", ["", None])
def test_missing_tenant_claim_cannot_be_matched_by_an_empty_tenant_query(
    client, monkeypatch, tenant_query
):
    # Finding: "" == "" used to pass when the JWT carried no tenant_id claim.
    monkeypatch.setattr(
        integrations, "_authenticate_odoo",
        lambda *_: {"campaigns": ["CMP-MBL"], "business_units": ["MBL"]},
    )
    params = {"business_unit_id": "MBL"}
    if tenant_query is not None:
        params["tenant_id"] = tenant_query
    response = client.get("/api/v1/integrations/odoo/campaigns/CMP-MBL", params=params)
    assert response.status_code in {403, 422}, response.text


def test_campaign_reader_is_pinned_to_dedicated_clients_and_environment(monkeypatch):
    captured = {}

    class Recorder:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def validate(self, _token):
            return {"tenant_id": "codestra"}

    monkeypatch.setattr(integrations, "KeycloakValidator", Recorder)
    monkeypatch.setattr(integrations.settings, "odoo_campaign_reader_client_ids", "reader-a, reader-b")
    monkeypatch.setattr(integrations.settings, "keycloak_authorized_parties", "agent-ui-client")
    monkeypatch.setattr(integrations.settings, "environment", "staging")

    # An implicit (derived) identity is never trusted by the integration routes.
    with pytest.raises(integrations.HTTPException) as denied:
        integrations._authenticate_odoo("Bearer x", "odoo.campaigns.read")
    assert denied.value.status_code == 401
    assert not captured

    monkeypatch.setattr(integrations.settings, "keycloak_issuer", "https://auth-staging.codestra.co/realms/codestra")
    monkeypatch.setattr(integrations.settings, "keycloak_audience", "middleware-api")
    monkeypatch.setattr(
        integrations.settings,
        "keycloak_jwks_url",
        "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/certs",
    )
    integrations._authenticate_odoo("Bearer x", "odoo.campaigns.read")
    assert captured["issuer"] == "https://auth-staging.codestra.co/realms/codestra"
    assert captured["authorized_parties"] == frozenset({"reader-a", "reader-b"})
    assert "agent-ui-client" not in captured["authorized_parties"]
    assert captured["required_environment"] == "staging"
    assert captured["required_scopes"] == frozenset({"odoo.campaigns.read"})


def test_campaign_reader_fails_closed_when_no_client_is_configured(monkeypatch):
    monkeypatch.setattr(integrations.settings, "odoo_campaign_reader_client_ids", "")
    with pytest.raises(integrations.HTTPException) as raised:
        integrations._authenticate_odoo("Bearer x", "odoo.campaigns.read")
    assert raised.value.status_code == 503


def test_n8n_authenticator_pins_deployment_environment_and_accepts_listed_clients(monkeypatch):
    captured = {}

    class Recorder:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def validate(self, _token):
            return {}

    monkeypatch.setattr(integrations, "KeycloakValidator", Recorder)
    monkeypatch.setattr(integrations.settings, "environment", "staging")
    monkeypatch.setattr(integrations.settings, "n8n_campaign_service_client_id", "single-client")
    monkeypatch.setattr(
        integrations.settings, "n8n_campaign_service_client_ids",
        "test-syn-n8n-submit, test-syn-n8n-read,test-syn-wrong-tenant",
    )
    integrations._authenticate_n8n("Bearer x", "n8n.results.read")
    assert captured["required_environment"] == "staging"
    assert captured["authorized_parties"] == frozenset(
        {"test-syn-n8n-submit", "test-syn-n8n-read", "test-syn-wrong-tenant"}
    )
    # Empty list falls back to the single production client.
    monkeypatch.setattr(integrations.settings, "n8n_campaign_service_client_ids", "")
    monkeypatch.setattr(integrations.settings, "environment", "production")
    integrations._authenticate_n8n("Bearer x", "n8n.results.submit")
    assert captured["authorized_parties"] == frozenset({"single-client"})
    assert captured["required_environment"] == "production"
