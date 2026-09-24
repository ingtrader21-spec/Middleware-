"""The deployed ``integration_api`` factory authenticates the four canonical routes itself.

These tests run against ``app.entrypoints.integration_api.app`` (the process
``deploy/compose.runtime.yaml`` starts), not only the ``app.main`` monolith.
Real RS256 JWTs are signed with a test key and verified by the real
``KeycloakValidator``; only the JWKS fetch is replaced, so issuer, audience,
expiry, authorized party, scope and environment checks all execute.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.db.session as db_session
from app.api.v1 import integrations
from app.core import jwt_auth
from app.entrypoints.integration_api import app as integration_app

ISSUER = "https://auth-staging.codestra.co/realms/codestra"
AUDIENCE = "middleware-api"
JWKS = f"{ISSUER}/protocol/openid-connect/certs"
SHARED_SECRET = "synthetic-shared-secret-never-a-jwt"
N8N_SUBMIT_CLIENT = "test-syn-n8n-submit"
N8N_READ_CLIENT = "test-syn-n8n-read"
ODOO_READER = "test-syn-odoo-reader"
CAMPAIGN = "TEST_SYN"
TENANT = "TEST_SYN_TENANT"
BUSINESS_UNIT = "TEST_SYN"
EVENT_ID = "EVT-TEST-SYN-0001"
PARAMS = {"tenant_id": TENANT, "business_unit_id": BUSINESS_UNIT}
GUARD_DETAILS = {"unauthorized", "authentication unavailable"}

READ = f"/api/v1/integrations/n8n/results/{EVENT_ID}"
SUBMIT = "/api/v1/integrations/n8n/results"
CAMPAIGN_READ = f"/api/v1/integrations/odoo/campaigns/{CAMPAIGN}"
DESIRED_STATE = f"{CAMPAIGN_READ}/desired-state"

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()


@pytest.fixture(autouse=True)
def canonical_runtime_environment(monkeypatch):
    """Give the deployed entrypoint its explicit, side-effect-free test runtime."""

    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ALLOW_IN_MEMORY_STORAGE", "true")


def sign(
    *,
    azp: str,
    scope: str,
    environment: str,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    expires_in: int = 300,
    campaigns: list[str] | None = None,
    business_units: list[str] | None = None,
    tenant_id: str = TENANT,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "azp": azp,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "scope": scope,
        "environment": environment,
        "tenant_id": tenant_id,
        "campaigns": [CAMPAIGN] if campaigns is None else campaigns,
        "business_units": [BUSINESS_UNIT] if business_units is None else business_units,
        "typ": "Bearer",
    }
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-syn"})


class FakeJWKClient:
    def __init__(self, *_args, **_kwargs):
        pass

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=PUBLIC_KEY)


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


def delivery():
    return SimpleNamespace(
        integration_event_id=17,
        result_public_id=UUID("00000000-0000-0000-0000-000000000042"),
        status="PENDING",
        attempts=0,
        delivered_at=None,
        last_error_class=None,
    )


def source_event():
    return SimpleNamespace(
        id=17,
        original_event_id=EVENT_ID,
        correlation_id="correlation-1",
        idempotency_key=f"result:{EVENT_ID}:1",
        payload_json={"event_id": EVENT_ID, "campaign_id": CAMPAIGN, "business_unit_id": BUSINESS_UNIT},
    )


def submit_body():
    return {
        "event_id": EVENT_ID,
        "correlation_id": "correlation-1",
        "idempotency_key": f"result:{EVENT_ID}:1",
        "workflow_key": "test_syn_certification",
        "execution_id": "execution-1",
        "status": "COMPLETED",
        "actions": [
            {
                "action_type": "CREATE_INTERNAL_SUMMARY",
                "entity_type": "crm.lead",
                "entity_id": "17",
                "values": {"summary": "certification"},
            }
        ],
        "completed_at": "2026-09-16T12:00:00Z",
    }


def test_deployed_app_preserves_specialized_automation_validation_errors():
    body = {
        "tenant_id": TENANT,
        "correlation_id": "correlation-1",
        "idempotency_key": "claim:TEST_SYN:0001",
        "job_id": "00000000-0000-0000-0000-000000000101",
        "delivery_token": "d" * 32,
        "workflow_key": "test_syn_certification",
        "workflow_version": 1,
        "execution_id": "00000000-0000-0000-0000-000000000102",
    }
    with TestClient(integration_app, raise_server_exceptions=False) as test_client:
        response = test_client.post("/v2/automation/jobs/claim", json=body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "automation_invalid"


@pytest.fixture
def staging(monkeypatch):
    """Configure the deployed factory the way staging would, with a synthetic shared secret."""
    settings = integrations.settings
    monkeypatch.setattr(settings, "middleware_secret", SHARED_SECRET)
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "n8n_service_issuer", ISSUER)
    monkeypatch.setattr(settings, "n8n_service_audience", AUDIENCE)
    monkeypatch.setattr(settings, "n8n_service_jwks_url", JWKS)
    monkeypatch.setattr(settings, "n8n_campaign_service_client_ids", f"{N8N_SUBMIT_CLIENT},{N8N_READ_CLIENT}")
    monkeypatch.setattr(settings, "keycloak_issuer", ISSUER)
    monkeypatch.setattr(settings, "keycloak_audience", AUDIENCE)
    monkeypatch.setattr(settings, "keycloak_jwks_url", JWKS)
    monkeypatch.setattr(settings, "odoo_campaign_reader_client_ids", ODOO_READER)
    monkeypatch.setattr(settings, "odoo_automation_writes_enabled", True)
    monkeypatch.setattr(jwt_auth.jwt, "PyJWKClient", FakeJWKClient)
    return settings


@pytest.fixture
def client(staging):
    with TestClient(integration_app) as test_client:
        yield test_client


@pytest.fixture
def session(monkeypatch):
    # integration_api builds its app from raw router routes, which carry no
    # dependency-override provider, so get_session() is patched at its source.
    def install(values):
        db = FakeSession(values)

        @asynccontextmanager
        async def factory():
            yield db

        monkeypatch.setattr(db_session, "SessionFactory", factory)
        return db

    return install


@pytest.fixture
def odoo_read(monkeypatch):
    calls = []

    async def fake_read(operation, payload, *, correlation_id, db):
        calls.append((operation, payload))
        return {"operation": operation, "campaign": payload["campaign_public_id"]}

    monkeypatch.setattr(integrations, "_odoo_read", fake_read)
    return calls


def n8n_token(scope: str, environment: str = "staging", **overrides) -> str:
    # One identity per scope, exactly as the staging certification clients are cut.
    azp = N8N_SUBMIT_CLIENT if scope == "n8n.results.submit" else N8N_READ_CLIENT
    return sign(azp=azp, scope=scope, environment=environment, **overrides)


def odoo_token(scope: str = "odoo.campaigns.read", **overrides) -> str:
    return sign(azp=ODOO_READER, scope=scope, environment="staging", **overrides)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- valid service JWT works without the shared secret -------------------------


def test_read_seeded_result_with_read_scope_only(client, session):
    session([delivery(), source_event()])
    response = client.get(READ, headers=bearer(n8n_token("n8n.results.read")))
    assert response.status_code == 200, response.text
    assert response.json()["event_id"] == EVENT_ID
    assert response.headers["X-Correlation-ID"]


def test_read_missing_result_is_404(client, session):
    session([None])
    response = client.get(READ, headers=bearer(n8n_token("n8n.results.read")))
    assert response.status_code == 404, response.text


def test_submit_result_with_submit_scope_only(client, session):
    db = session([source_event(), None])
    response = client.post(
        SUBMIT,
        json=submit_body(),
        headers={**bearer(n8n_token("n8n.results.submit")), "Idempotency-Key": f"result:{EVENT_ID}:1"},
    )
    assert response.status_code == 202, response.text
    assert db.commits == 1


@pytest.mark.parametrize("path,operation", [(CAMPAIGN_READ, "campaigns.read"), (DESIRED_STATE, "desired_state.read")])
def test_campaign_reads_with_odoo_reader_scope(client, odoo_read, path, operation):
    response = client.get(path, params=PARAMS, headers=bearer(odoo_token()))
    assert response.status_code == 200, response.text
    assert response.json() == {"operation": operation, "campaign": CAMPAIGN}
    assert odoo_read == [
        (
            operation,
            {
                "organization_public_id": TENANT,
                "business_unit_public_id": BUSINESS_UNIT,
                "campaign_public_id": CAMPAIGN,
            },
        )
    ]


# --- missing JWT reaches the JWT layer, not the shared-secret guard --------------


@pytest.mark.parametrize(
    "method,path,params",
    [
        ("GET", READ, None),
        ("POST", SUBMIT, None),
        ("GET", CAMPAIGN_READ, PARAMS),
        ("GET", DESIRED_STATE, PARAMS),
    ],
)
def test_missing_jwt_is_401_from_the_jwt_layer(client, method, path, params):
    response = client.request(method, path, params=params, json={} if method == "POST" else None)
    assert response.status_code in {401, 422}, response.text
    assert str(response.json()["detail"]) not in GUARD_DETAILS


# --- shared secret without JWT is 401 -------------------------------------------


@pytest.mark.parametrize(
    "method,path,params",
    [
        ("GET", READ, None),
        ("GET", CAMPAIGN_READ, PARAMS),
        ("GET", DESIRED_STATE, PARAMS),
    ],
)
def test_shared_secret_alone_is_rejected_by_the_jwt_layer(client, method, path, params):
    response = client.request(method, path, params=params, headers=bearer(SHARED_SECRET))
    assert response.status_code == 401, response.text
    assert response.json()["detail"] not in GUARD_DETAILS


# --- wrong scope ------------------------------------------------------------


WRONG_SCOPE_CASES = [
    ("submit token reads result", "GET", READ, None, lambda: n8n_token("n8n.results.submit")),
    ("read token submits result", "POST", SUBMIT, None, lambda: n8n_token("n8n.results.read")),
    ("n8n token reads campaign", "GET", CAMPAIGN_READ, PARAMS, lambda: n8n_token("n8n.results.read")),
    ("odoo token reads n8n result", "GET", READ, None, lambda: odoo_token()),
]


@pytest.mark.parametrize("label,method,path,params,token", WRONG_SCOPE_CASES, ids=[c[0] for c in WRONG_SCOPE_CASES])
def test_wrong_scope_is_rejected_before_the_handler(client, session, odoo_read, label, method, path, params, token):
    db = session([delivery(), source_event()])
    headers = {**bearer(token()), "Idempotency-Key": f"result:{EVENT_ID}:1"}
    response = client.request(
        method, path, params=params, headers=headers, json=submit_body() if method == "POST" else None
    )
    assert response.status_code in {401, 403}, response.text
    assert response.json()["detail"] not in GUARD_DETAILS
    assert odoo_read == [] and db.commits == 0


@pytest.mark.parametrize("label,method,path,params,token", WRONG_SCOPE_CASES, ids=[c[0] for c in WRONG_SCOPE_CASES])
def test_wrong_scope_returns_403(client, session, odoo_read, label, method, path, params, token):
    session([delivery(), source_event()])
    headers = {**bearer(token()), "Idempotency-Key": f"result:{EVENT_ID}:1"}
    response = client.request(
        method, path, params=params, headers=headers, json=submit_body() if method == "POST" else None
    )
    assert response.status_code == 403, response.text


# --- expired, tampered, wrong issuer, wrong audience -----------------------------


def test_expired_token_is_401(client, session):
    session([delivery(), source_event()])
    response = client.get(READ, headers=bearer(n8n_token("n8n.results.read", expires_in=-30)))
    assert response.status_code == 401
    assert response.json()["detail"] == "token validation failed"


def test_tampered_token_is_401(client, session):
    session([delivery(), source_event()])
    head, body, signature = n8n_token("n8n.results.read").split(".")
    tampered = f"{head}.{body}.{signature[::-1]}"
    response = client.get(READ, headers=bearer(tampered))
    assert response.status_code == 401
    assert response.json()["detail"] == "token validation failed"


def test_wrong_issuer_is_401(client, session):
    session([delivery(), source_event()])
    foreign = n8n_token("n8n.results.read", issuer="https://auth-staging.codestra.co/realms/other")
    response = client.get(READ, headers=bearer(foreign))
    assert response.status_code == 401
    assert response.json()["detail"] == "token validation failed"


def test_token_minted_for_another_environment_is_401(client, session):
    session([delivery(), source_event()])
    response = client.get(READ, headers=bearer(n8n_token("n8n.results.read", environment="production")))
    assert response.status_code == 401
    assert response.json()["detail"] == "environment denied"


def test_wrong_audience_is_401(client, session):
    session([delivery(), source_event()])
    response = client.get(READ, headers=bearer(n8n_token("n8n.results.read", audience="some-other-api")))
    assert response.status_code == 401
    assert response.json()["detail"] == "token validation failed"


# --- cross-tenant -------------------------------------------------------------


def test_cross_tenant_event_read_is_the_same_404_as_missing(client, session):
    session([None])
    missing = client.get(READ, headers=bearer(n8n_token("n8n.results.read")))
    session([delivery(), source_event()])
    foreign = n8n_token("n8n.results.read", campaigns=["OTHER-CAMPAIGN"], business_units=["OTHER"])
    hidden = client.get(READ, headers=bearer(foreign))
    assert missing.status_code == hidden.status_code == 404
    assert missing.json() == hidden.json()


def test_cross_tenant_campaign_read_is_denied_without_reaching_odoo(client, odoo_read):
    foreign = odoo_token(tenant_id="OTHER_TENANT", campaigns=["OTHER"], business_units=["OTHER"])
    response = client.get(CAMPAIGN_READ, params=PARAMS, headers=bearer(foreign))
    assert response.status_code == 403
    assert odoo_read == []


# --- wrong method and retired paths never reach a handler ----------------------


@pytest.mark.parametrize("path", [READ, CAMPAIGN_READ, DESIRED_STATE])
def test_wrong_method_on_get_route_does_not_match_the_service_jwt_handler(client, path):
    response = client.delete(path, headers=bearer(n8n_token("n8n.results.read")))
    # FastAPI answers 405 for a known path with an unsupported method; the shared-secret
    # guard (401) is also acceptable because the exemption is method-exact. Never 200.
    assert response.status_code in {401, 404, 405}, response.text


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/integrations/odoo/campaign-actions",
        "/api/v1/integrations/odoo/campaign-commands",
        "/api/v1/integration/campaign-actions",
    ],
)
def test_retired_paths_are_404_or_guarded(client, path):
    response = client.post(path, json={}, headers=bearer(n8n_token("n8n.results.submit")))
    assert response.status_code in {401, 404}, response.text


# --- unrelated routes keep their normal authentication --------------------------


def test_unrelated_integration_routes_still_require_the_shared_secret(client):
    denied = client.get("/api/v1/integrations/runtime")
    assert denied.status_code == 401
    assert denied.json()["detail"] == "unauthorized"
    jwt_only = client.get("/api/v1/integrations/runtime", headers=bearer(n8n_token("n8n.results.read")))
    assert jwt_only.status_code == 401
    assert jwt_only.json()["detail"] == "unauthorized"
