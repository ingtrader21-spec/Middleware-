"""Real-database regressions for GET /platform/v1/session/context and select.

codestra-foundation's tenant/entitlement API is not reachable in this test
sandbox, so its client is exercised against a stub HTTP transport (not
mocked at the Python-call level) - this proves the actual request shape
(path, bearer auth) rather than assuming FoundationClient's internals are
correct. The saga-derived parts of session context (campaigns/products) are
exercised against a real disposable PostgreSQL, same convention as
tests/test_agent_provisioning_reads.py.
"""

from __future__ import annotations

import os
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.adapters.foundation import client as foundation_client_module
from app.api.v1 import agent_provisioning
from app.api.v1 import session_context as session_context_module
from app.core.config import settings

ISSUER = "https://identity.example.invalid/realms/session-context-test"
AUDIENCE = "middleware-api-test"

pytestmark = pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)


class _StubFoundationTransport(httpx.AsyncBaseTransport):
    """Records every request it sees and returns a canned tenant/entitlement body."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path.endswith("/entitlements"):
            return httpx.Response(
                200,
                json=[
                    {"entitlement_key": "phone", "enabled": True, "limit_value": None, "unit": None},
                ],
            )
        return httpx.Response(
            200,
            json={"id": "COD", "slug": "cod", "name": "Codestra", "status": "ACTIVE"},
        )


@pytest.fixture
def authority(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Keys:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=private.public_key())

    monkeypatch.setattr(jwt, "PyJWKClient", Keys)
    for key, value in {
        "keycloak_issuer": ISSUER,
        "keycloak_audience": AUDIENCE,
        "keycloak_jwks_url": ISSUER + "/certs",
        "agent_provisioning_authorized_parties": "provisioning-service",
        "agent_provisioning_policy_revision": "7",
        "live_identity_provisioning_enabled": False,
        "live_writes_enabled": False,
        "foundation_base_url": "http://foundation.internal",
        "foundation_token_url": "http://foundation.internal/token",
        "foundation_client_id": "middleware-foundation-reader",
        "foundation_client_secret": "test-secret",
    }.items():
        monkeypatch.setattr(settings, key, value)

    def token(
        scope="identity.request integration.configure tenant.provision",
        subject="provisioning-service-subject",
        azp="provisioning-service",
        tenant_ids=("COD",),
        **overrides,
    ):
        current = int(time.time())
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "azp": azp,
            "sub": subject, "iat": current, "exp": current + 300,
            "jti": str(uuid4()), "scope": scope, "tenant_ids": list(tenant_ids),
            **overrides,
        }
        return jwt.encode(claims, private, algorithm="RS256")

    return token


@pytest_asyncio.fixture
async def client(monkeypatch):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def isolated_session():
        async with session_factory() as session:
            yield session

    stub_transport = _StubFoundationTransport()

    class _StubTokenManager:
        async def get_token(self, *_args, **_kwargs) -> str:
            return "stub-foundation-token"

    _real_async_client = httpx.AsyncClient

    def _fake_http_client_factory(*_args, **_kwargs):
        return _real_async_client(transport=stub_transport)

    # FoundationClient opens its own httpx.AsyncClient inside
    # session_context._resolve_context; patch httpx.AsyncClient globally for
    # the duration of this fixture so that call routes to the stub instead
    # of a real network socket, and stub token acquisition so no real
    # Keycloak client-credentials call happens either.
    monkeypatch.setattr(httpx, "AsyncClient", _fake_http_client_factory)
    monkeypatch.setattr(
        foundation_client_module.FoundationClient,
        "__init__",
        lambda self, settings_obj, **_kwargs: setattr(
            self, "_settings", settings_obj
        ) or setattr(self, "_token_manager", _StubTokenManager()),
    )

    app = FastAPI()
    app.include_router(agent_provisioning.router)
    app.include_router(session_context_module.router)
    app.dependency_overrides[agent_provisioning.get_session] = isolated_session

    async with engine.begin() as connection:
        await connection.execute(text("DELETE FROM agent_provisioning_audit"))
        await connection.execute(text("DELETE FROM agent_provisioning_step"))
        await connection.execute(text("DELETE FROM agent_provisioning_request"))
        await connection.execute(
            text("DELETE FROM idempotency_record WHERE scope = 'agent_provisioning'")
        )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client, stub_transport

    app.dependency_overrides.clear()
    await engine.dispose()


def _provision_body(**overrides) -> dict:
    body = {
        "request_id": f"req_{uuid4().hex[:12]}",
        "tenant_id": "COD",
        "employee_id": "COD.2026.00016",
        "identity": {"email": "appolon1908@gmail.com", "first_name": "A", "last_name": "P"},
        "campaigns": [{
            "campaign_id": "TEST_SYN", "role": "supervisor",
            "campaign_email": "a.p@codestra-test.invalid", "sms_sender": "CODESTRA",
        }],
        "channels": {"odoo": True, "phone": True, "webrtc": True, "sms": True, "email": True},
        "telephony": {
            "existing_extension": "6101", "incoming_allowed": True,
            "outgoing_allowed": True, "max_webrtc_sessions": 1,
        },
    }
    body.update(overrides)
    return body


def _provision_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": uuid4().hex,
        "X-Correlation-ID": str(uuid4()),
        "X-Policy-Revision": "7",
    }


@pytest.mark.asyncio
async def test_session_context_requires_bearer_token(client):
    http_client, _ = client
    response = await http_client.get("/platform/v1/session/context?tenant_id=COD")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_session_context_wrong_tenant_claim_is_denied(client, authority):
    http_client, _ = client
    token = authority(tenant_ids=("OTHER",))
    response = await http_client.get(
        "/platform/v1/session/context?tenant_id=COD",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_session_context_calls_real_foundation_contract_shape(client, authority):
    http_client, stub_transport = client
    response = await http_client.get(
        "/platform/v1/session/context?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "COD"
    assert body["tenant_status"] == "ACTIVE"
    assert body["entitlements"] == [{"key": "phone", "enabled": True}]
    # proves the client hit codestra-foundation's real path shape, not a
    # guessed one
    paths_hit = {request.url.path for request in stub_transport.requests}
    assert "/v1/tenants/COD" in paths_hit
    assert "/v1/tenants/COD/entitlements" in paths_hit
    auth_headers = {request.headers.get("authorization") for request in stub_transport.requests}
    assert auth_headers == {"Bearer stub-foundation-token"}


@pytest.mark.asyncio
async def test_session_context_reflects_real_campaign_membership(client, authority):
    http_client, _ = client
    await http_client.post(
        "/platform/v1/agent-provisioning/requests",
        json=_provision_body(), headers=_provision_headers(authority()),
    )
    response = await http_client.get(
        "/platform/v1/session/context?tenant_id=COD",
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert {"campaign_id": "TEST_SYN", "role": "supervisor"} in body["campaigns"]


@pytest.mark.asyncio
async def test_select_context_rejects_unauthorized_campaign(client, authority):
    http_client, _ = client
    await http_client.post(
        "/platform/v1/agent-provisioning/requests",
        json=_provision_body(), headers=_provision_headers(authority()),
    )
    response = await http_client.post(
        "/platform/v1/session/context/select",
        json={"tenant_id": "COD", "campaign_id": "NOT_A_REAL_CAMPAIGN"},
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_select_context_accepts_authorized_campaign(client, authority):
    http_client, _ = client
    await http_client.post(
        "/platform/v1/agent-provisioning/requests",
        json=_provision_body(), headers=_provision_headers(authority()),
    )
    response = await http_client.post(
        "/platform/v1/session/context/select",
        json={"tenant_id": "COD", "campaign_id": "TEST_SYN"},
        headers={"Authorization": f"Bearer {authority()}"},
    )
    assert response.status_code == 200
    assert response.json()["selected_campaign_id"] == "TEST_SYN"
