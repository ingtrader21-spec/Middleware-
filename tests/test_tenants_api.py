"""Real-signature regressions for GET /platform/v1/tenants.

No disposable PostgreSQL is required here (unlike test_session_context.py) -
this endpoint touches no local database at all, only codestra-foundation via
a stub HTTP transport, proving the request shape (scope requested, path)
rather than assuming FoundationClient's internals are correct.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.adapters.foundation import client as foundation_client_module
from app.api.v1 import tenants as tenants_module
from app.core.config import settings

ISSUER = "https://identity.example.invalid/realms/tenants-test"
AUDIENCE = "middleware-api-test"


class _StubFoundationTransport(httpx.AsyncBaseTransport):
    """Records every request it sees and returns a canned tenant list."""

    def __init__(self, *, status_code: int = 200) -> None:
        self.requests: list[httpx.Request] = []
        self.requested_scopes: list[tuple[str, ...]] = []
        self.status_code = status_code

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status_code != 200:
            return httpx.Response(self.status_code, json={"detail": "unavailable"})
        return httpx.Response(
            200,
            json=[
                {
                    "id": "COD",
                    "slug": "codestra",
                    "name": "Codestra",
                    "status": "ACTIVE",
                },
                {
                    "id": "SMT",
                    "slug": "smith-transport",
                    "name": "Smith Transport",
                    "status": "ACTIVE",
                },
            ],
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
        "keycloak_authorized_parties": "platform-console",
        "foundation_base_url": "http://foundation.internal",
        "foundation_token_url": "http://foundation.internal/token",
        "foundation_client_id": "middleware-foundation-reader",
        "foundation_client_secret": "test-secret",
    }.items():
        monkeypatch.setattr(settings, key, value)

    def token(
        role="platform_admin",
        scope="platform.tenants.read",
        subject="operator-1",
        **overrides,
    ):
        current = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "azp": "platform-console",
            "sub": subject,
            "iat": current,
            "exp": current + 300,
            "jti": str(uuid4()),
            "scope": scope,
            "realm_access": {"roles": [role]},
            **overrides,
        }
        return jwt.encode(claims, private, algorithm="RS256")

    return token


@pytest.fixture
def client_factory(monkeypatch):
    def make(stub_transport):
        class _StubTokenManager:
            async def get_token(self, *_args, **kwargs) -> str:
                stub_transport.requested_scopes.append(kwargs["scopes"])
                return "stub-foundation-token"

        _real_async_client = httpx.AsyncClient

        def _fake_http_client_factory(*_args, **_kwargs):
            return _real_async_client(transport=stub_transport)

        monkeypatch.setattr(httpx, "AsyncClient", _fake_http_client_factory)
        monkeypatch.setattr(
            foundation_client_module.FoundationClient,
            "__init__",
            lambda self, settings_obj, **_kwargs: setattr(
                self, "_settings", settings_obj
            )
            or setattr(self, "_token_manager", _StubTokenManager()),
        )

        app = FastAPI()
        app.include_router(tenants_module.router)
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    return make


@pytest.mark.asyncio
async def test_platform_admin_lists_all_tenants(authority, client_factory):
    stub_transport = _StubFoundationTransport()
    async with client_factory(stub_transport) as http_client:
        response = await http_client.get(
            "/platform/v1/tenants?status=ACTIVE&limit=2&offset=10",
            headers={"Authorization": "Bearer " + authority(role="platform_admin")},
        )
    assert response.status_code == 200
    body = response.json()
    assert [tenant["id"] for tenant in body["tenants"]] == ["COD", "SMT"]
    assert stub_transport.requests[0].url.path == "/v1/tenants"
    assert dict(stub_transport.requests[0].url.params) == {
        "status": "ACTIVE",
        "limit": "2",
        "offset": "10",
    }
    # codestra-foundation's authoritative route contract requires the admin
    # scope for this cross-tenant read; there is no foundation.tenant.list.
    assert stub_transport.requested_scopes == [("foundation.admin",)]
    assert body["pagination"] == {"limit": 2, "offset": 10, "returned": 2}


@pytest.mark.asyncio
async def test_platform_operator_can_also_list_tenants(authority, client_factory):
    stub_transport = _StubFoundationTransport()
    async with client_factory(stub_transport) as http_client:
        response = await http_client.get(
            "/platform/v1/tenants",
            headers={"Authorization": "Bearer " + authority(role="platform_operator")},
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_unrecognized_role_is_rejected(authority, client_factory):
    stub_transport = _StubFoundationTransport()
    async with client_factory(stub_transport) as http_client:
        response = await http_client.get(
            "/platform/v1/tenants",
            headers={"Authorization": "Bearer " + authority(role="tenant_admin")},
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_platform_reviewer_cannot_enumerate_tenants(authority, client_factory):
    stub_transport = _StubFoundationTransport()
    async with client_factory(stub_transport) as http_client:
        response = await http_client.get(
            "/platform/v1/tenants",
            headers={"Authorization": "Bearer " + authority(role="platform_reviewer")},
        )
    assert response.status_code == 403
    assert stub_transport.requests == []


@pytest.mark.asyncio
async def test_missing_bearer_is_rejected(client_factory):
    stub_transport = _StubFoundationTransport()
    async with client_factory(stub_transport) as http_client:
        response = await http_client.get("/platform/v1/tenants")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_foundation_unavailable_fails_closed_not_open(authority, client_factory):
    stub_transport = _StubFoundationTransport(status_code=503)
    async with client_factory(stub_transport) as http_client:
        response = await http_client.get(
            "/platform/v1/tenants",
            headers={"Authorization": "Bearer " + authority(role="platform_admin")},
        )
    assert response.status_code == 503
