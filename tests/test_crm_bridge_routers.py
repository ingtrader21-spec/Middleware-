"""Contacts/opportunities/tickets routers: auth, tenant scoping, and error
mapping against a fake ``OdooCrmBridgeClient`` -- no real Odoo or database
involved. Reads are passthrough over ``app.adapters.odoo.crm_bridge_client``;
writes are V3 kernel wrappers (``crm.<entity>.<action>.v1`` commands on
``odoo-19``) and never reach the bridge inside the request.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from uuid import UUID, uuid4

import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from app.adapters.odoo.crm_bridge_client import (
    BridgeResponse,
    CrmBridgeNotConfigured,
    CrmBridgeNotFound,
    CrmBridgeUnavailable,
    get_crm_bridge_client,
)
from app.adapters.odoo import crm_bridge_client as crm_bridge_module
from app.api.v1 import contacts as contacts_module
from app.api.v1 import opportunities as opportunities_module
from app.api.v1 import tickets as tickets_module
from app.commands import CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.core.config import Settings, settings
from app.core.runtime import RuntimeContainer
from app.platform.adapters.fixtures import development_fixtures
from app.platform.runtime import build_platform_runtime, command_policies
from app.platform.safety import SafetyGate, SafetySwitches
from app.replay import MemoryReplayGuard
from app.router_registry import install_domain_error_handler
from app.storage import MemoryInboxStore

ISSUER = "https://identity.example.invalid/realms/crm-bridge-test"
AUDIENCE = "middleware-api-test"


class FakeBridgeClient:
    def __init__(self):
        self.calls: list[tuple] = []
        self.raise_error: Exception | None = None
        self.next_response = BridgeResponse(status_code=200, body={"ok": True})

    async def _record(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if self.raise_error:
            raise self.raise_error
        return self.next_response

    def __getattr__(self, name):
        async def method(*args, **kwargs):
            return await self._record(name, *args, **kwargs)
        return method


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
async def bridge_client():
    return FakeBridgeClient()


class KernelStack:
    """An in-memory V3 runtime for the write routes (ODOO_WRITE stays off
    unless a test enables it explicitly, exactly as in every environment)."""

    def __init__(self, monkeypatch) -> None:
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("ALLOW_IN_MEMORY_STORAGE", "true")
        self.settings = Settings.from_env()
        self.store = MemoryCommandStore()
        self.commands = CommandService(store=self.store, policies=command_policies(self.settings))
        self.runtime = RuntimeContainer(settings=self.settings, inbox=MemoryInboxStore(), replay=MemoryReplayGuard(), tokens=None, commands=self.commands)  # type: ignore[arg-type]
        self.runtime.platform = build_platform_runtime(self.settings, commands=self.commands, http=None, pool=None, service_id="middleware-integration-api", adapters=development_fixtures())

    def enable_odoo_write(self) -> None:
        """What a governed activation looks like: capability on, effect gates
        and umbrella on, environment allowed -- all of them, not one."""
        enabled = self.settings.replace(enable_external_delivery=True, odoo_write=True, umbrella_external_delivery_enabled=True)
        base = CommandPolicyRegistry.load()
        policies = command_policies(enabled, CommandPolicyRegistry(base.policies, {**base.capabilities, "ODOO_WRITE": True}))
        switches = SafetySwitches.load()
        gates = dict(switches.gates)
        odoo = gates["ODOO_WRITE"]
        gates["ODOO_WRITE"] = type(odoo)(**{**odoo.__dict__, "environments": (*odoo.environments, "test")})
        self.commands = CommandService(store=self.store, policies=policies)
        self.runtime.commands = self.commands
        self.runtime.platform = build_platform_runtime(
            enabled,
            commands=self.commands,
            http=None,
            pool=None,
            service_id="middleware-integration-api",
            adapters=development_fixtures(),
            safety=SafetyGate(enabled, policies, type(switches)(**{**switches.__dict__, "gates": gates})),
        )


@pytest.fixture
def kernel_stack(monkeypatch) -> KernelStack:
    return KernelStack(monkeypatch)


@pytest_asyncio.fixture
async def client(bridge_client, kernel_stack):
    app = FastAPI()
    app.include_router(contacts_module.router)
    app.include_router(opportunities_module.router)
    app.include_router(tickets_module.router)
    app.dependency_overrides[get_crm_bridge_client] = lambda: bridge_client
    app.state.runtime = kernel_stack.runtime
    install_domain_error_handler(app)  # the canonical error envelope, as create_app installs it

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_crm_bridge_dependency_uses_active_runtime_settings(monkeypatch):
    configured = object()
    created_with = []

    class FakeClient:
        def __init__(self, value):
            created_with.append(value)

    monkeypatch.setattr(crm_bridge_module, "OdooCrmBridgeClient", FakeClient)
    app = FastAPI()
    app.state.runtime = SimpleNamespace(settings=configured)

    @app.get("/dependency-check")
    async def dependency_check(client=Depends(get_crm_bridge_client)):
        return {"created": client is not None}

    with TestClient(app) as test_client:
        assert test_client.get("/dependency-check").json() == {"created": True}
    assert created_with == [configured]


@pytest.mark.asyncio
async def test_list_contacts_requires_auth(client):
    response = await client.get("/platform/v1/contacts", params={"tenant_id": "COD"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_contacts_rejects_tenant_mismatch(client, authority):
    response = await client.get(
        "/platform/v1/contacts",
        params={"tenant_id": "OTHER"},
        headers=_headers(authority(tenant_ids=("COD",))),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_bridge_tenant_binding_fails_closed(client, authority, bridge_client):
    bridge_client.configured_tenant_id = "OTHER"
    response = await client.get(
        "/platform/v1/contacts",
        params={"tenant_id": "COD"},
        headers=_headers(authority(tenant_ids=("COD",))),
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_list_contacts_forwards_bridge_response(client, authority, bridge_client):
    bridge_client.next_response = BridgeResponse(200, {"items": [{"profile_id": 1}]})
    response = await client.get(
        "/platform/v1/contacts",
        params={"tenant_id": "COD"},
        headers=_headers(authority(tenant_ids=("COD",))),
    )
    assert response.status_code == 200
    assert response.json() == {"items": [{"profile_id": 1}]}
    assert bridge_client.calls[0][0] == "list_contacts"


@pytest.mark.asyncio
async def test_create_contact_is_a_kernel_command_not_a_bridge_call(client, authority, bridge_client, kernel_stack):
    headers = {**_headers(authority(tenant_ids=("COD",))), "Idempotency-Key": "abc-123-000001", "X-Correlation-ID": "crm-corr-1"}
    body = {"name": "Jane Doe", "partner_id": 1, "campaign_id": 2, "integration_key": "k"}
    # ODOO_WRITE is off (PROVIDER_EFFECTS=0): the Safety Gate refuses and the bridge is never called.
    denied = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=headers, json=body)
    assert denied.status_code == 403, denied.text
    assert denied.json()["error"]["code"] == "safety_denied"
    assert bridge_client.calls == []

    kernel_stack.enable_odoo_write()
    response = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=headers, json=body)
    assert response.status_code == 202, response.text
    accepted = response.json()
    assert accepted["state"] == "RECEIVED" and accepted["correlation_id"] == "crm-corr-1"
    assert response.headers["Location"] == f"/platform/v1/operations/{accepted['operation_id']}"
    assert bridge_client.calls == []  # execution is asynchronous, through the Odoo adapter
    envelope = await kernel_stack.commands.load_envelope("COD", UUID(accepted["operation_id"]))
    assert envelope.command_type == "crm.contact.create.v1"
    assert envelope.target == "odoo-19" and envelope.capability == "ODOO_WRITE"
    assert envelope.idempotency_key == "abc-123-000001"
    assert envelope.payload == {"record": body}
    assert envelope.requested_by == "provisioning-service-subject"
    replay = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=headers, json=body)
    assert replay.status_code == 200 and replay.json()["duplicate"] is True
    short_key = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers={**headers, "Idempotency-Key": "short"}, json=body)
    assert short_key.status_code == 400


@pytest.mark.asyncio
async def test_retry_with_the_same_key_and_no_correlation_header_is_the_same_command(client, authority, bridge_client, kernel_stack):
    """The ledger binds the key to the whole envelope, correlation id
    included: a retry that repeats the Idempotency-Key but omits
    X-Correlation-ID must derive the same correlation id (200 duplicate),
    while a different payload under the same key is still identity reuse (409)."""
    kernel_stack.enable_odoo_write()
    headers = {**_headers(authority(tenant_ids=("COD",))), "Idempotency-Key": "abc-123-000002"}
    body = {"name": "Jane Doe", "partner_id": 1, "campaign_id": 2, "integration_key": "k"}
    first = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=headers, json=body)
    assert first.status_code == 202, first.text
    derived = first.json()["correlation_id"]
    UUID(derived)  # derived deterministically from (tenant, command type, key)
    retry = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=headers, json=body)
    assert retry.status_code == 200 and retry.json()["duplicate"] is True
    assert retry.json()["correlation_id"] == derived
    conflict = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=headers, json={**body, "name": "Janet"})
    assert conflict.status_code == 409
    # without either header nothing is claimed: every request is a new command
    bare = _headers(authority(tenant_ids=("COD",)))
    one = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=bare, json=body)
    two = await client.post("/platform/v1/contacts", params={"tenant_id": "COD"}, headers=bare, json=body)
    assert one.status_code == 202 and two.status_code == 202
    assert one.json()["operation_id"] != two.json()["operation_id"]


@pytest.mark.asyncio
async def test_get_contact_not_found_maps_to_404(client, authority, bridge_client):
    bridge_client.raise_error = CrmBridgeNotFound("/customer-profiles/9")
    response = await client.get(
        "/platform/v1/contacts/9",
        params={"tenant_id": "COD"},
        headers=_headers(authority(tenant_ids=("COD",))),
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_bridge_unavailable_maps_to_502(client, authority, bridge_client):
    bridge_client.raise_error = CrmBridgeUnavailable("connection refused")
    response = await client.get(
        "/platform/v1/opportunities/ext-1",
        params={"tenant_id": "COD"},
        headers=_headers(authority(tenant_ids=("COD",))),
    )
    assert response.status_code == 502


@pytest.mark.asyncio
async def test_bridge_not_configured_maps_to_503(client, authority, bridge_client):
    bridge_client.raise_error = CrmBridgeNotConfigured("odoo_crm_bridge_base_url must be set")
    response = await client.get(
        "/platform/v1/tickets",
        params={"tenant_id": "COD"},
        headers=_headers(authority(tenant_ids=("COD",))),
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_complete_task_is_a_kernel_command(client, authority, bridge_client, kernel_stack):
    kernel_stack.enable_odoo_write()
    response = await client.post(
        "/platform/v1/tasks/3/complete",
        params={"tenant_id": "COD"},
        headers={**_headers(authority(tenant_ids=("COD",))), "Idempotency-Key": "complete-task-3-0001"},
    )
    assert response.status_code == 202, response.text
    assert bridge_client.calls == []
    envelope = await kernel_stack.commands.load_envelope("COD", UUID(response.json()["operation_id"]))
    assert envelope.command_type == "crm.task.complete.v1"
    assert envelope.payload == {"task_id": 3, "record": {}}


@pytest.mark.asyncio
async def test_update_ticket_is_a_kernel_command(client, authority, bridge_client, kernel_stack):
    kernel_stack.enable_odoo_write()
    response = await client.patch(
        "/platform/v1/tickets/7",
        params={"tenant_id": "COD"},
        headers={**_headers(authority(tenant_ids=("COD",))), "Idempotency-Key": "update-ticket-7-0001"},
        json={"resolution": "fixed"},
    )
    assert response.status_code == 202, response.text
    assert bridge_client.calls == []
    envelope = await kernel_stack.commands.load_envelope("COD", UUID(response.json()["operation_id"]))
    assert envelope.command_type == "crm.ticket.update.v1"
    assert envelope.payload == {"ticket_id": 7, "record": {"resolution": "fixed"}}
