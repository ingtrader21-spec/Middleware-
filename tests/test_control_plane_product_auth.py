from __future__ import annotations

from typing import Any
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

from app.commands import CommandPolicy, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import AuthenticationError, AuthorizationError
from app.storage import MemoryInboxStore


def _token(client_id: str, scopes: list[str], *, tenant_id: str = "tenant-1") -> str:
    return jwt.encode(
        {
            "azp": client_id,
            "scope": " ".join(scopes),
            "aud": "middleware-api",
            "tenant_id": tenant_id,
            "sub": "user-123",
            "iss": "https://auth.codestra.co/realms/codestra",
            "iat": 1_700_000_000,
            "exp": 1_700_000_300,
            "jti": str(uuid4()),
        },
        "test-only-key",
        algorithm="HS256",
    )


class ProductTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationError("Authorization must be a Bearer token")
        try:
            claims = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except Exception as exc:
            raise AuthenticationError("invalid bearer token") from exc
        if claims.get("azp") != expected_client_id:
            raise AuthorizationError("token azp does not match producer")
        scopes = set(str(claims.get("scope") or "").split())
        if required_scope not in scopes:
            raise AuthorizationError("required scope is missing")
        return claims

    async def ready(self) -> bool:
        return True


def _runtime(test_settings) -> Runtime:
    policies = CommandPolicyRegistry(
        (
            CommandPolicy(
                prefix="crm.",
                target="odoo-19",
                capability="ODOO_WRITE",
                readback_required=True,
            ),
            CommandPolicy(
                prefix="crawler.",
                target="kyqra-crawler",
                capability="CRAWLER_EXECUTION",
                readback_required=True,
            ),
            CommandPolicy(
                prefix="email.",
                target="klyrow-email",
                capability="EMAIL_DELIVERY",
                readback_required=True,
            ),
            CommandPolicy(
                prefix="sms.",
                target="telnexa-sms",
                capability="SMS_DELIVERY",
                readback_required=True,
            ),
            CommandPolicy(
                prefix="social.",
                target="postly-social",
                capability="SOCIAL_PUBLISH",
                readback_required=True,
            ),
            CommandPolicy(
                prefix="telephony.",
                target="vicidial-restricted",
                capability="PRODUCTION_DIALING",
                readback_required=True,
            ),
        ),
        {
            "ODOO_WRITE": True,
            "CRAWLER_EXECUTION": True,
            "EMAIL_DELIVERY": True,
            "SMS_DELIVERY": True,
            "SOCIAL_PUBLISH": True,
            "PRODUCTION_DIALING": True,
        },
    )
    return Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=ProductTokenVerifier(),
        commands=CommandService(MemoryCommandStore(), policies),
    )


def _command(*, command_type: str = "crm.contact.create.v1", target: str = "odoo-19", capability: str = "ODOO_WRITE") -> dict[str, Any]:
    return {
        "command_id": str(uuid4()),
        "command_type": command_type,
        "command_version": "1.0",
        "target": target,
        "tenant_id": "tenant-1",
        "requested_by": "user-123",
        "correlation_id": "correlation-product-auth-001",
        "idempotency_key": "idempotency-product-auth-001",
        "capability": capability,
        "payload": {"contact_id": "contact-1"},
    }


def _headers(body: dict[str, Any], token: str | None) -> dict[str, str]:
    headers = {
        "X-Tenant-ID": body["tenant_id"],
        "X-Correlation-ID": body["correlation_id"],
        "Idempotency-Key": body["idempotency_key"],
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def test_valid_moneybee_token_can_submit_crm_command(test_settings) -> None:
    body = _command()
    token = _token("moneybee-backend", ["moneybee.middleware.command.write"])
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
        response = client.post("/v1/commands", json=body, headers=_headers(body, token))
    assert response.status_code == 202, response.text
    assert response.json()["state"] == "RECEIVED"


def test_n8n_umbrella_blocks_canonical_command_route(test_settings) -> None:
    body = _command()
    token = _token("n8n-automation", ["middleware.request.forward"])
    with TestClient(
        create_app(settings=test_settings, runtime=_runtime(test_settings))
    ) as client:
        response = client.post("/v1/commands", json=body, headers=_headers(body, token))
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "capability_disabled"


@pytest.mark.parametrize("path", ("/v1/odoo/commands", "/v1/crm/commands"))
def test_n8n_umbrella_blocks_domain_command_routes(test_settings, path: str) -> None:
    body = _command()
    token = _token("n8n-automation", ["middleware.request.forward"])
    with TestClient(
        create_app(settings=test_settings, runtime=_runtime(test_settings))
    ) as client:
        response = client.post(path, json=body, headers=_headers(body, token))
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "capability_disabled"


def test_n8n_umbrella_blocks_communications_before_persistence(test_settings) -> None:
    active = _runtime(test_settings)
    token = _token("n8n-automation", ["middleware.request.forward"])
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": "tenant-1",
        "X-Correlation-ID": "correlation-n8n-communications-001",
        "Idempotency-Key": "idempotency-n8n-communications-001",
    }
    body = {
        "channel": "email",
        "from": "sender@example.com",
        "to": ["recipient@example.com"],
        "content": {"text": "must remain blocked"},
    }

    with TestClient(create_app(settings=test_settings, runtime=active)) as client:
        response = client.post(
            "/v1/communications/messages",
            json=body,
            headers=headers,
        )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "capability_disabled"
    assert active.communications is not None
    assert active.communications.store.messages == {}
    assert active.communications.store.idempotency == {}


def test_missing_and_invalid_tokens_are_401(test_settings) -> None:
    body = _command()
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
        missing = client.post("/v1/commands", json=body, headers=_headers(body, None))
        invalid = client.post("/v1/commands", json=body, headers=_headers(body, "not.a.valid-jwt"))
    assert missing.status_code == 401
    assert invalid.status_code == 401


def test_wrong_moneybee_scope_is_403(test_settings) -> None:
    body = _command()
    token = _token("moneybee-backend", ["breero.middleware.command.write"])
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
        response = client.post("/v1/commands", json=body, headers=_headers(body, token))
    assert response.status_code == 403


def test_social_token_cannot_submit_crm_command(test_settings) -> None:
    body = _command()
    token = _token("social-codestra", ["social.middleware.command.write"])
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
        response = client.post("/v1/commands", json=body, headers=_headers(body, token))
    assert response.status_code == 403


def test_kyqra_can_submit_crawler_and_sms_commands(test_settings) -> None:
    token = _token("kyqra", ["kyqra.middleware.command.write"])
    for command_type, target, capability in (
        ("crawler.job.submit.v1", "kyqra-crawler", "CRAWLER_EXECUTION"),
        ("sms.message.submit.v1", "telnexa-sms", "SMS_DELIVERY"),
    ):
        body = _command(command_type=command_type, target=target, capability=capability)
        with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
            response = client.post("/v1/commands", json=body, headers=_headers(body, token))
        assert response.status_code == 202, (command_type, response.text)


def test_klyrow_can_submit_email_commands(test_settings) -> None:
    body = _command(
        command_type="email.message.submit.v1",
        target="klyrow-email",
        capability="EMAIL_DELIVERY",
    )
    token = _token("klyrow", ["klyrow.middleware.command.write"])
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
        response = client.post("/v1/commands", json=body, headers=_headers(body, token))
    assert response.status_code == 202, response.text


def test_products_cannot_cross_control_plane_boundaries(test_settings) -> None:
    cases = (
        (
            "kyqra",
            "kyqra.middleware.command.write",
            "email.message.submit.v1",
            "klyrow-email",
            "EMAIL_DELIVERY",
        ),
        (
            "klyrow",
            "klyrow.middleware.command.write",
            "sms.message.submit.v1",
            "telnexa-sms",
            "SMS_DELIVERY",
        ),
        (
            "social-codestra",
            "social.middleware.command.write",
            "email.message.submit.v1",
            "klyrow-email",
            "EMAIL_DELIVERY",
        ),
    )
    for client_id, scope, command_type, target, capability in cases:
        body = _command(command_type=command_type, target=target, capability=capability)
        token = _token(client_id, [scope])
        with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
            response = client.post("/v1/commands", json=body, headers=_headers(body, token))
        assert response.status_code == 403, (client_id, command_type, response.text)


def test_business_products_cannot_submit_telephony_commands(test_settings) -> None:
    for client_id, scope in (
        ("breero-backend", "breero.middleware.command.write"),
        ("transportation-backend", "transportation.middleware.command.write"),
        ("larim-a-backend", "larim-a.middleware.command.write"),
    ):
        body = _command(
            command_type="telephony.call.start.v1",
            target="vicidial-restricted",
            capability="PRODUCTION_DIALING",
        )
        token = _token(client_id, [scope])
        with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings))) as client:
            response = client.post("/v1/commands", json=body, headers=_headers(body, token))
        assert response.status_code == 403, (client_id, response.text)
