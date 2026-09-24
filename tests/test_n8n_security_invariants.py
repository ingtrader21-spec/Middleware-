from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.commands import CommandPolicy, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import AuthenticationError
from app.storage import MemoryInboxStore


class ControlledN8nTokenVerifier:
    def __init__(
        self,
        *,
        tenant_id: str = "tenant-1",
        subject: str = "n8n-service-subject",
    ) -> None:
        self.tenant_id = tenant_id
        self.subject = subject
        self.calls: list[tuple[str, str, str]] = []

    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        self.calls.append((authorization, expected_client_id, required_scope))
        if expected_client_id != "n8n-automation":
            raise AuthenticationError("unexpected n8n client")
        if authorization != f"Bearer {required_scope}":
            raise AuthenticationError("invalid n8n token")
        return {
            "azp": "n8n-automation",
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": self.tenant_id,
            "sub": self.subject,
        }

    async def ready(self) -> bool:
        return True


def _policy() -> CommandPolicyRegistry:
    return CommandPolicyRegistry(
        (
            CommandPolicy(
                prefix="crm.",
                target="odoo-19",
                capability="ODOO_WRITE",
                readback_required=True,
            ),
        ),
        {"ODOO_WRITE": True},
    )


def _body() -> dict[str, Any]:
    command_id = str(uuid4())
    return {
        "command_id": command_id,
        "command_type": "crm.lead.upsert",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "tenant-1",
        "requested_by": "n8n-service-subject",
        "correlation_id": "corr-security-invariants",
        "idempotency_key": "idem-security-invariants",
        "capability": "ODOO_WRITE",
        "payload": {
            "lead_source": "synthetic-form",
            "source_record_id": f"source-{command_id}",
            "initial_stage": "review_pending",
            "review_required": True,
            "allow_external_contact": False,
            "provenance": {
                "method": "submitted_by_person",
                "captured_by": "security-test",
                "source_reference": "synthetic://security-test",
                "legal_basis": "unknown_review_required",
                "content_digest": "a" * 64,
            },
            "consent": {
                "status": "unknown",
                "captured_at": "2026-08-30T16:00:00+00:00",
                "policy_version": "test-v1",
                "channels": {"email": False, "sms": False, "phone": False},
            },
            "lead": {
                "name": "CODESTRA-INTEGRATION-TEST-Lead",
                "description": "Synthetic test only.",
                "contact": {
                    "name": "Synthetic Contact",
                    "email": "synthetic@example.invalid",
                    "phone": "+18095550199",
                    "preferred_language": "en",
                },
                "company": {
                    "name": "Synthetic Company",
                    "domain": "example.invalid",
                    "industry": "Testing",
                },
                "campaign_code": None,
                "tags": [],
            },
        },
    }


def _headers(
    body: dict[str, Any],
    *,
    scope: str = "middleware.request.forward",
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {scope}",
        "X-Tenant-ID": str(body["tenant_id"]),
        "X-Correlation-ID": str(body["correlation_id"]),
        "Idempotency-Key": str(body["idempotency_key"]),
    }


def _client(
    test_settings,
    verifier: ControlledN8nTokenVerifier,
    *,
    provider_writes_enabled: bool = True,
) -> TestClient:
    settings = test_settings.replace(
        umbrella_n8n_external_provider_writes=provider_writes_enabled,
    )
    runtime = Runtime(
        settings=settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=verifier,
        commands=CommandService(MemoryCommandStore(), _policy()),
    )
    # The deprecated /v1/integrations/n8n/* aliases exist only on the monolith.
    return TestClient(create_app(settings=settings, runtime=runtime, legacy_monolith=True))


def test_n8n_provider_write_umbrella_blocks_durable_submission(test_settings) -> None:
    verifier = ControlledN8nTokenVerifier()
    body = _body()

    with _client(test_settings, verifier, provider_writes_enabled=False) as client:
        response = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers=_headers(body),
        )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "capability_disabled"


def test_legacy_n8n_aliases_publish_deprecation_and_successor_metadata(
    test_settings,
) -> None:
    verifier = ControlledN8nTokenVerifier()
    body = _body()

    with _client(test_settings, verifier) as client:
        submitted = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers=_headers(body),
        )
        assert submitted.status_code == 202, submitted.text
        assert submitted.headers["deprecation"] == "true"
        assert submitted.headers["sunset"] == "Wed, 30 Jun 2027 23:59:59 GMT"
        assert "/v2/automation/commands" in submitted.headers["link"]

        status = client.get(
            f"/v1/integrations/n8n/operations/{body['command_id']}",
            headers={
                "Authorization": "Bearer middleware.status.read",
                "X-Tenant-ID": "tenant-1",
            },
        )
        assert status.status_code == 200, status.text
        assert status.headers["deprecation"] == "true"
        assert f"/v2/automation/commands/{body['command_id']}" in status.headers["link"]


def test_token_tenant_overrides_matching_body_and_header_assertions(test_settings) -> None:
    verifier = ControlledN8nTokenVerifier(tenant_id="tenant-2")
    body = _body()

    with _client(test_settings, verifier) as client:
        response = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers=_headers(body),
        )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "authorization_denied"


@pytest.mark.parametrize(
    ("header_name", "replacement"),
    (
        ("X-Tenant-ID", "tenant-2"),
        ("X-Correlation-ID", "corr-wrong"),
        ("Idempotency-Key", "idem-wrong-value"),
    ),
)
def test_all_forwarding_headers_must_equal_the_command_body(
    test_settings,
    header_name: str,
    replacement: str,
) -> None:
    verifier = ControlledN8nTokenVerifier()
    body = _body()
    headers = _headers(body)
    headers[header_name] = replacement

    with _client(test_settings, verifier) as client:
        response = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers=headers,
        )

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "invalid_request"


def test_gateway_identity_headers_never_replace_middleware_bearer_validation(
    test_settings,
) -> None:
    verifier = ControlledN8nTokenVerifier()
    body = _body()
    headers = _headers(body)
    headers.pop("Authorization")
    headers.update(
        {
            "X-Consumer-ID": "n8n-automation",
            "X-Consumer-Username": "n8n-automation",
            "X-Authenticated-Scope": "middleware.request.forward",
            "X-Authenticated-Tenant-ID": "tenant-1",
        }
    )

    with _client(test_settings, verifier) as client:
        response = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers=headers,
        )

    assert response.status_code == 401, response.text
    assert response.json()["error"]["code"] == "authentication_failed"
    assert verifier.calls == [("", "n8n-automation", "middleware.request.forward")]


def test_token_subject_is_the_only_command_actor_authority(test_settings) -> None:
    verifier = ControlledN8nTokenVerifier(subject="another-service-subject")
    body = _body()

    with _client(test_settings, verifier) as client:
        response = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers=_headers(body),
        )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "capability_disabled"


def test_status_reads_remain_scoped_to_the_verified_token_tenant(test_settings) -> None:
    verifier = ControlledN8nTokenVerifier()
    body = _body()

    with _client(test_settings, verifier) as client:
        submitted = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers=_headers(body),
        )
        assert submitted.status_code == 202, submitted.text

        verifier.tenant_id = "tenant-2"
        response = client.get(
            f"/v1/integrations/n8n/operations/{body['command_id']}",
            headers={
                "Authorization": "Bearer middleware.status.read",
                "X-Tenant-ID": "tenant-1",
            },
        )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "authorization_denied"
