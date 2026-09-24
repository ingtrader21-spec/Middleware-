from __future__ import annotations

import json
import ssl
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.core.config import ConfigurationError
from app.klyrow_email_adapter import KlyrowEmailAdapter, KlyrowEmailAdapterError
from app.temporal_workflows import CommandExecutionRequest

BASE_URL = "https://klyrow-email-api:18000"
TENANT = "tenant-1"
SENDER = "billing@codestra.co"
RECIPIENTS = ["customer@example.com"]

ENV = {
    "KLYROW_EMAIL_API_BASE_URL": BASE_URL,
    "KLYROW_EMAIL_MTLS_CA_FILE": "/run/secrets/ca.pem",
    "KLYROW_EMAIL_MTLS_CERT_FILE": "/run/secrets/cert.pem",
    "KLYROW_EMAIL_MTLS_KEY_FILE": "/run/secrets/key.pem",
    "KLYROW_EMAIL_OIDC_CLIENT_SECRET_FILE": "/run/secrets/client-secret",
}


class StubSettings:
    def __init__(self, *, app_env: str = "staging", email_enabled: bool = True,
                 source_sha: str = "a" * 40) -> None:
        self.app_env = app_env
        self.email_delivery_enabled = email_enabled
        self.source_sha = source_sha


def execution_request(**overrides: Any) -> CommandExecutionRequest:
    identity = str(uuid4())
    payload: dict[str, Any] = {
        "message_id": str(uuid4()),
        "channel": "email",
        "from": SENDER,
        "to": list(RECIPIENTS),
        "content": {
            "subject": "Your invoice",
            "text": "Invoice attached.",
        },
        "scheduled_at": None,
        "metadata": {"recipientCount": 1},
    }
    payload.update(overrides.pop("payload_overrides", {}))
    fields: dict[str, Any] = {
        "command_id": identity,
        "command_type": "email.message.send.v1",
        "command_version": "1.0",
        "target": "klyrow-email",
        "tenant_id": TENANT,
        "requested_by": "codestra-communication",
        "correlation_id": f"correlation-{identity}",
        "idempotency_key": f"idempotency-{identity}",
        "capability": "EMAIL_DELIVERY",
        "payload": payload,
        "authenticated_client_id": "codestra-communication",
    }
    fields.update(overrides)
    return CommandExecutionRequest(**fields)


@pytest.fixture(autouse=True)
def _stub_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub TLS/secret material and route requests through a MockTransport."""

    monkeypatch.setattr(
        KlyrowEmailAdapter,
        "_tls_context",
        lambda self: ssl.create_default_context(),
    )
    monkeypatch.setattr(
        KlyrowEmailAdapter,
        "_secret_file",
        lambda self, name: "x" * 40,
    )

    original = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("verify", None)
        kwargs["transport"] = httpx.MockTransport(_stub_transport.handler)  # type: ignore[attr-defined]
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def set_handler(handler: Any) -> None:
    _stub_transport.handler = handler  # type: ignore[attr-defined]


def token_response() -> httpx.Response:
    return httpx.Response(200, json={"access_token": "token-abc", "expires_in": 300})


def routing_handler(
    *,
    message: httpx.Response | None = None,
    status: httpx.Response | None = None,
    seen: dict[str, Any] | None = None,
) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return token_response()
        if seen is not None:
            seen.setdefault("requests", []).append(request)
        if request.method == "GET":
            assert status is not None, "unexpected read-back"
            return status
        assert message is not None, "unexpected send"
        return message

    return handler


def accepted(command_id: str) -> dict[str, Any]:
    return {"message_id": command_id, "status": "accepted"}


def status_body(command_id: str, **overrides: Any) -> dict[str, Any]:
    body = {
        "message_id": command_id,
        "status": "delivered",
        "sender": SENDER,
        "recipients": list(RECIPIENTS),
    }
    body.update(overrides)
    return body


def adapter(**kwargs: Any) -> KlyrowEmailAdapter:
    return KlyrowEmailAdapter(
        StubSettings(**kwargs.pop("settings", {})),  # type: ignore[arg-type]
        env=kwargs.pop("env", ENV),
    )


def production_authorization(**updates: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    value: dict[str, Any] = {
        "schemaVersion": "1.0",
        "tenantId": TENANT,
        "policyVersion": 2,
        "mode": "TRANSACTIONAL_PRODUCTION",
        "authorizationState": "ACTIVE",
        "killSwitchOpen": True,
        "changeId": "CHG-EMAIL-001",
        "category": "transactional",
        "validFrom": (now - timedelta(minutes=5)).isoformat(),
        "validUntil": (now + timedelta(hours=1)).isoformat(),
        "provider": "klyrow-postal",
        "environment": "production",
        "approvedReleaseSha": "a" * 40,
        "authorizationTimestamp": (now - timedelta(minutes=10)).isoformat(),
        "activationTimestamp": (now - timedelta(minutes=5)).isoformat(),
    }
    value.update(updates)
    return value


@pytest.mark.asyncio
async def test_execute_posts_the_provider_document_with_bearer_and_mtls_headers() -> None:
    seen: dict[str, Any] = {}
    command = execution_request()
    set_handler(
        routing_handler(
            message=httpx.Response(202, json=accepted(command.command_id)),
            seen=seen,
        )
    )
    result = await adapter().execute(command)

    assert result.status == "accepted"
    assert result.provider_operation_id == command.command_id
    sent = seen["requests"][0]
    assert str(sent.url) == f"{BASE_URL}/v1/email/messages"
    assert sent.headers["authorization"] == "Bearer token-abc"
    assert sent.headers["idempotency-key"] == command.idempotency_key
    assert sent.headers["x-tenant-id"] == TENANT
    assert sent.headers["x-codestra-classification"] == "transactional"


@pytest.mark.asyncio
async def test_execute_is_refused_while_the_capability_is_closed() -> None:
    command = execution_request()
    set_handler(routing_handler(message=httpx.Response(202, json=accepted(command.command_id))))
    with pytest.raises(KlyrowEmailAdapterError, match="email delivery is disabled"):
        await adapter(settings={"email_enabled": False}).execute(command)


@pytest.mark.asyncio
async def test_production_requires_server_injected_authorization_bound_to_release() -> None:
    missing = execution_request()
    set_handler(routing_handler(message=httpx.Response(202, json=accepted(missing.command_id))))
    with pytest.raises(KlyrowEmailAdapterError, match="authorization is required"):
        await adapter(settings={"app_env": "production"}).execute(missing)

    seen: dict[str, Any] = {}
    command = execution_request(payload_overrides={
        "metadata": {
            "category": "transactional",
            "productionAuthorization": production_authorization(),
        }
    })
    set_handler(routing_handler(
        message=httpx.Response(202, json=accepted(command.command_id)), seen=seen
    ))
    assert (await adapter(settings={"app_env": "production"}).execute(command)).status == "accepted"
    body = json.loads(seen["requests"][0].read())
    binding = body["metadata"]["productionAuthorization"]["commandBinding"]
    assert binding["messageId"] == command.command_id
    assert binding["correlationId"] == command.correlation_id
    assert binding["sender"] == SENDER

    mismatch = execution_request(payload_overrides={
        "metadata": {
            "category": "transactional",
            "productionAuthorization": production_authorization(
                approvedReleaseSha="b" * 40
            ),
        }
    })
    set_handler(routing_handler(message=httpx.Response(202, json=accepted(mismatch.command_id))))
    with pytest.raises(KlyrowEmailAdapterError, match="release does not match"):
        await adapter(settings={"app_env": "production"}).execute(mismatch)


@pytest.mark.asyncio
async def test_execute_rejects_commands_it_does_not_own() -> None:
    set_handler(routing_handler(message=httpx.Response(202, json={})))
    with pytest.raises(KlyrowEmailAdapterError, match="does not own"):
        await adapter().execute(execution_request(target="telnexa-sms"))
    with pytest.raises(KlyrowEmailAdapterError, match="capability"):
        await adapter().execute(execution_request(capability="SMS_DELIVERY"))
    with pytest.raises(KlyrowEmailAdapterError, match="unsupported"):
        await adapter().execute(execution_request(command_type="email.message.submit.v1"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"from": "not-an-address"}, "sender is not a valid"),
        ({"to": []}, "exactly one recipient"),
        ({"to": ["a@example.com", "a@example.com"]}, "exactly one recipient"),
        ({"to": ["nope"]}, "not all valid addresses"),
        ({"content": {"subject": "empty"}}, "requires text, html, or templateId"),
        ({"channel": "sms"}, "channel must be email"),
        ({"provider_token": "leaked"}, "forbidden secret keys"),
    ],
)
async def test_payload_validation_is_fail_closed(
    overrides: dict[str, Any], match: str
) -> None:
    set_handler(routing_handler(message=httpx.Response(202, json={})))
    with pytest.raises(KlyrowEmailAdapterError, match=match):
        await adapter().execute(execution_request(payload_overrides=overrides))


@pytest.mark.asyncio
async def test_recipient_ceiling_is_enforced() -> None:
    set_handler(routing_handler(message=httpx.Response(202, json={})))
    too_many = [f"user{index}@example.com" for index in range(1001)]
    with pytest.raises(KlyrowEmailAdapterError, match="exactly one recipient"):
        await adapter().execute(execution_request(payload_overrides={"to": too_many}))


@pytest.mark.asyncio
async def test_a_response_that_does_not_bind_the_command_identity_is_rejected() -> None:
    command = execution_request()
    set_handler(
        routing_handler(message=httpx.Response(202, json={"message_id": "someone-else"}))
    )
    with pytest.raises(KlyrowEmailAdapterError, match="did not bind the command identity"):
        await adapter().execute(command)


@pytest.mark.asyncio
async def test_interrupted_write_is_resolved_by_readback_not_a_resend() -> None:
    command = execution_request()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return token_response()
        calls.append(request)
        if request.method == "POST":
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json=status_body(command.command_id))

    set_handler(handler)
    result = await adapter().execute(command)

    assert result.status == "accepted"
    assert "read-back confirmed" in result.detail
    assert result.readback_evidence is not None
    assert result.readback_evidence["status"] == "delivered"
    # Exactly one send attempt, then a GET read-back. Never a second POST.
    assert [call.method for call in calls] == ["POST", "GET"]


@pytest.mark.asyncio
async def test_interrupted_write_stays_failed_when_readback_does_not_match() -> None:
    command = execution_request()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return token_response()
        if request.method == "POST":
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(
            200, json=status_body(command.command_id, recipients=["other@example.com"])
        )

    set_handler(handler)
    with pytest.raises(KlyrowEmailAdapterError, match="submission failed"):
        await adapter().execute(command)


@pytest.mark.asyncio
async def test_readback_matches_only_an_accepted_provider_status() -> None:
    command = execution_request()
    set_handler(
        routing_handler(status=httpx.Response(200, json=status_body(command.command_id)))
    )
    assert (await adapter().readback(command)).status == "matched"

    set_handler(
        routing_handler(
            status=httpx.Response(
                200, json=status_body(command.command_id, status="bounced")
            )
        )
    )
    assert (await adapter().readback(command)).status == "mismatch"


@pytest.mark.asyncio
async def test_template_reference_is_forwarded_not_expanded() -> None:
    seen: dict[str, Any] = {}
    template_id = str(uuid4())
    command = execution_request(
        payload_overrides={
            "content": {
                "templateId": template_id,
                "templateVersion": 3,
                "variables": {"name": "Ada"},
            }
        }
    )
    set_handler(
        routing_handler(
            message=httpx.Response(202, json=accepted(command.command_id)), seen=seen
        )
    )
    await adapter().execute(command)

    body = seen["requests"][0].read().decode()
    assert template_id in body
    assert '"template_version":3' in body.replace(" ", "")
    assert "Ada" in body


@pytest.mark.asyncio
async def test_an_unapproved_endpoint_is_refused() -> None:
    set_handler(routing_handler(message=httpx.Response(202, json={})))
    hostile = dict(ENV, KLYROW_EMAIL_API_BASE_URL="https://attacker.example.com")
    # A rejected endpoint must be a clean configuration failure, never an
    # "unknown outcome" that implies mail might have been sent.
    with pytest.raises(ConfigurationError, match="not an approved private endpoint"):
        await adapter(env=hostile).execute(execution_request())
