from __future__ import annotations

import hashlib
import json
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from app.core.config import ConfigurationError, Settings
from app.telnexa_provider_adapter import TelnexaProviderAdapterError, TelnexaSmsAdapter
from app.temporal_workflows import CommandExecutionRequest

BASE_URL = "https://telnexa.internal.invalid"
API_KEY = "tnx_" + "a" * 32  # Synthetic fixture; never a provider credential.
TENANT = "tenant-1"
ENV = {"TELNEXA_SMS_BASE_URL": BASE_URL, "TELNEXA_SMS_API_KEY": API_KEY}


class StubSettings:
    """Only the surface the adapter reads."""

    def __init__(self, *, app_env: str = "staging", sms_enabled: bool = True) -> None:
        self.app_env = app_env
        self.sms_delivery_enabled = sms_enabled


def settings_stub(*, app_env: str = "staging", sms_enabled: bool = True) -> Settings:
    # This unit fixture deliberately supplies only the adapter's two settings.
    # Production code continues to require the complete validated Settings object.
    return cast(Settings, StubSettings(app_env=app_env, sms_enabled=sms_enabled))


def execution_request(**overrides: Any) -> CommandExecutionRequest:
    identity = str(uuid4())
    payload: dict[str, Any] = {
        "message_id": str(uuid4()),
        "channel": "sms",
        "destination": "+15551234567",
        "sender": "Codestra",
        "content": "Your appointment is confirmed.",
        "encoding": "GSM-7",
        "characters": 29,
        "segments": 1,
        "category": "transactional",
        "client_reference": f"ref-{identity}",
        "scheduled_at": None,
        "billing_account_id": "billing-account-1",
        "campaign_id": None,
    }
    payload.update(overrides.pop("payload_overrides", {}))
    fields: dict[str, Any] = {
        "command_id": identity,
        "command_type": "sms.message.submit.v1",
        "command_version": "1.0",
        "target": "telnexa-sms",
        "tenant_id": TENANT,
        "requested_by": "codestra-communication",
        "correlation_id": identity,
        "idempotency_key": f"idempotency-{identity}",
        "capability": "SMS_DELIVERY",
        "payload": payload,
        "authenticated_client_id": "codestra-communication",
    }
    fields.update(overrides)
    return CommandExecutionRequest(**fields)


@pytest.fixture(autouse=True)
def _mock_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    original = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        handler = _mock_httpx.handler  # type: ignore[attr-defined]
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def set_handler(handler: Any) -> None:
    _mock_httpx.handler = handler  # type: ignore[attr-defined]


def accepted_body(message_id: str = "msg-1") -> dict[str, Any]:
    return {
        "message_id": message_id,
        "status": "accepted",
        "provider_message_id": "carrier-local",
        "simulated": False,
    }


def readback_body(command: CommandExecutionRequest, **overrides: Any) -> dict[str, Any]:
    # Construct the expected wire hash independently of the adapter helper.
    payload = command.payload
    normalized = {
        "billing_account_id": payload["billing_account_id"],
        "destination": payload["destination"],
        "sender": payload["sender"],
        "content": payload["content"],
        "category": payload["category"],
        "campaign_id": payload.get("campaign_id"),
        "client_reference": payload.get("client_reference"),
    }
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "contract_version": "telnexa.sms.readback.v1",
        "message_id": "msg-1",
        "tenant_id": command.tenant_id,
        "idempotency_key": command.idempotency_key,
        "request_hash": digest,
        "correlation_id": command.correlation_id,
        "status": "queued",
        "provider_message_id": None,
        "submission_certainty": None,
        **overrides,
    }


@pytest.mark.asyncio
async def test_execute_submits_the_projected_body_and_security_headers() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(
            url=str(request.url),
            headers=dict(request.headers),
            body=json.loads(request.content),
        )
        return httpx.Response(202, json=accepted_body())

    set_handler(handler)
    command = execution_request()
    result = await TelnexaSmsAdapter(settings_stub(), env=ENV).execute(command)
    assert result.status == "accepted" and result.provider_operation_id == "msg-1"
    assert seen["url"] == f"{BASE_URL}/api/v1/messages"
    assert seen["headers"]["x-api-key"] == API_KEY
    assert seen["headers"]["idempotency-key"] == command.idempotency_key
    assert seen["headers"]["x-correlation-id"] == command.correlation_id
    assert seen["headers"]["x-tenant-id"] == TENANT
    assert seen["body"] == {
        "billing_account_id": "billing-account-1",
        "destination": "+15551234567",
        "sender": "Codestra",
        "content": "Your appointment is confirmed.",
        "category": "transactional",
        "client_reference": command.payload["client_reference"],
    }
    assert "encoding" not in seen["body"] and "segments" not in seen["body"]


@pytest.mark.asyncio
async def test_execute_is_refused_while_the_capability_is_closed() -> None:
    set_handler(lambda request: pytest.fail("disabled execution contacted provider"))
    adapter = TelnexaSmsAdapter(settings_stub(sms_enabled=False), env=ENV)
    with pytest.raises(TelnexaProviderAdapterError, match="SMS delivery is disabled"):
        await adapter.execute(execution_request())


@pytest.mark.asyncio
async def test_execute_rejects_a_command_it_does_not_own() -> None:
    set_handler(lambda request: pytest.fail("invalid identity contacted provider"))
    adapter = TelnexaSmsAdapter(settings_stub(), env=ENV)
    for change, pattern in (
        ({"target": "odoo-19"}, "does not own"),
        ({"capability": "ODOO_WRITE"}, "capability"),
        ({"command_type": "sms.message.send.v1"}, "unsupported"),
    ):
        with pytest.raises(TelnexaProviderAdapterError, match=pattern):
            await adapter.execute(execution_request(**change))


@pytest.mark.asyncio
async def test_execute_rejects_a_payload_that_violates_the_canonical_contract() -> None:
    set_handler(lambda request: pytest.fail("invalid payload contacted provider"))
    adapter = TelnexaSmsAdapter(settings_stub(), env=ENV)
    with pytest.raises(TelnexaProviderAdapterError, match="canonical contract"):
        await adapter.execute(execution_request(payload_overrides={"destination": "not-a-number"}))


@pytest.mark.asyncio
async def test_execute_refuses_to_forward_secret_bearing_payload_keys() -> None:
    set_handler(lambda request: pytest.fail("secret-bearing payload contacted provider"))
    adapter = TelnexaSmsAdapter(settings_stub(), env=ENV)
    with pytest.raises(TelnexaProviderAdapterError):
        await adapter.execute(execution_request(payload_overrides={"provider_token": "leaked"}))


@pytest.mark.asyncio
async def test_connection_failure_before_send_is_not_an_unknown_outcome() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    set_handler(handler)
    with pytest.raises(TelnexaProviderAdapterError, match="before the submission"):
        await TelnexaSmsAdapter(settings_stub(), env=ENV).execute(execution_request())


@pytest.mark.asyncio
async def test_timeout_is_resolved_by_get_without_second_post() -> None:
    command = execution_request()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            assert len(calls) == 1
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json=readback_body(command))

    set_handler(handler)
    result = await TelnexaSmsAdapter(settings_stub(), env=ENV).execute(command)
    assert result.status == "accepted" and "unknown" in result.detail
    assert [request.method for request in calls] == ["POST", "GET"]
    assert str(calls[1].url) == f"{BASE_URL}/api/v1/messages/by-idempotency"
    assert calls[1].content == b""
    assert calls[0].headers["idempotency-key"] == calls[1].headers["idempotency-key"]


@pytest.mark.asyncio
async def test_gateway_5xx_is_reconciled_rather_than_resubmitted() -> None:
    command = execution_request()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return (
            httpx.Response(502, json={"detail": "bad gateway"})
            if request.method == "POST"
            else httpx.Response(200, json=readback_body(command))
        )

    set_handler(handler)
    result = await TelnexaSmsAdapter(settings_stub(), env=ENV).execute(command)
    assert result.status == "accepted" and calls == ["POST", "GET"]


@pytest.mark.asyncio
async def test_idempotency_conflict_on_readback_stays_quarantined() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(409, json={"detail": "idempotency_key_payload_mismatch"})

    set_handler(handler)
    with pytest.raises(TelnexaProviderAdapterError, match="already bound"):
        await TelnexaSmsAdapter(settings_stub(), env=ENV).execute(execution_request())


@pytest.mark.asyncio
async def test_provider_rejection_is_a_hard_failure() -> None:
    set_handler(lambda request: httpx.Response(409, json={"detail": "sender_not_approved"}))
    with pytest.raises(TelnexaProviderAdapterError, match="sender_not_approved"):
        await TelnexaSmsAdapter(settings_stub(), env=ENV).execute(execution_request())


@pytest.mark.asyncio
async def test_readback_reports_a_match_without_claiming_carrier_delivery() -> None:
    command = execution_request()
    set_handler(lambda request: httpx.Response(200, json=readback_body(command)))
    result = await TelnexaSmsAdapter(settings_stub(), env=ENV).readback(command)
    assert result.status == "matched" and result.provider_operation_id == "msg-1"
    assert "carrier delivery is not implied" in result.detail


@pytest.mark.asyncio
async def test_readback_reports_mismatch_for_an_unexpected_status() -> None:
    set_handler(lambda request: httpx.Response(500, json={"detail": "boom"}))
    result = await TelnexaSmsAdapter(settings_stub(), env=ENV).readback(execution_request())
    assert result.status == "mismatch" and "500" in result.detail


@pytest.mark.asyncio
async def test_missing_configuration_is_refused() -> None:
    set_handler(lambda request: pytest.fail("unconfigured transport contacted provider"))
    with pytest.raises(ConfigurationError, match="TELNEXA_SMS_BASE_URL"):
        await TelnexaSmsAdapter(settings_stub(), env={}).execute(execution_request())


@pytest.mark.asyncio
async def test_production_requires_https() -> None:
    set_handler(lambda request: pytest.fail("insecure transport contacted provider"))
    adapter = TelnexaSmsAdapter(
        settings_stub(app_env="production"),
        env={**ENV, "TELNEXA_SMS_BASE_URL": "http://telnexa.internal.invalid"},
    )
    with pytest.raises(ConfigurationError, match="requires HTTPS"):
        await adapter.execute(execution_request())


@pytest.mark.asyncio
async def test_readback_is_get_only_even_with_delivery_disabled_and_no_existing_record() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404, json={"detail": "submission_not_found"})

    set_handler(handler)
    result = await TelnexaSmsAdapter(settings_stub(sms_enabled=False), env=ENV).readback(
        execution_request()
    )
    assert result.status == "mismatch" and result.provider_operation_id is None
    assert len(calls) == 1 and calls[0].method == "GET" and calls[0].content == b""


@pytest.mark.asyncio
async def test_timeout_then_missing_readback_does_not_post_again() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            raise httpx.ReadTimeout("unconfirmed", request=request)
        return httpx.Response(404, json={"detail": "submission_not_found"})

    set_handler(handler)
    with pytest.raises(TelnexaProviderAdapterError, match="outcome unknown"):
        await TelnexaSmsAdapter(settings_stub(), env=ENV).execute(execution_request())
    assert calls == ["POST", "GET"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"tenant_id": "other"},
        {"idempotency_key": "other"},
        {"request_hash": "0" * 64},
        {"correlation_id": "other"},
        {"message_id": None},
        {"contract_version": "wrong"},
        {"status": "submission_unknown"},
        {"submission_certainty": "unknown"},
        {"status": []},
    ],
)
async def test_readback_rejects_unbound_or_unconfirmed_records(
    overrides: dict[str, Any],
) -> None:
    command = execution_request()
    set_handler(lambda request: httpx.Response(200, json=readback_body(command, **overrides)))
    result = await TelnexaSmsAdapter(settings_stub(), env=ENV).readback(command)
    assert result.status == "mismatch" and result.provider_operation_id is None


@pytest.mark.asyncio
async def test_readback_does_not_follow_redirects() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(307, headers={"Location": "https://unapproved.invalid"})

    set_handler(handler)
    result = await TelnexaSmsAdapter(settings_stub(), env=ENV).readback(execution_request())
    assert result.status == "mismatch" and len(calls) == 1


def test_fingerprint_uses_null_defaults_and_ascii_unicode_encoding() -> None:
    submission = {
        "billing_account_id": "a",
        "destination": "+15551234567",
        "sender": "s",
        "content": "Grüße 🙂",
        "category": "transactional",
    }
    expected = {**submission, "campaign_id": None, "client_reference": None}
    digest = hashlib.sha256(
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert TelnexaSmsAdapter._request_hash(submission) == digest
