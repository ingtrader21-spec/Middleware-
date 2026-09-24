from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest

from app.commands import CommandEnvelope, CommandOperation
from app.core.config import Settings
from app.platform.adapter import AdapterContext, Outcome, ReadbackStatus
from app.platform.adapters.providers import provider_adapters
from app.platform.adapters.whatsapp import WhatsAppProviderAdapter


def settings(**overrides: str) -> Settings:
    values = {
        "APP_ENV": "test",
        "ALLOW_IN_MEMORY_STORAGE": "true",
        "EVOLUTION_WHATSAPP_BASE_URL": "https://evolution.internal",
        "EVOLUTION_WHATSAPP_SERVICE_TOKEN": "test-service-token",
        "EVOLUTION_WHATSAPP_PROVIDER": "evolution",
        **overrides,
    }
    return Settings.from_env(values)


def command() -> CommandEnvelope:
    return CommandEnvelope.model_validate(
        {
            "command_id": str(uuid4()),
            "command_type": "whatsapp.message.send.v1",
            "command_version": "1.0",
            "target": "evolution-whatsapp",
            "tenant_id": "TEST_SYN",
            "requested_by": "user-1",
            "correlation_id": "corr-whatsapp-1",
            "idempotency_key": "idem-whatsapp-123",
            "capability": "WHATSAPP_DELIVERY",
            "payload": {
                "recipient": "15550000000",
                "instance_id": "test-instance",
                "message": {"type": "text", "text": "hello"},
                "business_context": {"campaign_id": "cmp-1"},
            },
        }
    )


def operation(cmd: CommandEnvelope, provider_id: str) -> CommandOperation:
    now = datetime.now(timezone.utc)
    return CommandOperation(
        **cmd.model_dump(exclude={"payload"}),
        state="accepted",
        created_at=now,
        updated_at=now,
        provider_operation_id=provider_id,
    )


def context(cmd: CommandEnvelope, client: httpx.AsyncClient) -> AdapterContext:
    return AdapterContext(
        tenant_id=cmd.tenant_id,
        command_id=str(cmd.command_id),
        correlation_id=cmd.correlation_id,
        attempt=1,
        timeout_seconds=5,
        environment="staging",
        deployment_sha="test",
        http=client,
        payload=cmd.payload,
    )


@pytest.mark.asyncio
async def test_execute_propagates_v3_identifiers_and_normalizes_provider_id() -> None:
    cmd = command()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/v1/whatsapp/transport/messages"
        assert request.headers["authorization"] == "Bearer test-service-token"
        assert request.headers["idempotency-key"] == cmd.idempotency_key
        assert request.headers["x-correlation-id"] == cmd.correlation_id
        payload = __import__("json").loads(request.content)
        assert payload["command_id"] == str(cmd.command_id)
        assert payload["correlation_id"] == cmd.correlation_id
        assert payload["idempotency_key"] == cmd.idempotency_key
        assert payload["provider"] == "evolution"
        assert payload["recipient"] == "15550000000"
        return httpx.Response(
            202,
            json={
                "command_id": str(cmd.command_id),
                "correlation_id": cmd.correlation_id,
                "result": {
                    "provider": "evolution",
                    "provider_message_id": "wamid.123",
                    "accepted": True,
                    "provider_status": 200,
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = WhatsAppProviderAdapter(settings())
        result = await adapter.execute(cmd, context(cmd, client))

    assert result.outcome is Outcome.ACCEPTED
    assert result.provider_operation_id == "wamid.123"


@pytest.mark.asyncio
async def test_readback_requires_delivered_or_read_for_match() -> None:
    cmd = command()

    def delivered(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/wamid.123")
        return httpx.Response(200, json={"provider_message_id": "wamid.123", "provider": "evolution", "state": "DELIVERED"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(delivered)) as client:
        adapter = WhatsAppProviderAdapter(settings())
        result = await adapter.readback(operation(cmd, "wamid.123"), context(cmd, client))
    assert result.status is ReadbackStatus.MATCHED

    def sent(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"provider_message_id": "wamid.123", "provider": "evolution", "state": "SENT"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(sent)) as client:
        adapter = WhatsAppProviderAdapter(settings())
        result = await adapter.readback(operation(cmd, "wamid.123"), context(cmd, client))
    assert result.status is ReadbackStatus.UNAVAILABLE


def test_provider_adapter_is_registered_only_when_configured() -> None:
    configured = provider_adapters(settings(), http=None)
    assert "evolution-whatsapp" in {adapter.adapter_id for adapter in configured}

    unconfigured = provider_adapters(
        settings(EVOLUTION_WHATSAPP_BASE_URL="", EVOLUTION_WHATSAPP_SERVICE_TOKEN=""),
        http=None,
    )
    assert "evolution-whatsapp" not in {adapter.adapter_id for adapter in unconfigured}

