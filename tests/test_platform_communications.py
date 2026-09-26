from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.commands import CommandEnvelope, CommandOperation, CommandPolicyRegistry
from app.platform.adapter import AdapterContext, Outcome, ReadbackStatus
from app.platform.adapters.communications import (
    DeliveryState,
    EvolutionWhatsAppAdapter,
    SyntheticCommunicationSink,
)
from app.platform.adapters.providers import provider_adapters


def command(**updates):
    value = {
        "command_id": str(uuid4()),
        "command_type": "whatsapp.message.send.v1",
        "command_version": "1.0",
        "target": "evolution-whatsapp",
        "tenant_id": "TEST_SYN",
        "requested_by": "tester",
        "correlation_id": "corr-whatsapp",
        "idempotency_key": "whatsapp-idempotency-0001",
        "capability": "WHATSAPP_DELIVERY",
        "payload": {
            "recipient": "+18095550101",
            "instance": "test-syn",
            "text": "synthetic hello",
            "campaign_id": "TEST_SYN",
            "metadata": {"fixture": True},
        },
    }
    value.update(updates)
    return CommandEnvelope.model_validate(value)


def context(**updates):
    value = dict(
        tenant_id="TEST_SYN",
        command_id="cmd",
        correlation_id="corr-whatsapp",
        attempt=1,
        timeout_seconds=2.0,
        environment="test",
        deployment_sha="test",
        test_syn=True,
    )
    value.update(updates)
    return AdapterContext(**value)


def operation(cmd: CommandEnvelope, provider_reference: str) -> CommandOperation:
    now = datetime.now(UTC)
    return CommandOperation(
        **cmd.model_dump(exclude={"payload"}),
        state="readback_pending",
        provider_operation_id=provider_reference,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_whatsapp_synthetic_send_readback_and_reconcile_are_tenant_bound():
    adapter = EvolutionWhatsAppAdapter(synthetic=SyntheticCommunicationSink("evolution"))
    adapter.validate_config()
    cmd = command()
    ctx = context(command_id=str(cmd.command_id))

    sent = await adapter.execute(cmd, ctx)
    assert sent.outcome is Outcome.ACCEPTED
    assert sent.provider_operation_id and sent.provider_operation_id.startswith("syn-evolution-")

    op = operation(cmd, sent.provider_operation_id)
    readback = await adapter.readback(op, ctx)
    assert readback.status is ReadbackStatus.MATCHED
    assert readback.evidence["delivery_state"] == DeliveryState.DELIVERED.value

    reconciled = await adapter.reconcile(op, ctx)
    assert reconciled.status is ReadbackStatus.MATCHED

    foreign = await adapter.readback(op, context(tenant_id="tenant-b", command_id=str(cmd.command_id)))
    assert foreign.status is ReadbackStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_whatsapp_live_path_fails_closed_without_transport_and_validates_input():
    adapter = EvolutionWhatsAppAdapter(synthetic=SyntheticCommunicationSink("evolution"))
    cmd = command()
    denied = await adapter.execute(cmd, context(test_syn=False, command_id=str(cmd.command_id)))
    assert denied.outcome is Outcome.REJECTED
    assert denied.safe_error_code == "DEPENDENCY_UNAVAILABLE"

    invalid = command(payload={"recipient": "8095550101", "instance": "test-syn", "text": "hello"})
    rejected = await adapter.execute(invalid, context(command_id=str(invalid.command_id)))
    assert rejected.outcome is Outcome.REJECTED
    assert rejected.safe_error_code == "invalid_whatsapp_recipient"


def test_whatsapp_capability_is_registered_but_off_by_default(test_settings):
    policies = CommandPolicyRegistry.load()
    policy = policies.resolve("whatsapp.message.send.v1")
    assert policy is not None
    assert policy.target == "evolution-whatsapp"
    assert policy.capability == "WHATSAPP_DELIVERY"
    assert policies.capabilities["WHATSAPP_DELIVERY"] is False

    configured = test_settings.replace(evolution_whatsapp_base_url="https://evolution.internal", evolution_whatsapp_service_token="test-token")
    adapters = provider_adapters(configured, http=None)
    evolution = next(item for item in adapters if item.adapter_id == "evolution-whatsapp")
    advertised = evolution.capabilities()
    assert advertised.connector_ids == ("evolution-whatsapp",)
    assert advertised.capabilities == ("WHATSAPP_DELIVERY",)
