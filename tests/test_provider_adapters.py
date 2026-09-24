from datetime import datetime, timedelta, timezone
import json
import socket

import pytest

from app.core.provider_adapters import (
    CommunicationCommand,
    CommunicationContentReference,
    CommunicationRecipient,
    DeliveryState,
    DisabledProviderStub,
    NullProviderAdapter,
    ProviderContractError,
    ProviderDeliveryDisabled,
    ProviderDispatchRequest,
    ProviderWebhookEnvelope,
    SyntheticSinkAdapter,
    validate_delivery_transition,
)


def command(**overrides):
    now = datetime(2026, 7, 29, 12, tzinfo=timezone.utc)
    values = {
        "command_id": "CMD-TEST-1",
        "idempotency_key": "IDEMPOTENCY-TEST-1",
        "correlation_id": "CORRELATION-TEST-1",
        "causation_id": "CAUSATION-TEST-1",
        "test_run_id": "CTR-TEST-1",
        "record_environment": "TEST",
        "organization_id": "ORG-CODESTRA",
        "business_unit_id": "BU-400-COD",
        "campaign_id": "CMP-400-COD",
        "lead_public_id": "400-L-90000001",
        "agent_public_id": "400-AGT-90000001",
        "channel": "EMAIL",
        "message_purpose": "SYNTHETIC_ACCEPTANCE",
        "consent_reference": "TEST-CONSENT-1",
        "suppression_check_version": "SUPPRESSION-1",
        "provider_adapter": "synthetic-sink",
        "recipient": CommunicationRecipient(
            destination_token="synthetic:destination:1",
            destination_classification="APPROVED_SYNTHETIC",
            channel="EMAIL",
        ),
        "content": CommunicationContentReference(
            reference="template:test-communication",
            version=1,
            content_hash="b" * 64,
        ),
        "requested_at": now,
        "expires_at": now + timedelta(minutes=5),
        "policy_hash": "a" * 64,
    }
    values.update(overrides)
    return CommunicationCommand(**values)


def test_provider_neutral_command_contains_trace_binding_and_no_message_body():
    value = command()
    value.validate()
    assert value.test_run_id == "CTR-TEST-1"
    assert "body" not in vars(value)
    assert "credentials" not in vars(value)


@pytest.mark.parametrize(
    "current,target",
    [
        (DeliveryState.REQUESTED, DeliveryState.POLICY_CHECKED),
        (DeliveryState.POLICY_CHECKED, DeliveryState.APPROVED),
        (DeliveryState.APPROVED, DeliveryState.DISPATCH_RESERVED),
        (DeliveryState.DISPATCH_RESERVED, DeliveryState.DISPATCHED),
        (DeliveryState.DISPATCHED, DeliveryState.PROVIDER_ACCEPTED),
        (DeliveryState.PROVIDER_ACCEPTED, DeliveryState.DELIVERED),
    ],
)
def test_delivery_state_machine_allows_forward_path(current, target):
    validate_delivery_transition(current, target)


@pytest.mark.parametrize(
    "current,target",
    [
        (DeliveryState.DELIVERED, DeliveryState.DISPATCHED),
        (DeliveryState.SUPPRESSED, DeliveryState.APPROVED),
        (DeliveryState.REQUESTED, DeliveryState.DELIVERED),
        (DeliveryState.FAILED_TERMINAL, DeliveryState.DISPATCH_RESERVED),
    ],
)
def test_terminal_and_backward_transitions_are_rejected(current, target):
    with pytest.raises(ProviderContractError):
        validate_delivery_transition(current, target)


def test_null_adapter_always_rejects_dispatch():
    with pytest.raises(ProviderDeliveryDisabled):
        NullProviderAdapter().dispatch(ProviderDispatchRequest(command(), 1))


def test_disabled_provider_stub_has_no_live_configuration():
    adapter = DisabledProviderStub("unapproved-email-provider")
    with pytest.raises(ProviderDeliveryDisabled):
        adapter.validate_configuration()
    assert adapter.readiness()["status"] == "not_ready"


def test_synthetic_sink_is_deterministic_and_idempotent(monkeypatch):
    def forbidden_network(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", forbidden_network)
    adapter = SyntheticSinkAdapter()
    request = ProviderDispatchRequest(command(), 1)
    first = adapter.dispatch(request)
    second = adapter.dispatch(request)
    assert first is second
    assert first.provider_id.startswith("synthetic:")
    assert first.state is DeliveryState.PROVIDER_ACCEPTED
    assert adapter.health() == {"status": "ok", "network": "not_used"}


@pytest.mark.parametrize(
    "override",
    [
        {"record_environment": "PRODUCTION"},
        {
            "recipient": CommunicationRecipient(
                destination_token="opaque",
                destination_classification="CUSTOMER",
                channel="EMAIL",
            )
        },
    ],
)
def test_synthetic_sink_rejects_non_test_or_non_synthetic_scope(override):
    with pytest.raises(ProviderDeliveryDisabled):
        SyntheticSinkAdapter().dispatch(ProviderDispatchRequest(command(**override), 1))


def test_synthetic_webhook_normalization_uses_hash_and_references_only():
    adapter = SyntheticSinkAdapter()
    body = json.dumps(
        {
            "provider_id": "synthetic:1",
            "command_id": "CMD-TEST-1",
            "correlation_id": "CORRELATION-TEST-1",
            "state": "DELIVERED",
        },
        separators=(",", ":"),
    ).encode()
    envelope = ProviderWebhookEnvelope(
        provider="synthetic-sink",
        provider_account="test-only",
        provider_event_id="EVENT-1",
        received_at=datetime(2026, 7, 29, 12, tzinfo=timezone.utc),
        occurred_at=datetime(2026, 7, 29, 12, tzinfo=timezone.utc),
        payload_hash=__import__("hashlib").sha256(body).hexdigest(),
        raw_body=body,
        headers={},
    )
    event = adapter.normalize_webhook(envelope)[0]
    assert event.state is DeliveryState.DELIVERED
    assert event.command_id == "CMD-TEST-1"


def test_synthetic_reconciliation_detects_no_drift():
    adapter = SyntheticSinkAdapter()
    response = adapter.dispatch(ProviderDispatchRequest(command(), 1))
    result = adapter.reconcile(
        command_id="CMD-TEST-1",
        desired_state=DeliveryState.PROVIDER_ACCEPTED,
        provider_id=response.provider_id,
    )
    assert result.drift_classification == "NO_DRIFT"
