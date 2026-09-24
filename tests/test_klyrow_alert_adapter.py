from __future__ import annotations

from dataclasses import replace

import pytest

from app.commands import CommandEnvelope
from app.core.config import ConfigurationError, Settings
from app.klyrow_alert_adapter import KlyrowAlertAdapter, KlyrowAlertAdapterError
from app.temporal_workflows import ActivityResult, CommandExecutionRequest


def settings() -> Settings:
    return Settings.from_env(
        {
            "APP_ENV": "test",
            "ALLOW_IN_MEMORY_STORAGE": "true",
            "EXTERNAL_EFFECTS": "false",
        }
    )


def request() -> CommandExecutionRequest:
    envelope = CommandEnvelope.model_validate(
        {
            "command_id": "8b8cc64c-607e-4ab2-8640-7608a0b922b0",
            "command_type": "observability.alert.email.send.v1",
            "command_version": "1.0",
            "target": "klyrow-alert-email",
            "tenant_id": "codestra-platform",
            "requested_by": "service-account-alertmanager",
            "correlation_id": "corr-observability-alert-0001",
            "idempotency_key": "obs-alert-v1:" + "1" * 64,
            "capability": "OBSERVABILITY_ALERT_EMAIL_DELIVERY",
            "payload": {
                "schema_version": "1.0",
                "message_id": "8b8cc64c-607e-4ab2-8640-7608a0b922b0",
                "from": "alerts@codestra.co",
                "to": ["appolon1908@gmail.com"],
                "reply_to": "appolon1908@gmail.com",
                "content": {
                    "subject": "[Codestra][FIRING][CRITICAL] HostDown",
                    "text": "State: FIRING",
                    "html": "<p>State: FIRING</p>",
                },
                "classification": "operational-alert",
                "recipient_policy_id": "codestra-observability-admin-v1",
                "sender_policy_id": "codestra-alert-sender-v1",
                "alert": {
                    "fingerprint": "abc123",
                    "state": "firing",
                    "severity": "critical",
                    "service": "node-exporter",
                    "host": "37.27.128.39",
                    "environment": "production",
                    "labels": {"release_id": "obs-1"},
                    "annotations": {},
                },
            },
        }
    )
    return CommandExecutionRequest(**envelope.model_dump(mode="json"))


def test_payload_is_fixed_to_reviewed_sender_and_recipient() -> None:
    adapter = KlyrowAlertAdapter(settings(), env={})
    payload = adapter._validate_payload(request())
    document = adapter._provider_document(request(), payload)
    assert document["sender"] == "alerts@codestra.co"
    assert document["recipients"] == ["appolon1908@gmail.com"]
    assert document["stream"] == "operational"


def test_changed_recipient_is_rejected() -> None:
    current = request()
    payload = dict(current.payload)
    payload["to"] = ["someone-else@example.com"]
    changed = replace(current, payload=payload)
    with pytest.raises(KlyrowAlertAdapterError, match="recipient"):
        KlyrowAlertAdapter(settings(), env={})._validate_payload(changed)



def legacy_request() -> CommandExecutionRequest:
    current = request()
    payload = dict(current.payload)
    payload["to"] = ["appolon@codestra.co"]
    payload["reply_to"] = "appolon@codestra.co"
    return replace(current, payload=payload)


def test_legacy_recipient_is_readback_only() -> None:
    adapter = KlyrowAlertAdapter(settings(), env={})
    with pytest.raises(KlyrowAlertAdapterError, match="recipient"):
        adapter._validate_payload(legacy_request())
    payload = adapter._validate_payload(
        legacy_request(),
        allow_legacy_recipient=True,
    )
    assert payload["to"] == ["appolon@codestra.co"]


@pytest.mark.asyncio
async def test_legacy_queued_alert_is_never_resubmitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = KlyrowAlertAdapter(
        settings(),
        env={
            "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true",
            "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
            "LIVE_EMAIL_DELIVERY": "false",
        },
    )

    async def unmatched_readback(
        _request: CommandExecutionRequest,
    ) -> ActivityResult:
        return ActivityResult(status="mismatch", detail="not accepted")

    monkeypatch.setattr(adapter, "readback", unmatched_readback)
    with pytest.raises(KlyrowAlertAdapterError, match="controlled reissue"):
        await adapter.execute(legacy_request())


def test_delivery_defaults_disabled() -> None:
    with pytest.raises(KlyrowAlertAdapterError, match="disabled"):
        KlyrowAlertAdapter(settings(), env={})._require_active(request())


def test_public_provider_endpoint_is_rejected() -> None:
    adapter = KlyrowAlertAdapter(
        settings(),
        env={"KLYROW_ALERT_API_BASE_URL": "https://api.example.com"},
    )
    with pytest.raises(ConfigurationError, match="approved private endpoint"):
        adapter._base_url()


def test_general_email_delivery_must_remain_disabled() -> None:
    adapter = KlyrowAlertAdapter(
        settings(),
        env={
            "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true",
            "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
            "LIVE_EMAIL_DELIVERY": "true",
        },
    )
    with pytest.raises(
        KlyrowAlertAdapterError,
        match="general LIVE_EMAIL_DELIVERY",
    ):
        adapter._require_active(request())
