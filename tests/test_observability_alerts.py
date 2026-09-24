from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import jwt
import yaml  # type: ignore[import-untyped]
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.commands import (
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    MemoryCommandStore,
)
from app.core.config import Settings
from app.observability_alert_contract import (
    AlertmanagerAlert,
    AlertmanagerWebhook,
    build_command,
)
from app.observability_alerts import AlertPolicy, create_app
from app.observability_incidents import (
    IncidentService,
    MemoryIncidentStore,
    incident_identity,
)
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore


class AlertTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        assert authorization.startswith("Bearer ")
        return {
            "azp": expected_client_id,
            "sub": f"service-account-{expected_client_id}",
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": "codestra-platform",
        }

    async def ready(self) -> bool:
        return True


def token(client_id: str) -> str:
    return jwt.encode({"azp": client_id}, "unit-test-only", algorithm="HS256")


def policy() -> AlertPolicy:
    return AlertPolicy.model_validate(
        {
            "schema_version": "1.0",
            "policy_id": "codestra-observability-alert-mail-v1",
            "tenant_id": "codestra-platform",
            "receiver": "codestra-observability-email",
            "recipient_policy_id": "codestra-observability-admin-v1",
            "sender_policy_id": "codestra-alert-sender-v1",
            "recipient": "appolon1908@gmail.com",
            "sender": "alerts@codestra.co",
            "reply_to": "appolon1908@gmail.com",
            "allowed_environments": ["test"],
            "allowed_severities": ["critical", "warning"],
            "immediate_severities": ["critical"],
            "grouped_severities": ["warning"],
            "state_only_severities": [],
            "warning_group_wait_seconds": 300,
            "warning_repeat_interval_seconds": 14400,
            "max_alerts_per_request": 20,
            "max_body_bytes": 131072,
            "normal_delivery_path": "middleware-klyrow-adapter",
            "direct_smtp_allowed": False,
            "delivery_enabled_by_default": False,
        }
    )


def settings() -> Settings:
    return Settings.from_env(
        {
            "APP_ENV": "test",
            "ALLOW_IN_MEMORY_STORAGE": "true",
            "EXTERNAL_EFFECTS": "false",
        }
    )


def runtime(active: bool = True) -> Runtime:
    command_store = MemoryCommandStore()
    command_service = CommandService(
        store=command_store,
        policies=CommandPolicyRegistry(
            policies=(
                CommandPolicy(
                    prefix="observability.alert.",
                    target="klyrow-alert-email",
                    capability="OBSERVABILITY_ALERT_EMAIL_DELIVERY",
                    readback_required=True,
                ),
            ),
            capabilities={"OBSERVABILITY_ALERT_EMAIL_DELIVERY": active},
        ),
    )
    return Runtime(
        settings=settings(),
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=AlertTokenVerifier(),
        commands=command_service,
    )


def webhook() -> dict[str, Any]:
    return {
        "version": "4",
        "groupKey": '{}:{alertname="HostDown"}',
        "truncatedAlerts": 0,
        "status": "firing",
        "receiver": "codestra-observability-email",
        "groupLabels": {"alertname": "HostDown"},
        "commonLabels": {
            "alertname": "HostDown",
            "severity": "critical",
            "service": "node-exporter",
            "environment": "test",
            "host": "37.27.128.39",
        },
        "commonAnnotations": {"summary": "Provider host is down"},
        "externalURL": "https://aler.codestra.media/#/alerts?secret=removed",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "HostDown",
                    "severity": "critical",
                    "service": "node-exporter",
                    "environment": "test",
                    "host": "37.27.128.39",
                    "owner": "codestra-observability",
                    "codestra_business": "platform",
                    "release_id": "obs-test-1",
                },
                "annotations": {
                    "summary": "Provider host is down",
                    "description": "The synthetic host target is unavailable.",
                    "runbook_url": (
                        "https://graf.codestra.media/d/runbooks/host-down?token=removed"
                    ),
                    "dashboard_url": (
                        "https://graf.codestra.media/d/host/provider?var=removed"
                    ),
                },
                "startsAt": "2026-09-02T16:00:00Z",
                "endsAt": "2026-09-02T16:00:00Z",
                "generatorURL": "https://prom.codestra.media/graph?g0.expr=up",
                "fingerprint": "abc123def456",
            }
        ],
    }


def headers(
    client_id: str = "alertmanager",
    *,
    key: str = "alertmanager-webhook-v1",
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token(client_id)}",
        "Content-Type": "application/json",
        "X-Tenant-ID": "codestra-platform",
        "X-Correlation-ID": "corr-observability-alert-0001",
        "Idempotency-Key": key,
        "X-Source-Deployment": "alertmanager-test-1",
    }


def app(active: bool = True):
    return create_app(
        settings=settings(),
        runtime=runtime(active=active),
        policy=policy(),
        env={
            "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true" if active else "false",
            "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
        },
    )


def test_firing_alert_is_durable_and_replay_safe() -> None:
    with TestClient(app()) as client:
        response = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=headers(),
        )
        assert response.status_code == 202
        body = response.json()
        assert body["recipient_policy_id"] == "codestra-observability-admin-v1"
        assert body["sender_policy_id"] == "codestra-alert-sender-v1"
        assert len(body["operations"]) == 1
        operation = body["operations"][0]
        assert operation["operation_state"] == "persisted"
        assert operation["duplicate"] is False

        replay = client.post(
            "/v1/observability/alerts",
            json=webhook(),
            headers=headers(),
        )
        assert replay.status_code == 200
        assert replay.json()["operations"][0]["duplicate"] is True
        assert (
            replay.json()["operations"][0]["operation_id"] == operation["operation_id"]
        )

        detail = client.get(
            operation["status_url"],
            headers=headers(key="alert-status-read-v1"),
        )
        assert detail.status_code == 200
        assert detail.json()["command_type"] == "observability.alert.email.send.v1"
        assert detail.json()["target"] == "klyrow-alert-email"

        events = client.get(
            operation["events_url"],
            headers=headers(key="alert-events-read-v1"),
        )
        assert events.status_code == 200
        assert events.json()["items"][0]["new_state"] == "persisted"


def test_mixed_status_group_processes_each_alert_transition() -> None:
    value = webhook()
    resolved = copy.deepcopy(value["alerts"][0])
    resolved["status"] = "resolved"
    resolved["fingerprint"] = "resolved123456"
    resolved["endsAt"] = "2026-09-02T16:05:00Z"
    value["alerts"].append(resolved)
    with TestClient(app()) as client:
        response = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="mixed-status-alert-group-v1"),
        )
        assert response.status_code == 202
        assert [item["alert_state"] for item in response.json()["operations"]] == [
            "firing",
            "resolved",
        ]


def test_annotation_urls_are_sanitized_before_command_creation() -> None:
    value = webhook()
    parsed = AlertmanagerWebhook.model_validate(value)
    alert = parsed.alerts[0]
    assert alert.annotations["runbook_url"] == (
        "https://graf.codestra.media/d/runbooks/host-down"
    )
    assert alert.annotations["dashboard_url"] == (
        "https://graf.codestra.media/d/host/provider"
    )


def test_notification_content_contains_required_incident_evidence() -> None:
    parsed = AlertmanagerWebhook.model_validate(webhook())
    alert = parsed.alerts[0]
    incident_id = incident_identity(policy().tenant_id, alert.fingerprint)
    command = build_command(
        policy=policy(),
        alert=alert,
        group_key=parsed.group_key,
        receiver=parsed.receiver,
        actor="service-account-alertmanager",
        correlation_id="corr-observability-alert-0001",
        incident_id=incident_id,
    )
    assert command.payload["alert"]["incident_id"] == str(incident_id)
    assert command.payload["alert"]["codestra_business"] == "platform"
    assert command.payload["alert"]["first_seen_at"] == alert.starts_at.isoformat()
    text = command.payload["content"]["text"]
    assert f"Incident ID: {incident_id}" in text
    assert "Business: platform" in text
    assert "First seen:" in text


def test_notification_content_can_preserve_persisted_first_seen_time() -> None:
    parsed = AlertmanagerWebhook.model_validate(webhook())
    alert = parsed.alerts[0]
    incident_id = incident_identity(policy().tenant_id, alert.fingerprint)
    persisted_first_seen = datetime(2026, 9, 1, 8, 30, tzinfo=UTC)
    command = build_command(
        policy=policy(),
        alert=alert,
        group_key=parsed.group_key,
        receiver=parsed.receiver,
        actor="service-account-alertmanager",
        correlation_id="corr-observability-recurrence-0001",
        incident_id=incident_id,
        first_seen_at=persisted_first_seen,
    )

    assert command.payload["alert"]["first_seen_at"] == (
        persisted_first_seen.isoformat()
    )
    assert command.payload["alert"]["starts_at"] == alert.starts_at.isoformat()
    assert (
        f"First seen: {persisted_first_seen.isoformat()}"
        in (command.payload["content"]["text"])
    )


def test_invalid_later_alert_does_not_partially_persist_batch() -> None:
    value = webhook()
    denied = copy.deepcopy(value["alerts"][0])
    denied["fingerprint"] = "denied123456"
    denied["labels"]["environment"] = "production"
    value["alerts"].append(denied)
    active_runtime = runtime()
    with TestClient(
        create_app(
            settings=settings(),
            runtime=active_runtime,
            policy=policy(),
            env={
                "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true",
                "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
            },
        )
    ) as client:
        response = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="all-or-nothing-alert-group-v1"),
        )
        assert response.status_code == 403
    assert active_runtime.commands is not None
    assert (
        asyncio.run(
            active_runtime.commands.list_operations(
                "codestra-platform",
                limit=100,
            )
        )
        == []
    )


def test_same_identity_with_changed_payload_is_a_conflict() -> None:
    changed = copy.deepcopy(webhook())
    changed["alerts"][0]["annotations"]["summary"] = "Different semantic payload"
    with TestClient(app()) as client:
        first = client.post(
            "/v1/observability/alerts",
            json=webhook(),
            headers=headers(),
        )
        assert first.status_code == 202
        second = client.post(
            "/v1/observability/alerts",
            json=changed,
            headers=headers(),
        )
        assert second.status_code == 409
        assert second.json()["code"] == "incident_conflict"


def test_sensitive_annotations_are_rejected() -> None:
    value = webhook()
    value["alerts"][0]["annotations"]["authorization"] = "Bearer secret"
    with TestClient(app()) as client:
        response = client.post(
            "/v1/observability/alerts",
            json=value,
            headers=headers(),
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_request"


def test_missing_business_label_and_runbook_are_rejected() -> None:
    value = webhook()
    del value["alerts"][0]["labels"]["codestra_business"]
    del value["alerts"][0]["annotations"]["runbook_url"]
    with TestClient(app()) as client:
        response = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="missing-required-alert-fields-0001"),
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_request"


def test_alert_delivery_capability_defaults_fail_closed() -> None:
    with TestClient(app(active=False)) as client:
        response = client.post(
            "/v1/observability/alerts",
            json=webhook(),
            headers=headers(),
        )
        assert response.status_code == 202
        assert response.json()["operations"][0]["operation_id"] is None
        assert response.json()["operations"][0]["notification_status"] == "disabled"
        assert response.json()["operations"][0]["status_url"] is None
        assert response.json()["operations"][0]["events_url"] is None
        capabilities = client.get("/capabilities")
        assert capabilities.status_code == 200
        assert capabilities.json()["OBSERVABILITY_ALERT_EMAIL_DELIVERY"] is False
        assert capabilities.json()["direct_smtp_allowed"] is False


def test_delivery_activation_queues_a_previously_state_only_warning() -> None:
    async def scenario() -> None:
        shared_runtime = runtime(active=True)
        assert shared_runtime.commands is not None
        store = MemoryIncidentStore(shared_runtime.commands)
        disabled = IncidentService(
            store=store,
            commands=shared_runtime.commands,
            policy=policy(),
            delivery_enabled=False,
        )
        enabled = IncidentService(
            store=store,
            commands=shared_runtime.commands,
            policy=policy(),
            delivery_enabled=True,
        )
        value = webhook()["alerts"][0]
        value["labels"]["severity"] = "warning"
        item = AlertmanagerAlert.model_validate(value)
        first = await disabled.ingest(
            group_key=webhook()["groupKey"],
            alert=item,
            actor_id="service-account-alertmanager",
            correlation_id="activation-disabled-correlation-0001",
            source_deployment="alertmanager-test-1",
            request_idempotency_key="activation-disabled-request-0001",
        )
        assert first.operation is None
        assert first.notification_status == "disabled"

        activated = await enabled.ingest(
            group_key=webhook()["groupKey"],
            alert=item,
            actor_id="service-account-alertmanager",
            correlation_id="activation-enabled-correlation-0001",
            source_deployment="alertmanager-test-1",
            request_idempotency_key="activation-enabled-request-0001",
        )
        assert activated.operation is not None
        assert activated.notification_status == "scheduled"
        assert activated.duplicate is False
        replay = await enabled.ingest(
            group_key=webhook()["groupKey"],
            alert=item,
            actor_id="service-account-alertmanager",
            correlation_id="activation-enabled-correlation-0001",
            source_deployment="alertmanager-test-1",
            request_idempotency_key="activation-enabled-request-0001",
        )
        assert replay.operation is not None
        assert replay.operation.command_id == activated.operation.command_id
        assert replay.notification_status == "scheduled"
        assert replay.duplicate is True
        timeline = await store.list_timeline(
            policy().tenant_id,
            activated.incident.incident_id,
            limit=10,
            after_event_id=None,
        )
        assert [event.event_type for event in timeline] == [
            "firing",
            "firing",
        ]
        assert (
            timeline[-1]
            .safe_metadata["activated_transition"]
            .startswith("alert-transition-v1:")
        )

    asyncio.run(scenario())


def test_incident_lifecycle_is_tenant_scoped_audited_and_idempotent() -> None:
    with TestClient(app()) as client:
        accepted = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=headers(),
        )
        incident_id = accepted.json()["operations"][0]["incident_id"]
        operator_headers = headers(
            "observability-operator",
            key="incident-acknowledge-0001",
        )

        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=operator_headers,
        )
        assert detail.status_code == 200
        assert detail.json()["state"] == "firing"
        assert detail.json()["resource_version"] == 1

        listing = client.get(
            "/v1/observability/incidents?state=firing&severity=critical&limit=1",
            headers=operator_headers,
        )
        assert listing.status_code == 200
        assert [item["incident_id"] for item in listing.json()["items"]] == [
            incident_id
        ]

        acknowledged = client.post(
            f"/v1/observability/incidents/{incident_id}/acknowledge",
            json={"expected_version": 1, "reason": "operator accepted incident"},
            headers=operator_headers,
        )
        assert acknowledged.status_code == 200
        assert acknowledged.json()["state"] == "acknowledged"
        assert acknowledged.json()["resource_version"] == 2

        replay = client.post(
            f"/v1/observability/incidents/{incident_id}/acknowledge",
            json={"expected_version": 1, "reason": "operator accepted incident"},
            headers=operator_headers,
        )
        assert replay.status_code == 200
        assert replay.json()["duplicate"] is True
        assert replay.json()["resource_version"] == 2

        resolve_headers = headers(
            "observability-operator",
            key="incident-resolve-0001",
        )
        resolved = client.post(
            f"/v1/observability/incidents/{incident_id}/resolve",
            json={"expected_version": 2, "reason": "operator verified recovery"},
            headers=resolve_headers,
        )
        assert resolved.status_code == 200
        assert resolved.json()["state"] == "resolved"

        reopen_headers = headers(
            "observability-operator",
            key="incident-reopen-0001",
        )
        reopened = client.post(
            f"/v1/observability/incidents/{incident_id}/reopen",
            json={"expected_version": 3, "reason": "signal returned"},
            headers=reopen_headers,
        )
        assert reopened.status_code == 200
        assert reopened.json()["state"] == "firing"
        assert reopened.json()["resource_version"] == 4

        timeline = client.get(
            f"/v1/observability/incidents/{incident_id}/timeline",
            headers=operator_headers,
        )
        assert timeline.status_code == 200
        assert [item["event_type"] for item in timeline.json()["items"]] == [
            "firing",
            "acknowledge",
            "resolve",
            "reopen",
        ]

        attempts = client.get(
            f"/v1/observability/incidents/{incident_id}/notification-attempts",
            headers=operator_headers,
        )
        assert attempts.status_code == 200
        assert attempts.json()["items"][0]["operation_state"] == "persisted"


def test_authenticated_status_snapshot_records_silenced_state() -> None:
    with TestClient(app()) as client:
        accepted = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=headers(),
        )
        incident_id = accepted.json()["operations"][0]["incident_id"]
        value = webhook()
        snapshot = {
            "observedAt": "2026-09-02T16:01:00Z",
            "sourceDeployment": "alertmanager-test-1",
            "items": [
                {
                    "groupKey": value["groupKey"],
                    "fingerprint": value["alerts"][0]["fingerprint"],
                    "startsAt": value["alerts"][0]["startsAt"],
                    "state": "silenced",
                    "silencedBy": ["silence-123"],
                    "inhibitedBy": [],
                }
            ],
        }
        status_headers = headers(key="alertmanager-status-snapshot-0001")
        response = client.post(
            "/v1/integrations/alertmanager/status-events",
            json=snapshot,
            headers=status_headers,
        )
        assert response.status_code == 200
        assert response.json()["items"][0]["state"] == "silenced"

        operator_headers = headers(
            "observability-operator",
            key="incident-status-read-0001",
        )
        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=operator_headers,
        )
        assert detail.json()["state"] == "silenced"


def test_transition_identity_does_not_depend_on_transport_key() -> None:
    with TestClient(app()) as client:
        first = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=headers(key="transport-key-first-0001"),
        )
        second = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=headers(key="transport-key-second-0001"),
        )
        assert first.status_code == 202
        assert second.status_code == 200
        assert second.json()["operations"][0]["duplicate"] is True
        assert (
            second.json()["operations"][0]["incident_id"]
            == first.json()["operations"][0]["incident_id"]
        )


def test_warning_repeat_uses_persisted_notification_timing() -> None:
    value = webhook()
    value["alerts"][0]["labels"]["severity"] = "warning"
    active_runtime = runtime()
    runtime_app = create_app(
        settings=settings(),
        runtime=active_runtime,
        policy=policy(),
        env={
            "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true",
            "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
        },
    )
    with TestClient(runtime_app) as client:
        first = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-repeat-first-0001"),
        )
        assert first.status_code == 202
        first_operation = first.json()["operations"][0]["operation_id"]
        assert first.json()["operations"][0]["notification_status"] == "scheduled"

        suppressed = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-repeat-suppressed-0001"),
        )
        assert suppressed.status_code == 200
        assert suppressed.json()["operations"][0]["operation_id"] == first_operation
        assert suppressed.json()["operations"][0]["notification_status"] == "scheduled"

        assert active_runtime.incidents is not None
        store = active_runtime.incidents.store
        notification_key = next(iter(store._notifications))  # type: ignore[attr-defined]
        notification = store._notifications[notification_key][0]  # type: ignore[attr-defined]
        store._notifications[notification_key][0] = (  # type: ignore[attr-defined]
            notification[0],
            notification[1],
            notification[2],
            datetime.now(UTC) - timedelta(seconds=14_401),
        )

        suppressed_replay = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-repeat-suppressed-0001"),
        )
        assert suppressed_replay.status_code == 200
        assert (
            suppressed_replay.json()["operations"][0]["operation_id"] == first_operation
        )

        repeated = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-repeat-second-0001"),
        )
        assert repeated.status_code == 202
        repeated_operation = repeated.json()["operations"][0]["operation_id"]
        assert repeated_operation != first_operation
        assert repeated.json()["operations"][0]["notification_status"] == "queued"

        replay = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-repeat-second-0001"),
        )
        assert replay.status_code == 200
        assert replay.json()["operations"][0]["operation_id"] == repeated_operation
        assert replay.json()["operations"][0]["notification_status"] == "queued"

        incident_id = repeated.json()["operations"][0]["incident_id"]
        timeline = client.get(
            f"/v1/observability/incidents/{incident_id}/timeline",
            headers=headers("observability-operator", key="warning-timeline-0001"),
        )
        assert [item["event_type"] for item in timeline.json()["items"]] == [
            "firing",
            "notification_suppressed",
            "notification_repeat",
        ]
        attempts = client.get(
            f"/v1/observability/incidents/{incident_id}/notification-attempts",
            headers=headers(
                "observability-operator",
                key="warning-attempts-0001",
            ),
        )
        assert attempts.status_code == 200
        assert [item["operation_id"] for item in attempts.json()["items"]] == [
            repeated_operation,
            first_operation,
        ]

        repeat_suppressed = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-repeat-third-0001"),
        )
        assert repeat_suppressed.status_code == 200
        assert (
            repeat_suppressed.json()["operations"][0]["notification_status"] == "queued"
        )
        repeat_suppressed_replay = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-repeat-third-0001"),
        )
        assert repeat_suppressed_replay.status_code == 200
        assert (
            repeat_suppressed_replay.json()["operations"][0]["notification_status"]
            == "queued"
        )


def test_warning_resolution_cancels_pending_grouped_notification() -> None:
    value = webhook()
    value["alerts"][0]["labels"]["severity"] = "warning"
    active_runtime = runtime()
    runtime_app = create_app(
        settings=settings(),
        runtime=active_runtime,
        policy=policy(),
        env={
            "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true",
            "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
        },
    )
    with TestClient(runtime_app) as client:
        firing = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-group-wait-firing-0001"),
        )
        assert firing.status_code == 202
        firing_operation = firing.json()["operations"][0]["operation_id"]

        resolved_value = copy.deepcopy(value)
        resolved_value["status"] = "resolved"
        resolved_value["alerts"][0]["status"] = "resolved"
        resolved_value["alerts"][0]["endsAt"] = "2026-09-02T16:02:00Z"
        resolved = client.post(
            "/v1/integrations/alertmanager/events",
            json=resolved_value,
            headers=headers(key="warning-group-wait-resolved-0001"),
        )
        assert resolved.status_code == 202
        assert resolved.json()["operations"][0]["operation_id"] != firing_operation

    assert active_runtime.commands is not None
    cancelled = asyncio.run(
        active_runtime.commands.get(
            "codestra-platform",
            UUID(firing_operation),
        )
    )
    assert cancelled.state == "cancelled"
    assert cancelled.cancellation_reason == (
        "warning resolved before group wait elapsed"
    )


def test_status_suppression_cancels_group_wait_and_blocks_delayed_repeat() -> None:
    value = webhook()
    value["alerts"][0]["labels"]["severity"] = "warning"
    active_runtime = runtime()
    runtime_app = create_app(
        settings=settings(),
        runtime=active_runtime,
        policy=policy(),
        env={
            "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true",
            "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
        },
    )
    with TestClient(runtime_app) as client:
        firing = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-status-firing-0001"),
        )
        assert firing.status_code == 202
        incident_id = firing.json()["operations"][0]["incident_id"]
        operation_id = firing.json()["operations"][0]["operation_id"]
        snapshot = {
            "observedAt": "2026-09-02T16:01:00Z",
            "sourceDeployment": "alertmanager-test-1",
            "items": [
                {
                    "groupKey": value["groupKey"],
                    "fingerprint": value["alerts"][0]["fingerprint"],
                    "startsAt": value["alerts"][0]["startsAt"],
                    "state": "silenced",
                    "silencedBy": ["silence-group-wait-1"],
                    "inhibitedBy": [],
                }
            ],
        }
        silenced = client.post(
            "/v1/integrations/alertmanager/status-events",
            json=snapshot,
            headers=headers(key="warning-status-silenced-0001"),
        )
        assert silenced.status_code == 200
        assert silenced.json()["items"][0]["state"] == "silenced"

        assert active_runtime.incidents is not None
        store = active_runtime.incidents.store
        notification_key = next(iter(store._notifications))  # type: ignore[attr-defined]
        notification = store._notifications[notification_key][0]  # type: ignore[attr-defined]
        store._notifications[notification_key][0] = (  # type: ignore[attr-defined]
            notification[0],
            notification[1],
            notification[2],
            datetime.now(UTC) - timedelta(seconds=14_401),
        )
        delayed = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-status-delayed-firing-0001"),
        )
        assert delayed.status_code == 200
        assert delayed.json()["operations"][0]["operation_id"] == operation_id
        assert len(store._notifications[notification_key]) == 1  # type: ignore[attr-defined]

        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=headers("observability-operator", key="warning-status-read-0001"),
        )
        assert detail.json()["state"] == "silenced"

    assert active_runtime.commands is not None
    cancelled = asyncio.run(
        active_runtime.commands.get("codestra-platform", UUID(operation_id))
    )
    assert cancelled.state == "cancelled"


def test_operator_resolution_cancels_pending_group_wait() -> None:
    value = webhook()
    value["alerts"][0]["labels"]["severity"] = "warning"
    active_runtime = runtime()
    runtime_app = create_app(
        settings=settings(),
        runtime=active_runtime,
        policy=policy(),
        env={
            "OBSERVABILITY_ALERT_EMAIL_DELIVERY": "true",
            "OBSERVABILITY_ALERT_ACTIVATION_ID": "CHG-TEST-OBS-ALERT-01",
        },
    )
    with TestClient(runtime_app) as client:
        firing = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="warning-operator-firing-0001"),
        )
        operation_id = firing.json()["operations"][0]["operation_id"]
        incident_id = firing.json()["operations"][0]["incident_id"]
        resolved = client.post(
            f"/v1/observability/incidents/{incident_id}/resolve",
            json={"expected_version": 1, "reason": "operator verified recovery"},
            headers=headers(
                "observability-operator", key="warning-operator-resolve-0001"
            ),
        )
        assert resolved.status_code == 200
        assert resolved.json()["state"] == "resolved"

    assert active_runtime.commands is not None
    cancelled = asyncio.run(
        active_runtime.commands.get("codestra-platform", UUID(operation_id))
    )
    assert cancelled.state == "cancelled"
    assert cancelled.cancellation_reason == (
        "warning was resolved before group wait elapsed"
    )


def test_delayed_webhook_cannot_replace_a_newer_alert_occurrence() -> None:
    first_value = webhook()
    newer_value = copy.deepcopy(first_value)
    newer_value["alerts"][0]["startsAt"] = "2026-09-02T17:00:00Z"
    with TestClient(app()) as client:
        first = client.post(
            "/v1/integrations/alertmanager/events",
            json=first_value,
            headers=headers(key="occurrence-first-0001"),
        )
        assert first.status_code == 202
        incident_id = first.json()["operations"][0]["incident_id"]
        newer = client.post(
            "/v1/integrations/alertmanager/events",
            json=newer_value,
            headers=headers(key="occurrence-newer-0001"),
        )
        assert newer.status_code == 202
        delayed = client.post(
            "/v1/integrations/alertmanager/events",
            json=first_value,
            headers=headers(key="delayed-0001"),
        )
        assert delayed.status_code == 409
        assert delayed.json()["code"] == "incident_conflict"
        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=headers("observability-operator", key="occurrence-read-0001"),
        )
        assert detail.json()["starts_at"] == "2026-09-02T17:00:00Z"


def test_delayed_firing_webhook_cannot_reopen_an_already_ended_occurrence() -> None:
    firing_value = webhook()
    resolved_value = copy.deepcopy(firing_value)
    resolved_value["status"] = "resolved"
    resolved_value["alerts"][0]["status"] = "resolved"
    resolved_value["alerts"][0]["endsAt"] = "2026-09-02T16:10:00Z"
    with TestClient(app()) as client:
        resolved = client.post(
            "/v1/integrations/alertmanager/events",
            json=resolved_value,
            headers=headers(key="ended-occurrence-resolved-0001"),
        )
        assert resolved.status_code == 202
        incident_id = resolved.json()["operations"][0]["incident_id"]
        delayed = client.post(
            "/v1/integrations/alertmanager/events",
            json=firing_value,
            headers=headers(key="ended-occurrence-delayed-firing-0001"),
        )
        assert delayed.status_code == 409
        assert delayed.json()["code"] == "incident_conflict"
        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=headers("observability-operator", key="ended-occurrence-read-0001"),
        )
        assert detail.status_code == 200
        assert detail.json()["state"] == "resolved"
        assert detail.json()["ends_at"] == "2026-09-02T16:10:00Z"


def test_status_cycles_and_rejects_stale_observations() -> None:
    value = webhook()
    with TestClient(app()) as client:
        accepted = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="status-cycle-alert-0001"),
        )
        incident_id = accepted.json()["operations"][0]["incident_id"]

        def status_payload(observed_at: str, state: str) -> dict[str, Any]:
            return {
                "observedAt": observed_at,
                "sourceDeployment": "alertmanager-test-1",
                "items": [
                    {
                        "groupKey": value["groupKey"],
                        "fingerprint": value["alerts"][0]["fingerprint"],
                        "startsAt": value["alerts"][0]["startsAt"],
                        "state": state,
                        "silencedBy": ["silence-cycle-1"]
                        if state == "silenced"
                        else [],
                        "inhibitedBy": [],
                    }
                ],
            }

        silenced = client.post(
            "/v1/integrations/alertmanager/status-events",
            json=status_payload("2026-09-02T16:02:00Z", "silenced"),
            headers=headers(key="status-cycle-silenced-0001"),
        )
        assert silenced.status_code == 200
        firing = client.post(
            "/v1/integrations/alertmanager/status-events",
            json=status_payload("2026-09-02T16:03:00Z", "firing"),
            headers=headers(key="status-cycle-firing-0001"),
        )
        assert firing.status_code == 200
        assert firing.json()["items"][0]["state"] == "firing"

        wrong_occurrence = status_payload("2026-09-02T16:05:00Z", "silenced")
        wrong_occurrence["items"][0]["startsAt"] = "2026-09-02T15:00:00Z"
        rejected_occurrence = client.post(
            "/v1/integrations/alertmanager/status-events",
            json=wrong_occurrence,
            headers=headers(key="status-cycle-old-occurrence-0001"),
        )
        assert rejected_occurrence.status_code == 409
        assert rejected_occurrence.json()["code"] == "incident_conflict"

        stale = client.post(
            "/v1/integrations/alertmanager/status-events",
            json=status_payload("2026-09-02T16:01:00Z", "silenced"),
            headers=headers(key="status-cycle-stale-0001"),
        )
        assert stale.status_code == 409
        assert stale.json()["code"] == "incident_conflict"

        reused_key = client.post(
            "/v1/integrations/alertmanager/status-events",
            json=status_payload("2026-09-02T16:04:00Z", "silenced"),
            headers=headers(key="status-cycle-firing-0001"),
        )
        assert reused_key.status_code == 409
        assert reused_key.json()["code"] == "incident_conflict"

        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=headers("observability-operator", key="status-cycle-read-0001"),
        )
        assert detail.json()["state"] == "firing"


def test_status_snapshot_before_resolved_end_cannot_reopen_incident() -> None:
    value = webhook()
    with TestClient(app()) as client:
        accepted = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="status-order-firing-0001"),
        )
        incident_id = accepted.json()["operations"][0]["incident_id"]
        resolved_value = copy.deepcopy(value)
        resolved_value["status"] = "resolved"
        resolved_value["alerts"][0]["status"] = "resolved"
        resolved_value["alerts"][0]["endsAt"] = "2026-09-02T16:10:00Z"
        resolved = client.post(
            "/v1/integrations/alertmanager/events",
            json=resolved_value,
            headers=headers(key="status-order-resolved-0001"),
        )
        assert resolved.status_code == 202

        stale_status = client.post(
            "/v1/integrations/alertmanager/status-events",
            json={
                "observedAt": "2026-09-02T16:05:00Z",
                "sourceDeployment": "alertmanager-test-1",
                "items": [
                    {
                        "groupKey": value["groupKey"],
                        "fingerprint": value["alerts"][0]["fingerprint"],
                        "startsAt": value["alerts"][0]["startsAt"],
                        "state": "firing",
                        "silencedBy": [],
                        "inhibitedBy": [],
                    }
                ],
            },
            headers=headers(key="status-order-stale-0001"),
        )
        assert stale_status.status_code == 409
        assert stale_status.json()["code"] == "incident_conflict"
        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=headers("observability-operator", key="status-order-read-0001"),
        )
        assert detail.json()["state"] == "resolved"


def test_newer_firing_status_reopens_ended_occurrence_for_matching_webhook() -> None:
    value = webhook()
    resolved_value = copy.deepcopy(value)
    resolved_value["status"] = "resolved"
    resolved_value["alerts"][0]["status"] = "resolved"
    resolved_value["alerts"][0]["endsAt"] = "2026-09-02T16:10:00Z"
    with TestClient(app()) as client:
        resolved = client.post(
            "/v1/integrations/alertmanager/events",
            json=resolved_value,
            headers=headers(key="status-reopen-resolved-0001"),
        )
        assert resolved.status_code == 202
        incident_id = resolved.json()["operations"][0]["incident_id"]

        reopened = client.post(
            "/v1/integrations/alertmanager/status-events",
            json={
                "observedAt": "2026-09-02T16:11:00Z",
                "sourceDeployment": "alertmanager-test-1",
                "items": [
                    {
                        "groupKey": value["groupKey"],
                        "fingerprint": value["alerts"][0]["fingerprint"],
                        "startsAt": value["alerts"][0]["startsAt"],
                        "state": "firing",
                        "silencedBy": [],
                        "inhibitedBy": [],
                    }
                ],
            },
            headers=headers(key="status-reopen-snapshot-0001"),
        )
        assert reopened.status_code == 200
        assert reopened.json()["items"][0]["state"] == "firing"
        assert reopened.json()["items"][0]["ends_at"] is None

        matching = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="status-reopen-webhook-0001"),
        )
        assert matching.status_code == 202
        assert matching.json()["operations"][0]["incident_id"] == incident_id


def test_newer_firing_status_clears_end_evidence_while_acknowledged() -> None:
    value = webhook()
    resolved_value = copy.deepcopy(value)
    resolved_value["status"] = "resolved"
    resolved_value["alerts"][0]["status"] = "resolved"
    resolved_value["alerts"][0]["endsAt"] = "2026-09-02T16:10:00Z"
    with TestClient(app()) as client:
        resolved = client.post(
            "/v1/integrations/alertmanager/events",
            json=resolved_value,
            headers=headers(key="status-ack-reopen-resolved-0001"),
        )
        assert resolved.status_code == 202
        incident_id = resolved.json()["operations"][0]["incident_id"]

        silenced = client.post(
            "/v1/integrations/alertmanager/status-events",
            json={
                "observedAt": "2026-09-02T16:11:00Z",
                "sourceDeployment": "alertmanager-test-1",
                "items": [
                    {
                        "groupKey": value["groupKey"],
                        "fingerprint": value["alerts"][0]["fingerprint"],
                        "startsAt": value["alerts"][0]["startsAt"],
                        "state": "silenced",
                        "silencedBy": ["status-ack-reopen-silence-1"],
                        "inhibitedBy": [],
                    }
                ],
            },
            headers=headers(key="status-ack-reopen-silenced-0001"),
        )
        assert silenced.status_code == 200
        assert silenced.json()["items"][0]["ends_at"] == "2026-09-02T16:10:00Z"

        acknowledged = client.post(
            f"/v1/observability/incidents/{incident_id}/acknowledge",
            json={"expected_version": 2, "reason": "operator owns recurrence"},
            headers=headers(
                "observability-operator",
                key="status-ack-reopen-mutation-0001",
            ),
        )
        assert acknowledged.status_code == 200
        assert acknowledged.json()["state"] == "acknowledged"
        assert acknowledged.json()["ends_at"] == "2026-09-02T16:10:00Z"

        firing = client.post(
            "/v1/integrations/alertmanager/status-events",
            json={
                "observedAt": "2026-09-02T16:12:00Z",
                "sourceDeployment": "alertmanager-test-1",
                "items": [
                    {
                        "groupKey": value["groupKey"],
                        "fingerprint": value["alerts"][0]["fingerprint"],
                        "startsAt": value["alerts"][0]["startsAt"],
                        "state": "firing",
                        "silencedBy": [],
                        "inhibitedBy": [],
                    }
                ],
            },
            headers=headers(key="status-ack-reopen-firing-0001"),
        )
        assert firing.status_code == 200
        assert firing.json()["items"][0]["state"] == "acknowledged"
        assert firing.json()["items"][0]["ends_at"] is None

        matching = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="status-ack-reopen-webhook-0001"),
        )
        assert matching.status_code == 202
        assert matching.json()["operations"][0]["incident_id"] == incident_id


def test_operator_reopen_clears_ended_occurrence_for_matching_webhook() -> None:
    firing_value = webhook()
    resolved_value = copy.deepcopy(firing_value)
    resolved_value["status"] = "resolved"
    resolved_value["alerts"][0]["status"] = "resolved"
    resolved_value["alerts"][0]["endsAt"] = "2026-09-02T16:10:00Z"
    with TestClient(app()) as client:
        resolved = client.post(
            "/v1/integrations/alertmanager/events",
            json=resolved_value,
            headers=headers(key="operator-reopen-resolved-0001"),
        )
        assert resolved.status_code == 202
        incident_id = resolved.json()["operations"][0]["incident_id"]

        reopened = client.post(
            f"/v1/observability/incidents/{incident_id}/reopen",
            json={"expected_version": 1, "reason": "operator verified recurrence"},
            headers=headers(
                "observability-operator",
                key="operator-reopen-mutation-0001",
            ),
        )
        assert reopened.status_code == 200
        assert reopened.json()["state"] == "firing"
        assert reopened.json()["ends_at"] is None

        matching = client.post(
            "/v1/integrations/alertmanager/events",
            json=firing_value,
            headers=headers(key="operator-reopen-webhook-0001"),
        )
        assert matching.status_code == 202
        assert matching.json()["operations"][0]["incident_id"] == incident_id


def test_status_snapshot_reports_partial_application_per_item() -> None:
    value = webhook()
    with TestClient(app()) as client:
        accepted = client.post(
            "/v1/integrations/alertmanager/events",
            json=value,
            headers=headers(key="status-partial-alert-0001"),
        )
        incident_id = accepted.json()["operations"][0]["incident_id"]
        valid = {
            "groupKey": value["groupKey"],
            "fingerprint": value["alerts"][0]["fingerprint"],
            "startsAt": value["alerts"][0]["startsAt"],
            "state": "silenced",
            "silencedBy": ["silence-partial-1"],
            "inhibitedBy": [],
        }
        missing = copy.deepcopy(valid)
        missing["fingerprint"] = "missing-partial-incident"
        response = client.post(
            "/v1/integrations/alertmanager/status-events",
            json={
                "observedAt": "2026-09-02T16:10:00Z",
                "sourceDeployment": "alertmanager-test-1",
                "items": [valid, missing],
            },
            headers=headers(key="status-partial-snapshot-0001"),
        )
        assert response.status_code == 207
        assert [item["result_status"] for item in response.json()["items"]] == [
            "applied",
            "rejected",
        ]
        assert response.json()["items"][1]["code"] == "incident_not_found"

        detail = client.get(
            f"/v1/observability/incidents/{incident_id}",
            headers=headers("observability-operator", key="status-partial-read-0001"),
        )
        assert detail.json()["state"] == "silenced"


def test_postgres_mutation_query_casts_conditional_parameters() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "app/observability_incidents.py"
    ).read_text(encoding="utf-8")
    assert "THEN $5::timestamptz ELSE NULL::timestamptz END" in source
    assert "THEN $6::text ELSE NULL::text END" in source
    assert "updated_at=$5::timestamptz" in source
    assert "last_seen_at=$4::timestamptz" in source
    assert "THEN $4::timestamptz ELSE NULL::timestamptz END" in source
    assert "source_deployment=$5::text, correlation_id=$6::text" in source


def test_canonical_openapi_methods_match_runtime() -> None:
    runtime_app = app()
    documented = yaml.safe_load(
        Path("contracts/observability/alert-api.v1.openapi.yaml").read_text(
            encoding="utf-8"
        )
    )
    http_methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
    runtime_methods = {
        (route.path, method)
        for route in runtime_app.routes
        if route.path != "/openapi.json"
        for method in route.methods
        if method in http_methods
    }
    documented_methods = {
        (path, method.upper())
        for path, path_item in documented["paths"].items()
        for method in path_item
        if method.upper() in http_methods
    }
    assert runtime_methods == documented_methods


def test_delivery_callback_uses_durable_inbox_and_is_replay_safe() -> None:
    with TestClient(app()) as client:
        accepted = client.post(
            "/v1/observability/alerts",
            json=webhook(),
            headers=headers(),
        )
        operation_id = accepted.json()["operations"][0]["operation_id"]
        delivery = {
            "event_id": "delivery-event-0001",
            "operation_id": operation_id,
            "status": "delivered",
            "provider_message_id": operation_id,
            "occurred_at": datetime(
                2026,
                9,
                2,
                16,
                5,
                tzinfo=UTC,
            ).isoformat(),
            "safe_metadata": {"provider_status": "delivered"},
        }
        delivery_headers = headers(
            "klyrow-alert-adapter",
            key="delivery-event-0001",
        )
        first = client.post(
            "/v1/observability/alert-delivery-events",
            json=delivery,
            headers=delivery_headers,
        )
        assert first.status_code == 202
        assert first.json()["status"] == "accepted"
        assert first.json()["authoritative_completion"] == "provider-readback"

        assert isinstance(client.app, FastAPI)
        stored = client.app.state.runtime.inbox
        assert stored.ledger_records[-1].payload["event_type"] == (
            "codestra.observability.alert_delivery.v1"
        )

        replay = client.post(
            "/v1/observability/alert-delivery-events",
            json=delivery,
            headers=delivery_headers,
        )
        assert replay.status_code == 200
        assert replay.json()["duplicate"] is True


def test_wrong_caller_and_environment_are_denied() -> None:
    with TestClient(app()) as client:
        wrong_caller = client.post(
            "/v1/observability/alerts",
            json=webhook(),
            headers=headers("kong-gateway"),
        )
        assert wrong_caller.status_code == 403

        production = webhook()
        production["alerts"][0]["labels"]["environment"] = "production"
        production["commonLabels"]["environment"] = "production"
        wrong_environment = client.post(
            "/v1/observability/alerts",
            json=production,
            headers=headers(key="environment-test-key"),
        )
        assert wrong_environment.status_code == 403


def native_headers(client_id: str = "alertmanager") -> dict[str, str]:
    value = headers(client_id)
    value.pop("Idempotency-Key")
    value.pop("X-Correlation-ID")
    value["X-Alertmanager-Native-Webhook"] = "v4"
    return value


def test_native_webhook_derives_transport_identity_and_deduplicates() -> None:
    value = webhook()
    value["receiver"] = "middleware-critical"
    with TestClient(app(active=False)) as client:
        first = client.post(
            "/v1/integrations/alertmanager/events", json=value, headers=native_headers()
        )
        assert first.status_code == 202
        assert first.headers["X-Correlation-ID"].startswith("alertmanager-native-")
        assert first.json()["operations"][0]["notification_status"] == "disabled"
        replay = client.post(
            "/v1/integrations/alertmanager/events", json=value, headers=native_headers()
        )
        assert replay.status_code == 200
        assert replay.json()["operations"][0]["duplicate"] is True
        assert (
            replay.json()["operations"][0]["incident_id"]
            == first.json()["operations"][0]["incident_id"]
        )


def test_native_webhook_cannot_bypass_workload_or_tenant() -> None:
    with TestClient(app(active=False)) as client:
        wrong_client = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=native_headers("observability-operator"),
        )
        assert wrong_client.status_code == 403
        wrong_tenant = native_headers()
        wrong_tenant["X-Tenant-ID"] = "another-tenant"
        response = client.post(
            "/v1/integrations/alertmanager/events", json=webhook(), headers=wrong_tenant
        )
        assert response.status_code == 403


def test_native_webhook_rejects_unknown_receiver_and_truncation() -> None:
    with TestClient(app(active=False)) as client:
        for value in [
            dict(webhook(), receiver="arbitrary-receiver"),
            dict(webhook(), truncatedAlerts=1),
        ]:
            response = client.post(
                "/v1/integrations/alertmanager/events",
                json=value,
                headers=native_headers(),
            )
            assert response.status_code in {400, 403}


def test_explicit_transport_keeps_required_headers_and_receiver() -> None:
    with TestClient(app(active=False)) as client:
        missing = native_headers()
        missing.pop("X-Alertmanager-Native-Webhook")
        response = client.post(
            "/v1/integrations/alertmanager/events", json=webhook(), headers=missing
        )
        assert response.status_code == 400
        value = dict(webhook(), receiver="middleware-critical")
        response = client.post(
            "/v1/integrations/alertmanager/events", json=value, headers=headers()
        )
        assert response.status_code == 403


def test_native_changed_semantic_payload_still_conflicts() -> None:
    value = webhook()
    with TestClient(app(active=False)) as client:
        first = client.post(
            "/v1/integrations/alertmanager/events", json=value, headers=native_headers()
        )
        assert first.status_code == 202
        value["alerts"][0]["annotations"]["summary"] = "changed semantic payload"
        conflict = client.post(
            "/v1/integrations/alertmanager/events", json=value, headers=native_headers()
        )
        assert conflict.status_code == 409


def test_native_preserves_source_and_metadata_requirements() -> None:
    with TestClient(app(active=False)) as client:
        missing_source = native_headers()
        missing_source.pop("X-Source-Deployment")
        response = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=missing_source,
        )
        assert response.status_code == 400
        missing_host = webhook()
        del missing_host["alerts"][0]["labels"]["host"]
        response = client.post(
            "/v1/integrations/alertmanager/events",
            json=missing_host,
            headers=native_headers(),
        )
        assert response.status_code == 400


def test_native_batch_is_bounded_and_works_with_single_alert_explicit_policy() -> None:
    selected = policy().model_copy(update={"max_alerts_per_request": 1})
    service = create_app(
        settings=settings(), runtime=runtime(active=False), policy=selected, env={}
    )
    value = webhook()
    second = copy.deepcopy(value["alerts"][0])
    second["fingerprint"] = "def456abc123"
    second["labels"]["host"] = "another-provider-host"
    value["alerts"].append(second)
    with TestClient(service) as client:
        response = client.post(
            "/v1/integrations/alertmanager/events", json=value, headers=native_headers()
        )
        assert response.status_code == 202
        assert len(response.json()["operations"]) == 2
        excessive = webhook()
        excessive["alerts"] = [
            copy.deepcopy(excessive["alerts"][0]) for _ in range(101)
        ]
        rejected = client.post(
            "/v1/integrations/alertmanager/events",
            json=excessive,
            headers=native_headers(),
        )
        assert rejected.status_code == 400


def test_native_informational_is_normalized_to_state_only_info() -> None:
    selected = policy().model_copy(
        update={
            "allowed_severities": ["info"],
            "immediate_severities": [],
            "grouped_severities": [],
            "state_only_severities": ["info"],
        }
    )
    service = create_app(
        settings=settings(), runtime=runtime(active=False), policy=selected, env={}
    )
    value = webhook()
    value["receiver"] = "middleware-informational"
    value["alerts"][0]["labels"]["severity"] = "informational"
    with TestClient(service) as client:
        response = client.post(
            "/v1/integrations/alertmanager/events", json=value, headers=native_headers()
        )
        assert response.status_code == 202
        assert response.json()["operations"][0]["operation_id"] is None


def test_canonical_internal_path_shares_authorization_and_replay_store() -> None:
    with TestClient(app()) as client:
        canonical = "/internal/v1/alerts/alertmanager"
        assert client.post(canonical, json=webhook()).status_code in {401, 403}

        accepted = client.post(canonical, json=webhook(), headers=headers())
        assert accepted.status_code == 202

        replay = client.post(
            "/v1/integrations/alertmanager/events",
            json=webhook(),
            headers=headers(),
        )
        assert replay.status_code == 200
        accepted_operation = accepted.json()["operations"][0]
        replay_operation = replay.json()["operations"][0]
        assert replay_operation["duplicate"] is True
        assert replay_operation["operation_id"] == accepted_operation["operation_id"]
