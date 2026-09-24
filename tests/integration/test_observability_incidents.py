from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

from app.commands import (
    CommandConflict,
    CommandEnvelope,
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    PostgresCommandStore,
)
from app.observability_alert_contract import (
    ALERTMANAGER_CLIENT_ID,
    AlertPolicy,
    AlertmanagerAlert,
    build_command,
)
from app.observability_incidents import (
    AlertmanagerStatusItem,
    IncidentConflict,
    IncidentService,
    PostgresIncidentStore,
    incident_identity,
)


DATABASE_URL = os.getenv("DATABASE_URL", "")
RUN = os.getenv("RUNTIME_INTEGRATION_TESTS") == "1"
TENANT_ID = f"observability-incident-integration-{uuid.uuid4()}"
ACTOR_ID = "service-account-alertmanager"
GROUP_KEY = '{}:{alertname="IncidentIntegration"}'

pytestmark = pytest.mark.skipif(
    not RUN,
    reason="set RUNTIME_INTEGRATION_TESTS=1 against disposable PostgreSQL/Redis",
)


def policy() -> AlertPolicy:
    return AlertPolicy.model_validate(
        {
            "schema_version": "1.0",
            "policy_id": "observability-incident-integration-v1",
            "tenant_id": TENANT_ID,
            "receiver": "codestra-observability-email",
            "recipient_policy_id": "codestra-observability-admin-v1",
            "sender_policy_id": "codestra-alert-sender-v1",
            "recipient": "integration@example.invalid",
            "sender": "alerts@example.invalid",
            "reply_to": "integration@example.invalid",
            "allowed_environments": ["integration"],
            "allowed_severities": ["critical", "warning", "info"],
            "immediate_severities": ["critical"],
            "grouped_severities": ["warning"],
            "state_only_severities": ["info"],
            "warning_group_wait_seconds": 300,
            "warning_repeat_interval_seconds": 14_400,
            "max_alerts_per_request": 20,
            "max_body_bytes": 131_072,
            "normal_delivery_path": "middleware-klyrow-adapter",
            "direct_smtp_allowed": False,
            "delivery_enabled_by_default": False,
        }
    )


def alert(*, fingerprint: str, severity: str = "critical") -> AlertmanagerAlert:
    return AlertmanagerAlert.model_validate(
        {
            "status": "firing",
            "labels": {
                "alertname": "IncidentIntegration",
                "severity": severity,
                "service": "disposable-ci",
                "environment": "integration",
                "host": "disposable-postgres",
                "codestra_business": "platform",
                "owner": "codestra-observability",
            },
            "annotations": {
                "summary": "Disposable incident integration test",
                "description": "No provider or production traffic is produced.",
                "runbook_url": "https://runbooks.example.invalid/incident-integration",
            },
            "startsAt": "2026-09-02T16:00:00Z",
            "endsAt": "2026-09-02T16:00:00Z",
            "generatorURL": "https://prom.example.invalid/graph",
            "fingerprint": fingerprint,
        }
    )


def services(pool: asyncpg.Pool) -> tuple[CommandService, IncidentService]:
    commands = CommandService(
        store=PostgresCommandStore(pool),
        policies=CommandPolicyRegistry(
            policies=(
                CommandPolicy(
                    prefix="observability.alert.",
                    target="klyrow-alert-email",
                    capability="OBSERVABILITY_ALERT_EMAIL_DELIVERY",
                    readback_required=True,
                ),
            ),
            capabilities={"OBSERVABILITY_ALERT_EMAIL_DELIVERY": True},
        ),
    )
    incidents = IncidentService(
        store=PostgresIncidentStore(commands),
        commands=commands,
        policy=policy(),
        delivery_enabled=True,
    )
    return commands, incidents


@pytest_asyncio.fixture
async def pool() -> asyncpg.Pool:
    assert DATABASE_URL, "DATABASE_URL is required"
    value = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=4)
    async with value.acquire() as conn:
        for migration in sorted(
            Path("migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")
        ):
            await conn.execute(migration.read_text(encoding="utf-8"))
    try:
        yield value
    finally:
        await value.close()


@pytest.mark.asyncio
async def test_incident_command_and_notification_commit_atomically(
    pool: asyncpg.Pool,
) -> None:
    commands, incidents = services(pool)
    item = alert(fingerprint="incident-atomic-0001")

    first = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-request-0001",
    )
    assert first.operation is not None
    assert first.notification_status == "queued"
    assert first.duplicate is False
    assert await incidents.store.ready() is True
    assert await commands.store.ready() is True

    replay = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="different-transport-key-0001",
    )
    assert replay.duplicate is True
    assert replay.operation is not None
    assert replay.operation.command_id == first.operation.command_id

    async with pool.acquire() as conn:
        counts = {
            table: await conn.fetchval(
                f"SELECT count(*) FROM {table} WHERE tenant_id=$1",  # noqa: S608
                TENANT_ID,
            )
            for table in (
                "middleware_observability_incidents",
                "middleware_observability_incident_events",
                "middleware_observability_incident_audit",
                "middleware_observability_notification_intents",
                "middleware_commands",
                "middleware_command_audit",
                "middleware_outbox",
            )
        }
    assert counts == {table: 1 for table in counts}
    acknowledged = await incidents.store.mutate(
        TENANT_ID,
        first.incident.incident_id,
        action="acknowledge",
        actor_id="service-account-observability-operator",
        correlation_id="incident-correlation-ack-0001",
        idempotency_key="incident-acknowledge-0001",
        expected_version=1,
        reason="disposable integration acknowledgement",
    )
    assert acknowledged.state == "acknowledged"
    assert acknowledged.resource_version == 2

    silenced = await incidents.store.ingest_status(
        policy=policy(),
        item=AlertmanagerStatusItem.model_validate(
            {
                "groupKey": GROUP_KEY,
                "fingerprint": item.fingerprint,
                "startsAt": "2026-09-02T16:00:00Z",
                "state": "silenced",
                "silencedBy": ["disposable-silence-1"],
                "inhibitedBy": [],
            }
        ),
        actor_id=ACTOR_ID,
        correlation_id="incident-correlation-status-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-request-0001",
        observed_at=datetime(2026, 9, 2, 16, 1, tzinfo=UTC),
    )
    assert silenced.state == "silenced"
    firing = await incidents.store.ingest_status(
        policy=policy(),
        item=AlertmanagerStatusItem.model_validate(
            {
                "groupKey": GROUP_KEY,
                "fingerprint": item.fingerprint,
                "startsAt": "2026-09-02T16:00:00Z",
                "state": "firing",
                "silencedBy": [],
                "inhibitedBy": [],
            }
        ),
        actor_id=ACTOR_ID,
        correlation_id="incident-correlation-status-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-request-0002",
        observed_at=datetime(2026, 9, 2, 16, 2, tzinfo=UTC),
    )
    assert firing.state == "firing"
    with pytest.raises(IncidentConflict):
        await incidents.store.ingest_status(
            policy=policy(),
            item=AlertmanagerStatusItem.model_validate(
                {
                    "groupKey": GROUP_KEY,
                    "fingerprint": item.fingerprint,
                    "startsAt": "2026-09-02T15:00:00Z",
                    "state": "silenced",
                    "silencedBy": ["old-occurrence-silence-1"],
                    "inhibitedBy": [],
                }
            ),
            actor_id=ACTOR_ID,
            correlation_id="incident-correlation-status-old-occurrence",
            source_deployment="alertmanager-disposable-ci",
            request_idempotency_key="incident-status-request-old-occurrence",
            observed_at=datetime(2026, 9, 2, 16, 3, tzinfo=UTC),
        )
    with pytest.raises(IncidentConflict):
        await incidents.store.ingest_status(
            policy=policy(),
            item=AlertmanagerStatusItem.model_validate(
                {
                    "groupKey": GROUP_KEY,
                    "fingerprint": item.fingerprint,
                    "startsAt": "2026-09-02T16:00:00Z",
                    "state": "silenced",
                    "silencedBy": ["stale-silence-1"],
                    "inhibitedBy": [],
                }
            ),
            actor_id=ACTOR_ID,
            correlation_id="incident-correlation-status-stale",
            source_deployment="alertmanager-disposable-ci",
            request_idempotency_key="incident-status-request-stale",
            observed_at=datetime(2026, 9, 2, 16, 0, tzinfo=UTC),
        )
    timeline = await incidents.store.list_timeline(
        TENANT_ID,
        first.incident.incident_id,
        limit=10,
        after_event_id=None,
    )
    assert [event.event_type for event in timeline] == [
        "firing",
        "acknowledge",
        "silenced",
        "firing",
    ]
    assert timeline[-1].occurred_at == datetime(2026, 9, 2, 16, 2, tzinfo=UTC)

    async with pool.acquire() as conn:
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute(
                "UPDATE middleware_observability_incident_events SET actor_id='tamper' "
                "WHERE tenant_id=$1",
                TENANT_ID,
            )


@pytest.mark.asyncio
async def test_enabling_delivery_queues_an_existing_warning(
    pool: asyncpg.Pool,
) -> None:
    commands, enabled = services(pool)
    disabled = IncidentService(
        store=enabled.store,
        commands=commands,
        policy=policy(),
        delivery_enabled=False,
    )
    item = alert(fingerprint="incident-delivery-activation-0001", severity="warning")
    first = await disabled.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-delivery-disabled-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-delivery-disabled-request-0001",
    )
    assert first.operation is None
    assert first.notification_status == "disabled"

    activated = await enabled.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-delivery-enabled-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-delivery-enabled-request-0001",
    )
    assert activated.operation is not None
    assert activated.notification_status == "scheduled"
    replay = await enabled.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-delivery-enabled-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-delivery-enabled-request-0001",
    )
    assert replay.operation is not None
    assert replay.operation.command_id == activated.operation.command_id
    assert replay.notification_status == "scheduled"
    assert replay.duplicate is True

    async with pool.acquire() as conn:
        intent = await conn.fetchrow(
            """SELECT ni.scheduled_at,c.created_at,o.next_attempt_at,
                      e.event_type,e.safe_metadata,a.action AS audit_action
               FROM middleware_observability_notification_intents ni
               JOIN middleware_commands c ON c.tenant_id=ni.tenant_id
                 AND c.command_id=ni.operation_id
               JOIN middleware_outbox o ON o.tenant_id=ni.tenant_id
                 AND o.command_id=ni.operation_id
               JOIN middleware_observability_incident_events e
                 ON e.tenant_id=ni.tenant_id AND e.operation_id=ni.operation_id
               JOIN middleware_observability_incident_audit a
                 ON a.tenant_id=e.tenant_id AND a.event_id=e.id
               WHERE ni.tenant_id=$1 AND ni.incident_id=$2""",
            TENANT_ID,
            activated.incident.incident_id,
        )
    assert intent is not None
    assert intent["scheduled_at"] > intent["created_at"]
    assert intent["next_attempt_at"] == intent["scheduled_at"]
    assert intent["event_type"] == "firing"
    assert intent["audit_action"] == "notification_activated"
    assert "activated_transition" in intent["safe_metadata"]


@pytest.mark.asyncio
async def test_command_conflict_rolls_back_incident_projection(
    pool: asyncpg.Pool,
) -> None:
    commands, incidents = services(pool)
    item = alert(fingerprint="incident-rollback-0001")
    expected = build_command(
        policy=policy(),
        alert=item,
        group_key=GROUP_KEY,
        receiver=policy().receiver,
        actor=ACTOR_ID,
        correlation_id="incident-correlation-rollback-0001",
        incident_id=incident_identity(TENANT_ID, item.fingerprint),
    )
    changed_payload = expected.model_dump(mode="python")
    changed_payload["payload"]["content"]["subject"] = "Conflicting durable command"
    conflicting = CommandEnvelope.model_validate(changed_payload)
    await commands.submit(
        conflicting,
        authenticated_subject=ACTOR_ID,
        authenticated_client_id=ALERTMANAGER_CLIENT_ID,
    )

    with pytest.raises(CommandConflict):
        await incidents.ingest(
            group_key=GROUP_KEY,
            alert=item,
            actor_id=ACTOR_ID,
            correlation_id="incident-correlation-rollback-0001",
            source_deployment="alertmanager-disposable-ci",
            request_idempotency_key="incident-request-rollback-0001",
        )

    async with pool.acquire() as conn:
        assert (
            await conn.fetchval(
                "SELECT count(*) FROM middleware_observability_incidents "
                "WHERE tenant_id=$1 AND incident_id=$2",
                TENANT_ID,
                incident_identity(TENANT_ID, item.fingerprint),
            )
            == 0
        )
        assert (
            await conn.fetchval(
                "SELECT count(*) FROM middleware_observability_incident_events "
                "WHERE tenant_id=$1 AND incident_id=$2",
                TENANT_ID,
                incident_identity(TENANT_ID, item.fingerprint),
            )
            == 0
        )


@pytest.mark.asyncio
async def test_warning_repeat_uses_persisted_schedule(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    item = alert(fingerprint="incident-warning-repeat-0001", severity="warning")
    first = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-warning-repeat-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-warning-repeat-request-0001",
    )
    assert first.operation is not None
    assert first.notification_status == "scheduled"
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE middleware_observability_notification_intents
            SET scheduled_at=now() - interval '14401 seconds'
            WHERE tenant_id=$1 AND incident_id=$2
            """,
            TENANT_ID,
            first.incident.incident_id,
        )

    repeated = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-warning-repeat-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-warning-repeat-request-0002",
    )
    assert repeated.operation is not None
    assert repeated.operation.command_id != first.operation.command_id
    assert repeated.notification_status == "queued"
    replay = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-warning-repeat-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-warning-repeat-request-0002",
    )
    assert replay.duplicate is True
    assert replay.operation is not None
    assert replay.operation.command_id == repeated.operation.command_id
    assert replay.notification_status == "queued"

    suppressed = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-warning-repeat-correlation-0003",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-warning-repeat-request-0003",
    )
    assert suppressed.operation is not None
    assert suppressed.operation.command_id == repeated.operation.command_id
    assert suppressed.notification_status == "queued"
    suppressed_replay = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-warning-repeat-correlation-0003",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-warning-repeat-request-0003",
    )
    assert suppressed_replay.duplicate is True
    assert suppressed_replay.operation is not None
    assert suppressed_replay.operation.command_id == repeated.operation.command_id
    assert suppressed_replay.notification_status == "queued"

    attempts = await incidents.store.list_notification_attempts(
        TENANT_ID,
        first.incident.incident_id,
        limit=1,
    )
    assert [item.operation_id for item in attempts] == [
        repeated.operation.command_id
    ]

    async with pool.acquire() as conn:
        assert (
            await conn.fetchval(
                "SELECT count(*) FROM middleware_observability_notification_intents "
                "WHERE tenant_id=$1 AND incident_id=$2",
                TENANT_ID,
                first.incident.incident_id,
            )
            == 2
        )
        assert (
            await conn.fetchval(
                "SELECT count(*) FROM middleware_observability_incident_events "
                "WHERE tenant_id=$1 AND incident_id=$2 "
                "AND event_type='notification_repeat'",
                TENANT_ID,
                first.incident.incident_id,
            )
            == 1
        )


@pytest.mark.asyncio
async def test_warning_resolution_cancels_pending_grouped_outbox(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    firing_item = alert(
        fingerprint="incident-warning-group-wait-0001",
        severity="warning",
    )
    firing = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=firing_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-warning-group-wait-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-warning-group-wait-request-0001",
    )
    assert firing.operation is not None
    assert firing.notification_status == "scheduled"

    resolved_payload = firing_item.model_dump(mode="json", by_alias=True)
    resolved_payload["status"] = "resolved"
    resolved_payload["endsAt"] = "2026-09-02T16:02:00Z"
    resolved_item = AlertmanagerAlert.model_validate(resolved_payload)
    resolved = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=resolved_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-warning-group-wait-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-warning-group-wait-request-0002",
    )
    assert resolved.operation is not None
    assert resolved.operation.command_id != firing.operation.command_id

    async with pool.acquire() as conn:
        command = await conn.fetchrow(
            "SELECT state,cancellation_reason FROM middleware_commands "
            "WHERE tenant_id=$1 AND command_id=$2",
            TENANT_ID,
            str(firing.operation.command_id),
        )
        cancelled_outbox = await conn.fetchval(
            "SELECT cancelled_at IS NOT NULL FROM middleware_outbox "
            "WHERE tenant_id=$1 AND command_id=$2",
            TENANT_ID,
            str(firing.operation.command_id),
        )
    assert command is not None
    assert command["state"] == "cancelled"
    assert command["cancellation_reason"] == (
        "warning resolved before group wait elapsed"
    )
    assert cancelled_outbox is True


@pytest.mark.asyncio
async def test_status_snapshot_before_resolved_end_cannot_reopen_incident(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    firing_item = alert(fingerprint="incident-resolved-status-order-0001")
    await incidents.ingest(
        group_key=GROUP_KEY,
        alert=firing_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-resolved-status-order-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-resolved-status-order-request-0001",
    )
    resolved_payload = firing_item.model_dump(mode="json", by_alias=True)
    resolved_payload["status"] = "resolved"
    resolved_payload["endsAt"] = "2026-09-02T16:10:00Z"
    await incidents.ingest(
        group_key=GROUP_KEY,
        alert=AlertmanagerAlert.model_validate(resolved_payload),
        actor_id=ACTOR_ID,
        correlation_id="incident-resolved-status-order-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-resolved-status-order-request-0002",
    )

    with pytest.raises(IncidentConflict):
        await incidents.store.ingest_status(
            policy=policy(),
            item=AlertmanagerStatusItem.model_validate(
                {
                    "groupKey": GROUP_KEY,
                    "fingerprint": firing_item.fingerprint,
                    "startsAt": "2026-09-02T16:00:00Z",
                    "state": "firing",
                    "silencedBy": [],
                    "inhibitedBy": [],
                }
            ),
            actor_id=ACTOR_ID,
            correlation_id="incident-resolved-status-order-correlation-0003",
            source_deployment="alertmanager-disposable-ci",
            request_idempotency_key="incident-resolved-status-order-request-0003",
            observed_at=datetime(2026, 9, 2, 16, 5, tzinfo=UTC),
        )


@pytest.mark.asyncio
async def test_newer_status_reopens_ended_occurrence_for_webhook(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    firing_item = alert(fingerprint="incident-newer-status-reopen-0001")
    resolved_payload = firing_item.model_dump(mode="json", by_alias=True)
    resolved_payload["status"] = "resolved"
    resolved_payload["endsAt"] = "2026-09-02T16:10:00Z"
    resolved = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=AlertmanagerAlert.model_validate(resolved_payload),
        actor_id=ACTOR_ID,
        correlation_id="incident-newer-status-reopen-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-newer-status-reopen-request-0001",
    )

    reopened = await incidents.store.ingest_status(
        policy=policy(),
        item=AlertmanagerStatusItem.model_validate(
            {
                "groupKey": GROUP_KEY,
                "fingerprint": firing_item.fingerprint,
                "startsAt": "2026-09-02T16:00:00Z",
                "state": "firing",
                "silencedBy": [],
                "inhibitedBy": [],
            }
        ),
        actor_id=ACTOR_ID,
        correlation_id="incident-newer-status-reopen-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-newer-status-reopen-request-0002",
        observed_at=datetime(2026, 9, 2, 16, 11, tzinfo=UTC),
    )
    assert reopened.state == "firing"
    assert reopened.ends_at is None

    matching = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=firing_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-newer-status-reopen-correlation-0003",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-newer-status-reopen-request-0003",
    )
    assert matching.incident.incident_id == resolved.incident.incident_id
    assert matching.incident.state == "firing"


@pytest.mark.asyncio
async def test_newer_firing_status_clears_end_evidence_while_acknowledged(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    firing_item = alert(fingerprint="incident-acknowledged-status-reopen-0001")
    resolved_payload = firing_item.model_dump(mode="json", by_alias=True)
    resolved_payload["status"] = "resolved"
    resolved_payload["endsAt"] = "2026-09-02T16:10:00Z"
    resolved = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=AlertmanagerAlert.model_validate(resolved_payload),
        actor_id=ACTOR_ID,
        correlation_id="incident-ack-status-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-ack-status-request-0001",
    )

    silenced = await incidents.store.ingest_status(
        policy=policy(),
        item=AlertmanagerStatusItem.model_validate(
            {
                "groupKey": GROUP_KEY,
                "fingerprint": firing_item.fingerprint,
                "startsAt": "2026-09-02T16:00:00Z",
                "state": "silenced",
                "silencedBy": ["incident-ack-status-silence-1"],
                "inhibitedBy": [],
            }
        ),
        actor_id=ACTOR_ID,
        correlation_id="incident-ack-status-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-ack-status-request-0002",
        observed_at=datetime(2026, 9, 2, 16, 11, tzinfo=UTC),
    )
    assert silenced.ends_at is not None

    acknowledged = await incidents.store.mutate(
        TENANT_ID,
        resolved.incident.incident_id,
        action="acknowledge",
        actor_id="service-account-observability-operator",
        correlation_id="incident-ack-status-correlation-0003",
        idempotency_key="incident-ack-status-mutation-0001",
        expected_version=silenced.resource_version,
        reason="operator owns recurrence",
    )
    assert acknowledged.state == "acknowledged"
    assert acknowledged.ends_at is not None

    authoritative_firing = await incidents.store.ingest_status(
        policy=policy(),
        item=AlertmanagerStatusItem.model_validate(
            {
                "groupKey": GROUP_KEY,
                "fingerprint": firing_item.fingerprint,
                "startsAt": "2026-09-02T16:00:00Z",
                "state": "firing",
                "silencedBy": [],
                "inhibitedBy": [],
            }
        ),
        actor_id=ACTOR_ID,
        correlation_id="incident-ack-status-correlation-0004",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-ack-status-request-0003",
        observed_at=datetime(2026, 9, 2, 16, 12, tzinfo=UTC),
    )
    assert authoritative_firing.state == "acknowledged"
    assert authoritative_firing.ends_at is None

    matching = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=firing_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-ack-status-correlation-0005",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-ack-status-request-0004",
    )
    assert matching.incident.incident_id == resolved.incident.incident_id
    assert matching.incident.state == "acknowledged"


@pytest.mark.asyncio
async def test_operator_reopen_clears_ended_occurrence_for_webhook(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    firing_item = alert(fingerprint="incident-operator-reopen-0001")
    resolved_payload = firing_item.model_dump(mode="json", by_alias=True)
    resolved_payload["status"] = "resolved"
    resolved_payload["endsAt"] = "2026-09-02T16:10:00Z"
    resolved = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=AlertmanagerAlert.model_validate(resolved_payload),
        actor_id=ACTOR_ID,
        correlation_id="incident-operator-reopen-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-operator-reopen-request-0001",
    )

    reopened = await incidents.store.mutate(
        TENANT_ID,
        resolved.incident.incident_id,
        action="reopen",
        actor_id="service-account-observability-operator",
        correlation_id="incident-operator-reopen-correlation-0002",
        idempotency_key="incident-operator-reopen-mutation-0001",
        expected_version=resolved.incident.resource_version,
        reason="operator verified recurrence",
    )
    assert reopened.state == "firing"
    assert reopened.ends_at is None

    matching = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=firing_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-operator-reopen-correlation-0003",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-operator-reopen-request-0002",
    )
    assert matching.incident.incident_id == resolved.incident.incident_id
    assert matching.incident.state == "firing"


@pytest.mark.asyncio
async def test_recurrence_command_preserves_incident_first_seen_time(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    first_item = alert(fingerprint="incident-recurrence-0001")
    first = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=first_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-recurrence-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-recurrence-request-0001",
    )
    assert first.operation is not None

    recurrence_payload = first_item.model_dump(mode="json", by_alias=True)
    recurrence_payload["startsAt"] = "2026-09-02T17:00:00Z"
    recurrence_item = AlertmanagerAlert.model_validate(recurrence_payload)
    recurrence = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=recurrence_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-recurrence-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-recurrence-request-0002",
    )
    assert recurrence.operation is not None

    async with pool.acquire() as conn:
        payload = await conn.fetchval(
            "SELECT payload FROM middleware_commands "
            "WHERE tenant_id=$1 AND command_id=$2",
            TENANT_ID,
            str(recurrence.operation.command_id),
        )
    if isinstance(payload, str):
        import json

        payload = json.loads(payload)
    alert_payload = payload["payload"]["alert"]
    assert alert_payload["first_seen_at"] == first_item.starts_at.isoformat()
    assert alert_payload["starts_at"] == recurrence_item.starts_at.isoformat()


@pytest.mark.asyncio
async def test_status_replay_returns_its_original_projection(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    item = alert(fingerprint="incident-status-replay-0001")
    await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-status-replay-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-replay-alert-0001",
    )
    silenced_item = AlertmanagerStatusItem.model_validate(
        {
            "groupKey": GROUP_KEY,
            "fingerprint": item.fingerprint,
            "startsAt": "2026-09-02T16:00:00Z",
            "state": "silenced",
            "silencedBy": ["disposable-silence-replay-1"],
            "inhibitedBy": [],
        }
    )
    silenced = await incidents.store.ingest_status(
        policy=policy(),
        item=silenced_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-status-replay-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-replay-request-0001",
        observed_at=datetime(2026, 9, 2, 16, 1, tzinfo=UTC),
    )
    firing = await incidents.store.ingest_status(
        policy=policy(),
        item=AlertmanagerStatusItem.model_validate(
            {
                "groupKey": GROUP_KEY,
                "fingerprint": item.fingerprint,
                "startsAt": "2026-09-02T16:00:00Z",
                "state": "firing",
                "silencedBy": [],
                "inhibitedBy": [],
            }
        ),
        actor_id=ACTOR_ID,
        correlation_id="incident-status-replay-correlation-0003",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-replay-request-0002",
        observed_at=datetime(2026, 9, 2, 16, 2, tzinfo=UTC),
    )
    replay = await incidents.store.ingest_status(
        policy=policy(),
        item=silenced_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-status-replay-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-replay-request-0001",
        observed_at=datetime(2026, 9, 2, 16, 1, tzinfo=UTC),
    )
    assert silenced.state == "silenced"
    assert firing.state == "firing"
    assert replay.state == "silenced"
    assert replay.resource_version == silenced.resource_version
    assert replay.duplicate is True
    current = await incidents.store.get(TENANT_ID, firing.incident_id)
    assert current.state == "firing"
    assert current.resource_version == firing.resource_version


@pytest.mark.asyncio
async def test_status_suppression_cancels_group_wait_and_blocks_repeat(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    item = alert(fingerprint="incident-status-group-wait-0001", severity="warning")
    first = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-status-group-wait-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-group-wait-alert-0001",
    )
    assert first.operation is not None
    silenced = await incidents.store.ingest_status(
        policy=policy(),
        item=AlertmanagerStatusItem.model_validate(
            {
                "groupKey": GROUP_KEY,
                "fingerprint": item.fingerprint,
                "startsAt": "2026-09-02T16:00:00Z",
                "state": "silenced",
                "silencedBy": ["disposable-silence-group-wait-1"],
                "inhibitedBy": [],
            }
        ),
        actor_id=ACTOR_ID,
        correlation_id="incident-status-group-wait-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-group-wait-request-0001",
        observed_at=datetime(2026, 9, 2, 16, 1, tzinfo=UTC),
    )
    assert silenced.state == "silenced"
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE middleware_observability_notification_intents
               SET scheduled_at=now() - interval '14401 seconds'
               WHERE tenant_id=$1 AND incident_id=$2""",
            TENANT_ID,
            first.incident.incident_id,
        )
    delayed = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-status-group-wait-correlation-0003",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-status-group-wait-alert-0002",
    )
    assert delayed.incident.state == "silenced"
    assert delayed.operation is not None
    assert delayed.operation.command_id == first.operation.command_id
    assert delayed.operation.state == "cancelled"
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT count(*) FROM middleware_observability_notification_intents WHERE tenant_id=$1 AND incident_id=$2",
            TENANT_ID,
            first.incident.incident_id,
        ) == 1
        assert await conn.fetchval(
            "SELECT cancelled_at IS NOT NULL FROM middleware_outbox WHERE tenant_id=$1 AND command_id=$2",
            TENANT_ID,
            str(first.operation.command_id),
        ) is True


@pytest.mark.asyncio
async def test_operator_resolution_cancels_group_wait_outbox(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    item = alert(fingerprint="incident-operator-group-wait-0001", severity="warning")
    first = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=item,
        actor_id=ACTOR_ID,
        correlation_id="incident-operator-group-wait-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-operator-group-wait-alert-0001",
    )
    assert first.operation is not None
    resolved = await incidents.store.mutate(
        TENANT_ID,
        first.incident.incident_id,
        action="resolve",
        actor_id="service-account-observability-operator",
        correlation_id="incident-operator-group-wait-correlation-0002",
        idempotency_key="incident-operator-group-wait-resolve-0001",
        expected_version=first.incident.resource_version,
        reason="operator verified recovery",
    )
    assert resolved.state == "resolved"
    async with pool.acquire() as conn:
        command = await conn.fetchrow(
            "SELECT state,cancellation_reason FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
            TENANT_ID,
            str(first.operation.command_id),
        )
        outbox_cancelled = await conn.fetchval(
            "SELECT cancelled_at IS NOT NULL FROM middleware_outbox WHERE tenant_id=$1 AND command_id=$2",
            TENANT_ID,
            str(first.operation.command_id),
        )
    assert command["state"] == "cancelled"
    assert command["cancellation_reason"] == (
        "warning was resolved before group wait elapsed"
    )
    assert outbox_cancelled is True


@pytest.mark.asyncio
async def test_delayed_webhook_cannot_replace_newer_occurrence(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    first_item = alert(fingerprint="incident-delayed-occurrence-0001")
    first = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=first_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-delayed-occurrence-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-delayed-occurrence-request-0001",
    )
    newer_payload = first_item.model_dump(mode="json", by_alias=True)
    newer_payload["startsAt"] = "2026-09-02T17:00:00Z"
    newer_item = AlertmanagerAlert.model_validate(newer_payload)
    newer = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=newer_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-delayed-occurrence-correlation-0002",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-delayed-occurrence-request-0002",
    )
    with pytest.raises(IncidentConflict):
        await incidents.ingest(
            group_key=GROUP_KEY,
            alert=first_item,
            actor_id=ACTOR_ID,
            correlation_id="incident-delayed-occurrence-correlation-0003",
            source_deployment="alertmanager-disposable-ci",
            request_idempotency_key="incident-delayed-occurrence-request-0003",
        )
    current = await incidents.store.get(TENANT_ID, first.incident.incident_id)
    assert current.starts_at == newer_item.starts_at
    assert current.resource_version == newer.incident.resource_version


@pytest.mark.asyncio
async def test_delayed_firing_cannot_reopen_already_ended_occurrence(
    pool: asyncpg.Pool,
) -> None:
    _, incidents = services(pool)
    firing_item = alert(fingerprint="incident-ended-occurrence-0001")
    resolved_payload = firing_item.model_dump(mode="json", by_alias=True)
    resolved_payload["status"] = "resolved"
    resolved_payload["endsAt"] = "2026-09-02T16:10:00Z"
    resolved_item = AlertmanagerAlert.model_validate(resolved_payload)
    resolved = await incidents.ingest(
        group_key=GROUP_KEY,
        alert=resolved_item,
        actor_id=ACTOR_ID,
        correlation_id="incident-ended-occurrence-correlation-0001",
        source_deployment="alertmanager-disposable-ci",
        request_idempotency_key="incident-ended-occurrence-request-0001",
    )
    with pytest.raises(IncidentConflict):
        await incidents.ingest(
            group_key=GROUP_KEY,
            alert=firing_item,
            actor_id=ACTOR_ID,
            correlation_id="incident-ended-occurrence-correlation-0002",
            source_deployment="alertmanager-disposable-ci",
            request_idempotency_key="incident-ended-occurrence-request-0002",
        )
    current = await incidents.store.get(TENANT_ID, resolved.incident.incident_id)
    assert current.state == "resolved"
    assert current.ends_at == resolved_item.ends_at
    assert current.resource_version == resolved.incident.resource_version
