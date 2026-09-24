from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

import asyncpg
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .commands import (
    CommandConflict,
    CommandEnvelope,
    CommandNotFound,
    CommandOperation,
    CommandService,
    MemoryCommandStore,
    OperationAttempt,
    PostgresCommandStore,
)
from .observability_alert_contract import (
    ALERTMANAGER_CLIENT_ID,
    AlertPolicy,
    AlertmanagerAlert,
    build_command,
)
from .storage import canonical_payload_sha256


IncidentState = Literal["firing", "acknowledged", "resolved", "inhibited", "silenced"]
IncidentAction = Literal["acknowledge", "resolve", "reopen"]
StatusState = Literal["firing", "resolved", "inhibited", "silenced"]


class IncidentNotFound(CommandNotFound):
    code = "incident_not_found"


class IncidentConflict(CommandConflict):
    code = "incident_conflict"


class IncidentRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: uuid.UUID
    tenant_id: str
    alert_fingerprint: str
    group_key: str
    state: IncidentState
    severity: str
    service: str
    environment: str
    host: str
    labels: dict[str, str]
    annotations: dict[str, str]
    first_seen_at: datetime
    last_seen_at: datetime
    starts_at: datetime
    ends_at: datetime | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    resolved_at: datetime | None = None
    source_deployment: str
    correlation_id: str
    resource_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    duplicate: bool = False


class IncidentTimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: int
    incident_id: uuid.UUID
    event_type: str
    previous_state: IncidentState | None
    new_state: IncidentState
    actor_id: str
    correlation_id: str
    source_deployment: str
    operation_id: uuid.UUID | None = None
    safe_metadata: dict[str, Any]
    occurred_at: datetime


class NotificationAttemptView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notification_id: int
    operation_id: uuid.UUID
    notification_class: Literal["immediate", "grouped"]
    operation_state: str
    attempt_number: int | None = None
    attempt_state: str | None = None
    provider_operation_id: str | None = None
    safe_error_code: str | None = None
    reconciliation_required: bool
    scheduled_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


class IncidentMutationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    reason: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: /-]*$",
    )


class AlertmanagerStatusItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_key: str = Field(alias="groupKey", min_length=1, max_length=2_048)
    fingerprint: str = Field(min_length=1, max_length=128)
    starts_at: datetime = Field(alias="startsAt")
    state: StatusState
    silenced_by: list[str] = Field(alias="silencedBy", max_length=32)
    inhibited_by: list[str] = Field(alias="inhibitedBy", max_length=32)

    @field_validator("starts_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("startsAt must include timezone")
        return value

    @field_validator("silenced_by", "inhibited_by")
    @classmethod
    def validate_status_ids(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or any(
            not item or len(item) > 128 or not item.replace("-", "").isalnum()
            for item in value
        ):
            raise ValueError("status identifiers are invalid")
        return sorted(value)

    @model_validator(mode="after")
    def validate_evidence(self) -> "AlertmanagerStatusItem":
        if self.state == "silenced" and not self.silenced_by:
            raise ValueError("silenced state requires silencedBy evidence")
        if self.state == "inhibited" and not self.inhibited_by:
            raise ValueError("inhibited state requires inhibitedBy evidence")
        if self.state in {"firing", "resolved"} and (
            self.silenced_by or self.inhibited_by
        ):
            raise ValueError("active state cannot carry suppression evidence")
        return self


class AlertmanagerStatusSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: datetime = Field(alias="observedAt")
    source_deployment: str = Field(alias="sourceDeployment", min_length=1, max_length=128)
    items: list[AlertmanagerStatusItem] = Field(min_length=1, max_length=100)

    @field_validator("observed_at")
    @classmethod
    def require_observed_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observedAt must include timezone")
        return value


class IncidentIngestionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident: IncidentRecord
    operation: CommandOperation | None
    notification_status: Literal["queued", "scheduled", "disabled", "state_only"]
    timeline_event_id: int
    duplicate: bool


def incident_identity(tenant_id: str, fingerprint: str) -> uuid.UUID:
    return uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://operations.codestra.co/observability/incidents/{tenant_id}/{fingerprint}",
    )


def transition_identity(
    *,
    group_key: str,
    alert: AlertmanagerAlert,
) -> str:
    material = "\n".join(
        (
            "codestra-alertmanager-transition-v1",
            group_key,
            alert.fingerprint,
            alert.status,
            alert.starts_at.isoformat(),
        )
    ).encode("utf-8")
    return "alert-transition-v1:" + hashlib.sha256(material).hexdigest()


def status_identity(item: AlertmanagerStatusItem, observed_at: datetime) -> str:
    material = json.dumps(
        {
            "group_key": item.group_key,
            "fingerprint": item.fingerprint,
            "starts_at": item.starts_at.isoformat(),
            "state": item.state,
            "silenced_by": sorted(item.silenced_by),
            "inhibited_by": sorted(item.inhibited_by),
            "observed_at": observed_at.isoformat(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "alert-status-v1:" + hashlib.sha256(material).hexdigest()


def repeat_event_identity(request_key: str) -> str:
    return "alert-repeat-event-v1:" + hashlib.sha256(
        request_key.encode("utf-8")
    ).hexdigest()


def suppressed_event_identity(request_key: str) -> str:
    return "alert-suppressed-event-v1:" + hashlib.sha256(
        request_key.encode("utf-8")
    ).hexdigest()


def activation_event_identity(request_key: str) -> str:
    return "alert-activation-event-v1:" + hashlib.sha256(
        request_key.encode("utf-8")
    ).hexdigest()


def repeat_command(command: CommandEnvelope, request_key: str) -> CommandEnvelope:
    idempotency_key = "obs-alert-repeat-v1:" + hashlib.sha256(
        f"{command.idempotency_key}\n{request_key}".encode("utf-8")
    ).hexdigest()
    command_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://operations.codestra.co/observability/alert-repeats/{idempotency_key}",
    )
    value = command.model_dump(mode="python")
    value["command_id"] = command_id
    value["idempotency_key"] = idempotency_key
    value["payload"]["message_id"] = str(command_id)
    value["payload"]["alert"]["notification_repeat"] = True
    return CommandEnvelope.model_validate(value)


def request_identity(client_id: str, key: str, fingerprint: str) -> str:
    material = f"{client_id}\n{key}\n{fingerprint}".encode("utf-8")
    return "alert-request-v1:" + hashlib.sha256(material).hexdigest()


def encode_cursor(updated_at: datetime, incident_id: uuid.UUID) -> str:
    value = f"{updated_at.isoformat()}|{incident_id}".encode("utf-8")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_cursor(value: str | None) -> tuple[datetime, uuid.UUID] | None:
    if not value:
        return None
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding).decode("utf-8")
        timestamp, raw_id = decoded.split("|", 1)
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("cursor timestamp is naive")
        return parsed, uuid.UUID(raw_id)
    except (ValueError, UnicodeError) as exc:
        raise IncidentConflict("incident cursor is malformed") from exc


def notification_class(policy: AlertPolicy, severity: str) -> str:
    if severity in policy.immediate_severities:
        return "immediate"
    if severity in policy.grouped_severities:
        return "grouped"
    return "state_only"


def next_incident_state(
    previous: IncidentState | None,
    incoming: StatusState,
) -> tuple[IncidentState, str]:
    if incoming == "resolved":
        return "resolved", "resolved"
    if incoming in {"inhibited", "silenced"}:
        return incoming, incoming
    if previous == "resolved":
        return "firing", "reopened"
    if previous == "acknowledged":
        return "acknowledged", "firing"
    return "firing", "firing"


def webhook_transition_predates_projection(
    alert: AlertmanagerAlert,
    *,
    starts_at: datetime,
    ends_at: datetime | None,
) -> bool:
    """Reject transitions that cannot be newer than the current occurrence."""

    return alert.starts_at < starts_at or (
        alert.status == "firing"
        and alert.starts_at == starts_at
        and ends_at is not None
    )


class IncidentStore(Protocol):
    async def ingest(
        self,
        *,
        policy: AlertPolicy,
        group_key: str,
        alert: AlertmanagerAlert,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        request_idempotency_key: str,
        command: CommandEnvelope | None,
        authenticated_client_id: str,
        notification_kind: str,
    ) -> IncidentIngestionResult: ...

    async def ingest_status(
        self,
        *,
        policy: AlertPolicy,
        item: AlertmanagerStatusItem,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        request_idempotency_key: str,
        observed_at: datetime,
    ) -> IncidentRecord: ...

    async def get(self, tenant_id: str, incident_id: uuid.UUID) -> IncidentRecord: ...

    async def list_incidents(
        self,
        tenant_id: str,
        *,
        limit: int,
        position: tuple[datetime, uuid.UUID] | None,
        state: str | None,
        severity: str | None,
        service: str | None,
    ) -> list[IncidentRecord]: ...

    async def list_timeline(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        limit: int,
        after_event_id: int | None,
    ) -> list[IncidentTimelineEvent]: ...

    async def mutate(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        action: IncidentAction,
        actor_id: str,
        correlation_id: str,
        idempotency_key: str,
        expected_version: int,
        reason: str,
    ) -> IncidentRecord: ...

    async def list_notification_attempts(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        limit: int,
    ) -> list[NotificationAttemptView]: ...

    async def ready(self) -> bool: ...

    async def close(self) -> None: ...


class MemoryIncidentStore:
    def __init__(self, commands: CommandService) -> None:
        if not isinstance(commands.store, MemoryCommandStore):
            raise TypeError("memory incident store requires MemoryCommandStore")
        self.commands = commands
        self._incidents: dict[tuple[str, uuid.UUID], IncidentRecord] = {}
        self._events: dict[tuple[str, uuid.UUID], list[IncidentTimelineEvent]] = {}
        self._event_replays: dict[str, tuple[str, IncidentIngestionResult | IncidentRecord]] = {}
        self._notifications: dict[tuple[str, uuid.UUID], list[tuple[int, uuid.UUID, str, datetime]]] = {}
        self._mutations: dict[tuple[str, uuid.UUID, str, str, str], tuple[str, IncidentRecord]] = {}
        self._status_observed: dict[tuple[str, uuid.UUID], datetime] = {}
        self._lock = asyncio.Lock()
        self._event_sequence = 0
        self._notification_sequence = 0

    def _append_event(
        self,
        *,
        incident: IncidentRecord,
        event_type: str,
        previous: IncidentState | None,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        operation_id: uuid.UUID | None,
        metadata: dict[str, Any],
        occurred_at: datetime,
    ) -> IncidentTimelineEvent:
        self._event_sequence += 1
        event = IncidentTimelineEvent(
            event_id=self._event_sequence,
            incident_id=incident.incident_id,
            event_type=event_type,
            previous_state=previous,
            new_state=incident.state,
            actor_id=actor_id,
            correlation_id=correlation_id,
            source_deployment=source_deployment,
            operation_id=operation_id,
            safe_metadata=metadata,
            occurred_at=occurred_at,
        )
        self._events.setdefault((incident.tenant_id, incident.incident_id), []).append(event)
        return event

    async def _cancel_pending_grouped_notifications(
        self,
        *,
        tenant_id: str,
        incident_id: uuid.UUID,
        actor_id: str,
        now: datetime,
        reason: str,
    ) -> None:
        for _, operation_id, kind, scheduled_at in self._notifications.get(
            (tenant_id, incident_id), []
        ):
            if kind != "grouped" or scheduled_at <= now:
                continue
            pending = await self.commands.store.get(tenant_id, operation_id)
            if pending.state not in {"persisted", "queued"}:
                continue
            await self.commands.store.mutate_operation(
                tenant_id,
                operation_id,
                action="cancel",
                actor_id=actor_id,
                idempotency_key=(
                    "incident-group-wait-cancel-v1:"
                    f"{incident_id}:{operation_id}"
                ),
                expected_version=pending.resource_version,
                reason=reason,
            )

    async def ingest(
        self,
        *,
        policy: AlertPolicy,
        group_key: str,
        alert: AlertmanagerAlert,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        request_idempotency_key: str,
        command: CommandEnvelope | None,
        authenticated_client_id: str,
        notification_kind: str,
    ) -> IncidentIngestionResult:
        previous: IncidentRecord | None
        operation: CommandOperation | None
        event_key = transition_identity(group_key=group_key, alert=alert)
        request_key = request_identity(
            authenticated_client_id, request_idempotency_key, alert.fingerprint
        )
        payload_digest = canonical_payload_sha256(
            {"group_key": group_key, "alert": alert.model_dump(mode="json")}
        )
        async with self._lock:
            incident_id = incident_identity(policy.tenant_id, alert.fingerprint)
            key = (policy.tenant_id, incident_id)
            current_projection = self._incidents.get(key)
            if (
                current_projection is not None
                and webhook_transition_predates_projection(
                    alert,
                    starts_at=current_projection.starts_at,
                    ends_at=current_projection.ends_at,
                )
            ):
                raise IncidentConflict(
                    "alert transition predates the current alert occurrence"
                )
            transition_replay = self._event_replays.get(
                f"{policy.tenant_id}:{event_key}"
            )
            request_replay = self._event_replays.get(
                f"{policy.tenant_id}:{request_key}"
            )
            if request_replay is not None:
                if request_replay[0] != payload_digest or not isinstance(
                    request_replay[1], IncidentIngestionResult
                ):
                    raise IncidentConflict("alert transition identity was reused with different content")
                value = request_replay[1]
                return value.model_copy(
                    update={
                        "duplicate": True,
                        "incident": value.incident.model_copy(update={"duplicate": True}),
                        "operation": (
                            value.operation.model_copy(update={"duplicate": True})
                            if value.operation is not None
                            else None
                        ),
                    }
                )
            if transition_replay is not None:
                if transition_replay[0] != payload_digest or not isinstance(
                    transition_replay[1], IncidentIngestionResult
                ):
                    raise IncidentConflict(
                        "alert transition identity was reused with different content"
                    )
                now = datetime.now(UTC)
                notifications = self._notifications.get(key, [])
                if (
                    alert.status == "firing"
                    and command is not None
                    and not notifications
                    and current_projection is not None
                    and current_projection.state == "firing"
                ):
                    previous = self._incidents[key]
                    command = build_command(
                        policy=policy,
                        alert=alert,
                        group_key=group_key,
                        receiver=policy.receiver,
                        actor=actor_id,
                        correlation_id=correlation_id,
                        incident_id=incident_id,
                        first_seen_at=previous.first_seen_at,
                    )
                    operation = await self.commands.store.submit(
                        command,
                        authenticated_client_id=authenticated_client_id,
                    )
                    state, _ = next_incident_state(previous.state, alert.status)
                    incident = previous.model_copy(
                        update={
                            "state": state,
                            "last_seen_at": now,
                            "source_deployment": source_deployment,
                            "correlation_id": correlation_id,
                            "resource_version": previous.resource_version + 1,
                            "updated_at": now,
                            "duplicate": False,
                        }
                    )
                    self._incidents[key] = incident
                    timeline = self._append_event(
                        incident=incident,
                        event_type="firing",
                        previous=previous.state,
                        actor_id=actor_id,
                        correlation_id=correlation_id,
                        source_deployment=source_deployment,
                        operation_id=operation.command_id,
                        metadata={
                            "event_key": activation_event_identity(request_key),
                            "payload_sha256": payload_digest,
                            "activated_transition": event_key,
                        },
                        occurred_at=now,
                    )
                    scheduled_at = now + timedelta(
                        seconds=(
                            policy.warning_group_wait_seconds
                            if notification_kind == "grouped"
                            else 0
                        )
                    )
                    self._notification_sequence += 1
                    self._notifications.setdefault(key, []).append(
                        (
                            self._notification_sequence,
                            operation.command_id,
                            notification_kind,
                            scheduled_at,
                        )
                    )
                    result = IncidentIngestionResult(
                        incident=incident,
                        operation=operation,
                        notification_status=(
                            "scheduled"
                            if notification_kind == "grouped"
                            else "queued"
                        ),
                        timeline_event_id=timeline.event_id,
                        duplicate=False,
                    )
                    entry = (payload_digest, result)
                    self._event_replays[f"{policy.tenant_id}:{event_key}"] = entry
                    self._event_replays[
                        f"{policy.tenant_id}:{activation_event_identity(request_key)}"
                    ] = entry
                    self._event_replays[f"{policy.tenant_id}:{request_key}"] = entry
                    return result
                repeat_eligible = (
                    alert.status == "firing"
                    and notification_kind == "grouped"
                    and command is not None
                    and notifications
                    and current_projection is not None
                    and current_projection.state == "firing"
                    and now
                    >= max(item[3] for item in notifications)
                    + timedelta(seconds=policy.warning_repeat_interval_seconds)
                )
                if repeat_eligible:
                    previous = self._incidents[key]
                    command = build_command(
                        policy=policy,
                        alert=alert,
                        group_key=group_key,
                        receiver=policy.receiver,
                        actor=actor_id,
                        correlation_id=correlation_id,
                        incident_id=incident_id,
                        first_seen_at=previous.first_seen_at,
                    )
                    repeated_command = repeat_command(command, request_key)
                    operation = await self.commands.store.submit(
                        repeated_command,
                        authenticated_client_id=authenticated_client_id,
                    )
                    state, _ = next_incident_state(previous.state, alert.status)
                    incident = previous.model_copy(
                        update={
                            "state": state,
                            "last_seen_at": now,
                            "source_deployment": source_deployment,
                            "correlation_id": correlation_id,
                            "resource_version": previous.resource_version + 1,
                            "updated_at": now,
                            "duplicate": False,
                        }
                    )
                    self._incidents[key] = incident
                    timeline = self._append_event(
                        incident=incident,
                        event_type="notification_repeat",
                        previous=previous.state,
                        actor_id=actor_id,
                        correlation_id=correlation_id,
                        source_deployment=source_deployment,
                        operation_id=operation.command_id,
                        metadata={
                            "event_key": repeat_event_identity(request_key),
                            "payload_sha256": payload_digest,
                            "repeat_of_transition": event_key,
                        },
                        occurred_at=now,
                    )
                    self._notification_sequence += 1
                    self._notifications.setdefault(key, []).append(
                        (
                            self._notification_sequence,
                            operation.command_id,
                            notification_kind,
                            now,
                        )
                    )
                    result = IncidentIngestionResult(
                        incident=incident,
                        operation=operation,
                        notification_status="queued",
                        timeline_event_id=timeline.event_id,
                        duplicate=False,
                    )
                    entry = (payload_digest, result)
                    self._event_replays[f"{policy.tenant_id}:{event_key}"] = entry
                    self._event_replays[
                        f"{policy.tenant_id}:{repeat_event_identity(request_key)}"
                    ] = entry
                    self._event_replays[f"{policy.tenant_id}:{request_key}"] = entry
                    return result

                value = transition_replay[1]
                current_incident = self._incidents[key]
                replay_result = value.model_copy(
                    update={
                        "duplicate": True,
                        "incident": current_incident.model_copy(
                            update={"duplicate": True}
                        ),
                        "operation": (
                            value.operation.model_copy(update={"duplicate": True})
                            if value.operation is not None
                            else None
                        ),
                    }
                )
                if not (
                    alert.status == "firing"
                    and notification_kind == "grouped"
                    and command is not None
                    and notifications
                ):
                    return replay_result
                timeline = self._append_event(
                    incident=replay_result.incident,
                    event_type="notification_suppressed",
                    previous=replay_result.incident.state,
                    actor_id=actor_id,
                    correlation_id=correlation_id,
                    source_deployment=source_deployment,
                    operation_id=(
                        replay_result.operation.command_id
                        if replay_result.operation is not None
                        else None
                    ),
                    metadata={
                        "event_key": suppressed_event_identity(request_key),
                        "payload_sha256": payload_digest,
                        "suppressed_transition": event_key,
                        "reason": "repeat_interval_not_elapsed",
                    },
                    occurred_at=now,
                )
                replay_result = replay_result.model_copy(
                    update={"timeline_event_id": timeline.event_id}
                )
                self._event_replays[f"{policy.tenant_id}:{request_key}"] = (
                    payload_digest,
                    replay_result,
                )
                return replay_result

            now = datetime.now(UTC)
            previous = self._incidents.get(key)
            state, event_type = next_incident_state(
                previous.state if previous else None,
                alert.status,
            )
            if (
                alert.status == "resolved"
                and notification_kind == "grouped"
                and previous is not None
            ):
                await self._cancel_pending_grouped_notifications(
                    tenant_id=policy.tenant_id,
                    incident_id=incident_id,
                    actor_id=actor_id,
                    now=now,
                    reason="warning resolved before group wait elapsed",
                )
            operation = None
            if command is not None:
                command = build_command(
                    policy=policy,
                    alert=alert,
                    group_key=group_key,
                    receiver=policy.receiver,
                    actor=actor_id,
                    correlation_id=correlation_id,
                    incident_id=incident_id,
                    first_seen_at=(
                        previous.first_seen_at if previous else alert.starts_at
                    ),
                )
                operation = await self.commands.store.submit(
                    command,
                    authenticated_client_id=authenticated_client_id,
                )
            incident = IncidentRecord(
                incident_id=incident_id,
                tenant_id=policy.tenant_id,
                alert_fingerprint=alert.fingerprint,
                group_key=group_key,
                state=state,
                severity=alert.labels["severity"],
                service=alert.labels["service"],
                environment=alert.labels["environment"],
                host=alert.labels["host"],
                labels=alert.labels,
                annotations=alert.annotations,
                first_seen_at=previous.first_seen_at if previous else alert.starts_at,
                last_seen_at=now,
                starts_at=alert.starts_at,
                ends_at=alert.ends_at if alert.status == "resolved" else None,
                acknowledged_at=(
                    previous.acknowledged_at if previous and state == "acknowledged" else None
                ),
                acknowledged_by=(
                    previous.acknowledged_by if previous and state == "acknowledged" else None
                ),
                resolved_at=now if state == "resolved" else None,
                source_deployment=source_deployment,
                correlation_id=correlation_id,
                resource_version=(previous.resource_version + 1 if previous else 1),
                created_at=previous.created_at if previous else now,
                updated_at=now,
            )
            self._incidents[key] = incident
            timeline = self._append_event(
                incident=incident,
                event_type=event_type,
                previous=previous.state if previous else None,
                actor_id=actor_id,
                correlation_id=correlation_id,
                source_deployment=source_deployment,
                operation_id=operation.command_id if operation else None,
                metadata={"event_key": event_key, "payload_sha256": payload_digest},
                occurred_at=now,
            )
            if operation is not None:
                self._notification_sequence += 1
                scheduled = now
                if notification_kind == "grouped":
                    scheduled += timedelta(seconds=policy.warning_group_wait_seconds)
                self._notifications.setdefault(key, []).append(
                    (
                        self._notification_sequence,
                        operation.command_id,
                        notification_kind,
                        scheduled,
                    )
                )
            result = IncidentIngestionResult(
                incident=incident,
                operation=operation,
                notification_status=(
                    "scheduled"
                    if notification_kind == "grouped" and operation is not None
                    else "queued"
                    if operation is not None
                    else "state_only"
                    if notification_kind == "state_only"
                    else "disabled"
                ),
                timeline_event_id=timeline.event_id,
                duplicate=False,
            )
            self._event_replays[f"{policy.tenant_id}:{event_key}"] = (
                payload_digest,
                result,
            )
            self._event_replays[f"{policy.tenant_id}:{request_key}"] = (
                payload_digest,
                result,
            )
            return result

    async def ingest_status(
        self,
        *,
        policy: AlertPolicy,
        item: AlertmanagerStatusItem,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        request_idempotency_key: str,
        observed_at: datetime,
    ) -> IncidentRecord:
        event_key = status_identity(item, observed_at)
        request_key = request_identity(
            ALERTMANAGER_CLIENT_ID,
            request_idempotency_key,
            item.fingerprint,
        )
        digest = canonical_payload_sha256(
            {
                "item": item.model_dump(mode="json"),
                "observed_at": observed_at.isoformat(),
            }
        )
        async with self._lock:
            replay = self._event_replays.get(f"{policy.tenant_id}:{event_key}")
            request_replay = self._event_replays.get(
                f"{policy.tenant_id}:{request_key}"
            )
            if replay is not None and request_replay is not None and replay != request_replay:
                raise IncidentConflict("request and status identities disagree")
            replay = replay or request_replay
            if replay is not None:
                if replay[0] != digest or not isinstance(replay[1], IncidentRecord):
                    raise IncidentConflict("status identity was reused with different content")
                return replay[1].model_copy(update={"duplicate": True})
            incident_id = incident_identity(policy.tenant_id, item.fingerprint)
            key = (policy.tenant_id, incident_id)
            previous = self._incidents.get(key)
            if previous is None or previous.group_key != item.group_key:
                raise IncidentNotFound("status reconciliation incident was not found")
            if previous.starts_at != item.starts_at:
                raise IncidentConflict(
                    "status evidence does not match the current alert occurrence"
                )
            evidence_times = [
                value
                for value in (
                    self._status_observed.get(key),
                    previous.ends_at if previous.state == "resolved" else None,
                )
                if value is not None
            ]
            if evidence_times and observed_at <= max(evidence_times):
                raise IncidentConflict("status observation is not newer than current evidence")
            state, event_type = next_incident_state(previous.state, item.state)
            now = datetime.now(UTC)
            if item.state in {"resolved", "silenced", "inhibited"}:
                await self._cancel_pending_grouped_notifications(
                    tenant_id=policy.tenant_id,
                    incident_id=incident_id,
                    actor_id=actor_id,
                    now=now,
                    reason="warning left firing state before group wait elapsed",
                )
            incident = previous.model_copy(
                update={
                    "state": state,
                    # A newer authoritative firing snapshot reopens this exact
                    # occurrence. Clear its prior terminal evidence so the
                    # matching webhook can subsequently create the governed
                    # notification command without looking like a delayed
                    # pre-resolution replay.
                    "ends_at": None if item.state == "firing" else previous.ends_at,
                    "last_seen_at": now,
                    "source_deployment": source_deployment,
                    "correlation_id": correlation_id,
                    "resource_version": previous.resource_version + 1,
                    "resolved_at": now if state == "resolved" else None,
                    "updated_at": now,
                    "duplicate": False,
                }
            )
            self._incidents[key] = incident
            self._append_event(
                incident=incident,
                event_type=event_type,
                previous=previous.state,
                actor_id=actor_id,
                correlation_id=correlation_id,
                source_deployment=source_deployment,
                operation_id=None,
                metadata={
                    "event_key": event_key,
                    "silenced_by": sorted(item.silenced_by),
                    "inhibited_by": sorted(item.inhibited_by),
                    "status_source": "alertmanager-status",
                },
                occurred_at=observed_at,
            )
            self._event_replays[f"{policy.tenant_id}:{event_key}"] = (digest, incident)
            self._event_replays[f"{policy.tenant_id}:{request_key}"] = (digest, incident)
            self._status_observed[key] = observed_at
            return incident

    async def get(self, tenant_id: str, incident_id: uuid.UUID) -> IncidentRecord:
        value = self._incidents.get((tenant_id, incident_id))
        if value is None:
            raise IncidentNotFound("incident was not found")
        return value

    async def list_incidents(
        self,
        tenant_id: str,
        *,
        limit: int,
        position: tuple[datetime, uuid.UUID] | None,
        state: str | None,
        severity: str | None,
        service: str | None,
    ) -> list[IncidentRecord]:
        rows = [row for (row_tenant, _), row in self._incidents.items() if row_tenant == tenant_id]
        if state:
            rows = [row for row in rows if row.state == state]
        if severity:
            rows = [row for row in rows if row.severity == severity]
        if service:
            rows = [row for row in rows if row.service == service]
        rows.sort(key=lambda row: (row.updated_at, row.incident_id.int), reverse=True)
        if position:
            rows = [
                row
                for row in rows
                if (row.updated_at, row.incident_id.int)
                < (position[0], position[1].int)
            ]
        return rows[:limit]

    async def list_timeline(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        limit: int,
        after_event_id: int | None,
    ) -> list[IncidentTimelineEvent]:
        await self.get(tenant_id, incident_id)
        rows = self._events.get((tenant_id, incident_id), [])
        if after_event_id is not None:
            rows = [row for row in rows if row.event_id > after_event_id]
        return rows[:limit]

    async def mutate(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        action: IncidentAction,
        actor_id: str,
        correlation_id: str,
        idempotency_key: str,
        expected_version: int,
        reason: str,
    ) -> IncidentRecord:
        digest = canonical_payload_sha256(
            {"expected_version": expected_version, "reason": reason}
        )
        mutation_key = (tenant_id, incident_id, action, actor_id, idempotency_key)
        async with self._lock:
            replay = self._mutations.get(mutation_key)
            if replay:
                if replay[0] != digest:
                    raise IncidentConflict("idempotency key was reused with different content")
                return replay[1].model_copy(update={"duplicate": True})
            previous = await self.get(tenant_id, incident_id)
            if previous.resource_version != expected_version:
                raise IncidentConflict("expected_version is stale")
            allowed = {
                "acknowledge": {"firing", "inhibited", "silenced"},
                "resolve": {"firing", "acknowledged", "inhibited", "silenced"},
                "reopen": {"resolved"},
            }
            if previous.state not in allowed[action]:
                raise IncidentConflict(f"incident cannot transition via {action}")
            now = datetime.now(UTC)
            target_states: dict[IncidentAction, IncidentState] = {
                "acknowledge": "acknowledged", "resolve": "resolved", "reopen": "firing",
            }
            state = target_states[action]
            if action == "resolve":
                await self._cancel_pending_grouped_notifications(
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    actor_id=actor_id,
                    now=now,
                    reason="warning was resolved before group wait elapsed",
                )
            incident = previous.model_copy(
                update={
                    "state": state,
                    "acknowledged_at": now if action == "acknowledge" else None,
                    "acknowledged_by": actor_id if action == "acknowledge" else None,
                    "resolved_at": now if action == "resolve" else None,
                    "ends_at": None if action == "reopen" else previous.ends_at,
                    "correlation_id": correlation_id,
                    "resource_version": previous.resource_version + 1,
                    "updated_at": now,
                    "duplicate": False,
                }
            )
            self._incidents[(tenant_id, incident_id)] = incident
            self._append_event(
                incident=incident,
                event_type=action,
                previous=previous.state,
                actor_id=actor_id,
                correlation_id=correlation_id,
                source_deployment=previous.source_deployment,
                operation_id=None,
                metadata={"reason": reason, "idempotency_key": idempotency_key},
                occurred_at=now,
            )
            self._mutations[mutation_key] = (digest, incident)
            return incident

    async def list_notification_attempts(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        limit: int,
    ) -> list[NotificationAttemptView]:
        await self.get(tenant_id, incident_id)
        result: list[NotificationAttemptView] = []
        notifications = self._notifications.get((tenant_id, incident_id), [])
        for notification_id, operation_id, kind, scheduled_at in reversed(
            notifications
        ):
            operation = await self.commands.get(tenant_id, operation_id)
            attempts = await self.commands.list_attempts(
                tenant_id, operation_id, limit=limit
            )
            if not attempts:
                result.append(
                    NotificationAttemptView(
                        notification_id=notification_id,
                        operation_id=operation_id,
                        notification_class=_delivered_notification_class(kind),
                        operation_state=operation.state,
                        reconciliation_required=operation.state
                        == "reconciliation_required",
                        scheduled_at=scheduled_at,
                    )
                )
            for attempt in reversed(attempts):
                result.append(
                    _attempt_view(notification_id, kind, scheduled_at, operation, attempt)
                )
        return result[:limit]

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


def _delivered_notification_class(kind: str) -> Literal["immediate", "grouped"]:
    if kind == "immediate":
        return "immediate"
    if kind == "grouped":
        return "grouped"
    raise IncidentConflict("notification attempt has an invalid delivery class")


def _attempt_view(
    notification_id: int,
    kind: str,
    scheduled_at: datetime,
    operation: CommandOperation,
    attempt: OperationAttempt,
) -> NotificationAttemptView:
    return NotificationAttemptView(
        notification_id=notification_id,
        operation_id=operation.command_id,
        notification_class=_delivered_notification_class(kind),
        operation_state=operation.state,
        attempt_number=attempt.attempt_number,
        attempt_state=attempt.state,
        provider_operation_id=attempt.provider_operation_id,
        safe_error_code=attempt.safe_error_code,
        reconciliation_required=operation.state == "reconciliation_required",
        scheduled_at=scheduled_at,
        started_at=attempt.started_at,
        finished_at=attempt.finished_at,
    )


class PostgresIncidentStore:
    REQUIRED_TABLES = {
        "middleware_observability_incidents",
        "middleware_observability_incident_events",
        "middleware_observability_incident_audit",
        "middleware_observability_notification_intents",
        "middleware_observability_incident_mutations",
    }
    REQUIRED_TRIGGERS = {
        "middleware_observability_incident_events_immutable",
        "middleware_observability_incident_audit_immutable",
        "middleware_observability_incident_mutations_immutable",
    }
    REQUIRED_COLUMNS = {
        "middleware_observability_incidents": {
            "tenant_id",
            "incident_id",
            "alert_fingerprint",
            "group_key",
            "state",
            "severity",
            "service",
            "environment",
            "host",
            "labels",
            "annotations",
            "first_seen_at",
            "last_seen_at",
            "starts_at",
            "ends_at",
            "acknowledged_at",
            "acknowledged_by",
            "resolved_at",
            "source_deployment",
            "correlation_id",
            "resource_version",
            "created_at",
            "updated_at",
        },
        "middleware_observability_incident_events": {
            "id",
            "tenant_id",
            "incident_id",
            "event_key",
            "request_idempotency_key",
            "event_type",
            "previous_state",
            "new_state",
            "actor_id",
            "correlation_id",
            "source_deployment",
            "operation_id",
            "payload_sha256",
            "safe_metadata",
            "occurred_at",
            "created_at",
        },
        "middleware_observability_incident_audit": {
            "id",
            "tenant_id",
            "incident_id",
            "event_id",
            "action",
            "actor_id",
            "previous_state",
            "new_state",
            "correlation_id",
            "safe_metadata",
            "created_at",
        },
        "middleware_observability_notification_intents": {
            "id",
            "tenant_id",
            "incident_id",
            "operation_id",
            "notification_class",
            "idempotency_key",
            "scheduled_at",
            "created_at",
        },
        "middleware_observability_incident_mutations": {
            "id",
            "tenant_id",
            "incident_id",
            "action",
            "actor_id",
            "idempotency_key",
            "request_sha256",
            "response_payload",
            "created_at",
        },
    }
    REQUIRED_KEYS = {
        (
            "middleware_observability_incidents",
            "PRIMARY KEY",
            ("tenant_id", "incident_id"),
        ),
        (
            "middleware_observability_incidents",
            "UNIQUE",
            ("tenant_id", "alert_fingerprint"),
        ),
        (
            "middleware_observability_incident_events",
            "UNIQUE",
            ("tenant_id", "event_key"),
        ),
        (
            "middleware_observability_incident_events",
            "UNIQUE",
            ("tenant_id", "request_idempotency_key"),
        ),
        (
            "middleware_observability_notification_intents",
            "UNIQUE",
            ("tenant_id", "idempotency_key"),
        ),
        (
            "middleware_observability_notification_intents",
            "UNIQUE",
            ("tenant_id", "operation_id"),
        ),
        (
            "middleware_observability_incident_mutations",
            "UNIQUE",
            (
                "tenant_id",
                "incident_id",
                "action",
                "actor_id",
                "idempotency_key",
            ),
        ),
    }
    REQUIRED_FOREIGN_KEYS = {
        (
            "middleware_observability_incident_events",
            ("tenant_id", "incident_id"),
            "middleware_observability_incidents",
            ("tenant_id", "incident_id"),
        ),
        (
            "middleware_observability_incident_events",
            ("tenant_id", "operation_id"),
            "middleware_commands",
            ("tenant_id", "command_id"),
        ),
        (
            "middleware_observability_incident_audit",
            ("tenant_id", "incident_id"),
            "middleware_observability_incidents",
            ("tenant_id", "incident_id"),
        ),
        (
            "middleware_observability_notification_intents",
            ("tenant_id", "incident_id"),
            "middleware_observability_incidents",
            ("tenant_id", "incident_id"),
        ),
        (
            "middleware_observability_notification_intents",
            ("tenant_id", "operation_id"),
            "middleware_commands",
            ("tenant_id", "command_id"),
        ),
        (
            "middleware_observability_incident_mutations",
            ("tenant_id", "incident_id"),
            "middleware_observability_incidents",
            ("tenant_id", "incident_id"),
        ),
    }

    def __init__(self, commands: CommandService) -> None:
        if not isinstance(commands.store, PostgresCommandStore):
            raise TypeError("PostgreSQL incident store requires PostgresCommandStore")
        self.commands = commands
        self.command_store = commands.store
        self.pool = commands.store.pool

    @staticmethod
    def _json(value: object) -> dict[str, Any]:
        if isinstance(value, str):
            value = json.loads(value)
        return dict(value) if isinstance(value, dict) else {}

    @classmethod
    def _incident(cls, row: asyncpg.Record, *, duplicate: bool = False) -> IncidentRecord:
        return IncidentRecord(
            incident_id=row["incident_id"],
            tenant_id=row["tenant_id"],
            alert_fingerprint=row["alert_fingerprint"],
            group_key=row["group_key"],
            state=row["state"],
            severity=row["severity"],
            service=row["service"],
            environment=row["environment"],
            host=row["host"],
            labels=cls._json(row["labels"]),
            annotations=cls._json(row["annotations"]),
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            starts_at=row["starts_at"],
            ends_at=row["ends_at"],
            acknowledged_at=row["acknowledged_at"],
            acknowledged_by=row["acknowledged_by"],
            resolved_at=row["resolved_at"],
            source_deployment=row["source_deployment"],
            correlation_id=row["correlation_id"],
            resource_version=row["resource_version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            duplicate=duplicate,
        )

    async def _operation_on_connection(
        self,
        conn: asyncpg.Connection,
        tenant_id: str,
        operation_id: uuid.UUID | str | None,
    ) -> CommandOperation | None:
        if operation_id is None:
            return None
        row = await conn.fetchrow(
            "SELECT * FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
            tenant_id,
            str(operation_id),
        )
        if row is None:
            raise IncidentConflict("notification operation is missing")
        return self.command_store._operation(row)

    async def _replay_result(
        self,
        conn: asyncpg.Connection,
        *,
        tenant_id: str,
        incident_id: uuid.UUID,
        operation_id: uuid.UUID | str | None,
        notification_class: str | None,
        notification_is_repeat: bool,
        timeline_event_id: int,
        notification_kind: str,
    ) -> IncidentIngestionResult:
        row = await conn.fetchrow(
            """SELECT * FROM middleware_observability_incidents
               WHERE tenant_id=$1 AND incident_id=$2""",
            tenant_id,
            incident_id,
        )
        if row is None:
            raise IncidentConflict("incident replay projection is missing")
        operation = await self._operation_on_connection(
            conn,
            tenant_id,
            operation_id,
        )
        return IncidentIngestionResult(
            incident=self._incident(row, duplicate=True),
            operation=(
                operation.model_copy(update={"duplicate": True})
                if operation is not None
                else None
            ),
            notification_status=(
                "scheduled"
                if notification_class == "grouped"
                and operation is not None
                and not notification_is_repeat
                else "queued"
                if operation is not None
                else "state_only"
                if notification_kind == "state_only"
                else "disabled"
            ),
            timeline_event_id=timeline_event_id,
            duplicate=True,
        )

    async def _cancel_pending_grouped_notifications(
        self,
        conn: asyncpg.Connection,
        *,
        tenant_id: str,
        incident_id: uuid.UUID,
        actor_id: str,
        now: datetime,
        reason: str,
    ) -> None:
        pending = await conn.fetch(
            """
            SELECT ni.operation_id,c.state AS previous_state,
                   c.resource_version,o.id AS outbox_id
            FROM middleware_observability_notification_intents ni
            JOIN middleware_commands c ON c.tenant_id=ni.tenant_id
              AND c.command_id=ni.operation_id
            JOIN middleware_outbox o ON o.tenant_id=ni.tenant_id
              AND o.command_id=ni.operation_id
            WHERE ni.tenant_id=$1 AND ni.incident_id=$2
              AND ni.notification_class='grouped' AND ni.scheduled_at>$3
              AND c.state IN ('persisted','queued')
              AND o.next_attempt_at>$3 AND o.completed_at IS NULL
              AND o.dead_lettered_at IS NULL
              AND o.reconciliation_required_at IS NULL
              AND o.cancelled_at IS NULL
              AND (o.lease_owner IS NULL OR o.lease_until<=$3)
            ORDER BY ni.id,o.id
            FOR UPDATE OF c,o
            """,
            tenant_id,
            incident_id,
            now,
        )
        updated_commands: set[str] = set()
        for row in pending:
            operation_id = row["operation_id"]
            if operation_id not in updated_commands:
                updated = await conn.fetchrow(
                    """
                    UPDATE middleware_commands SET state='cancelled',
                      resource_version=resource_version+1,cancelled_at=$3,
                      cancellation_reason=$4,updated_at=$3
                    WHERE tenant_id=$1 AND command_id=$2
                      AND state IN ('persisted','queued')
                    RETURNING resource_version
                    """,
                    tenant_id,
                    operation_id,
                    now,
                    reason,
                )
                if updated is not None:
                    await conn.execute(
                        """
                        INSERT INTO middleware_command_audit (
                          tenant_id,command_id,previous_state,new_state,
                          actor_id,reason,metadata
                        ) VALUES ($1,$2,$3,'cancelled',$4,$5,$6::jsonb)
                        """,
                        tenant_id,
                        operation_id,
                        row["previous_state"],
                        actor_id,
                        reason,
                        json.dumps(
                            {
                                "action": "incident_group_wait_cancel",
                                "incident_id": str(incident_id),
                                "resource_version": updated["resource_version"],
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                    )
                    updated_commands.add(operation_id)
            await conn.execute(
                """
                UPDATE middleware_outbox SET cancelled_at=$2,
                  lease_owner=NULL,lease_until=NULL
                WHERE id=$1 AND completed_at IS NULL
                  AND dead_lettered_at IS NULL
                  AND reconciliation_required_at IS NULL
                  AND cancelled_at IS NULL
                """,
                row["outbox_id"],
                now,
            )

    async def ingest(
        self,
        *,
        policy: AlertPolicy,
        group_key: str,
        alert: AlertmanagerAlert,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        request_idempotency_key: str,
        command: CommandEnvelope | None,
        authenticated_client_id: str,
        notification_kind: str,
    ) -> IncidentIngestionResult:
        operation: CommandOperation | None
        event_key = transition_identity(group_key=group_key, alert=alert)
        request_key = request_identity(
            authenticated_client_id, request_idempotency_key, alert.fingerprint
        )
        payload_digest = canonical_payload_sha256(
            {"group_key": group_key, "alert": alert.model_dump(mode="json")}
        )
        incident_id = incident_identity(policy.tenant_id, alert.fingerprint)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    f"{policy.tenant_id}:{alert.fingerprint}",
                )
                current_projection = await conn.fetchrow(
                    """SELECT * FROM middleware_observability_incidents
                       WHERE tenant_id=$1 AND incident_id=$2 FOR UPDATE""",
                    policy.tenant_id,
                    incident_id,
                )
                if (
                    current_projection is not None
                    and webhook_transition_predates_projection(
                        alert,
                        starts_at=current_projection["starts_at"],
                        ends_at=current_projection["ends_at"],
                    )
                ):
                    raise IncidentConflict(
                        "alert transition predates the current alert occurrence"
                    )
                replays = await conn.fetch(
                    """
                    SELECT e.incident_id,e.operation_id,e.payload_sha256,e.id,
                           e.event_type,ni.notification_class,
                           EXISTS (
                             SELECT 1
                             FROM middleware_observability_incident_events ne
                             WHERE ne.tenant_id=e.tenant_id
                               AND ne.operation_id=e.operation_id
                               AND ne.event_type='notification_repeat'
                           ) AS notification_is_repeat,
                           e.event_key=$2 AS transition_match,
                           e.request_idempotency_key=$3 AS request_match
                    FROM middleware_observability_incident_events e
                    LEFT JOIN middleware_observability_notification_intents ni
                      ON ni.tenant_id=e.tenant_id AND ni.operation_id=e.operation_id
                    WHERE e.tenant_id=$1
                      AND (e.event_key=$2 OR e.request_idempotency_key=$3)
                    ORDER BY e.id
                    """,
                    policy.tenant_id,
                    event_key,
                    request_key,
                )
                request_matches = [row for row in replays if row["request_match"]]
                transition_matches = [
                    row for row in replays if row["transition_match"]
                ]
                if request_matches:
                    if len(request_matches) != 1 or any(
                        row["payload_sha256"] != payload_digest for row in replays
                    ):
                        raise IncidentConflict(
                            "request identity disagrees with the alert transition"
                        )
                    replay = request_matches[0]
                    return await self._replay_result(
                        conn,
                        tenant_id=policy.tenant_id,
                        incident_id=replay["incident_id"],
                        operation_id=replay["operation_id"],
                        notification_class=replay["notification_class"],
                        notification_is_repeat=replay["notification_is_repeat"],
                        timeline_event_id=replay["id"],
                        notification_kind=notification_kind,
                    )

                if transition_matches:
                    if len(transition_matches) != 1 or any(
                        row["payload_sha256"] != payload_digest
                        for row in transition_matches
                    ):
                        raise IncidentConflict(
                            "alert transition identity was reused with different content"
                        )
                    transition = transition_matches[0]
                    latest_notification = await conn.fetchrow(
                        """
                        SELECT ni.operation_id,ni.notification_class,ni.scheduled_at,
                               e.id AS event_id,e.event_type,
                               EXISTS (
                                 SELECT 1
                                 FROM middleware_observability_incident_events ne
                                 WHERE ne.tenant_id=ni.tenant_id
                                   AND ne.operation_id=ni.operation_id
                                   AND ne.event_type='notification_repeat'
                               ) AS notification_is_repeat
                        FROM middleware_observability_notification_intents ni
                        LEFT JOIN middleware_observability_incident_events e
                          ON e.tenant_id=ni.tenant_id
                         AND e.operation_id=ni.operation_id
                        WHERE ni.tenant_id=$1 AND ni.incident_id=$2
                        ORDER BY ni.id DESC, e.id DESC LIMIT 1
                        """,
                        policy.tenant_id,
                        transition["incident_id"],
                    )
                    now = datetime.now(UTC)
                    activation_eligible = (
                        alert.status == "firing"
                        and command is not None
                        and latest_notification is None
                        and current_projection is not None
                        and current_projection["state"] == "firing"
                    )
                    repeat_eligible = (
                        alert.status == "firing"
                        and notification_kind == "grouped"
                        and command is not None
                        and latest_notification is not None
                        and current_projection is not None
                        and current_projection["state"] == "firing"
                        and now
                        >= latest_notification["scheduled_at"]
                        + timedelta(
                            seconds=policy.warning_repeat_interval_seconds
                        )
                    )
                    if not repeat_eligible and not activation_eligible:
                        replay = latest_notification or transition
                        replay_result = await self._replay_result(
                            conn,
                            tenant_id=policy.tenant_id,
                            incident_id=transition["incident_id"],
                            operation_id=replay["operation_id"],
                            notification_class=replay["notification_class"],
                            notification_is_repeat=replay["notification_is_repeat"],
                            timeline_event_id=(
                                replay["event_id"]
                                if latest_notification is not None
                                and replay["event_id"] is not None
                                else transition["id"]
                            ),
                            notification_kind=notification_kind,
                        )
                        if not (
                            alert.status == "firing"
                            and notification_kind == "grouped"
                            and command is not None
                            and latest_notification is not None
                        ):
                            return replay_result
                        suppressed_event_id = await conn.fetchval(
                            """
                            INSERT INTO middleware_observability_incident_events (
                              tenant_id,incident_id,event_key,request_idempotency_key,
                              event_type,previous_state,new_state,actor_id,correlation_id,
                              source_deployment,operation_id,payload_sha256,safe_metadata,
                              occurred_at
                            ) VALUES (
                              $1,$2,$3,$4,'notification_suppressed',$5,$5,$6,$7,$8,$9,$10,
                              $11::jsonb,$12
                            ) RETURNING id
                            """,
                            policy.tenant_id,
                            transition["incident_id"],
                            suppressed_event_identity(request_key),
                            request_key,
                            replay_result.incident.state,
                            actor_id,
                            correlation_id,
                            source_deployment,
                            (
                                str(replay_result.operation.command_id)
                                if replay_result.operation is not None
                                else None
                            ),
                            payload_digest,
                            json.dumps(
                                {
                                    "suppressed_transition": event_key,
                                    "reason": "repeat_interval_not_elapsed",
                                },
                                separators=(",", ":"),
                            ),
                            now,
                        )
                        await conn.execute(
                            """
                            INSERT INTO middleware_observability_incident_audit (
                              tenant_id,incident_id,event_id,action,actor_id,
                              previous_state,new_state,correlation_id,safe_metadata
                            ) VALUES (
                              $1,$2,$3,'notification_suppressed',$4,$5,$5,$6,$7::jsonb
                            )
                            """,
                            policy.tenant_id,
                            transition["incident_id"],
                            suppressed_event_id,
                            actor_id,
                            replay_result.incident.state,
                            correlation_id,
                            json.dumps(
                                {
                                    "suppressed_transition": event_key,
                                    "reason": "repeat_interval_not_elapsed",
                                },
                                separators=(",", ":"),
                            ),
                        )
                        return replay_result.model_copy(
                            update={"timeline_event_id": suppressed_event_id}
                        )

                    previous = await conn.fetchrow(
                        """SELECT * FROM middleware_observability_incidents
                           WHERE tenant_id=$1 AND incident_id=$2 FOR UPDATE""",
                        policy.tenant_id,
                        incident_id,
                    )
                    if previous is None:
                        raise IncidentConflict("repeat incident projection is missing")
                    command = build_command(
                        policy=policy,
                        alert=alert,
                        group_key=group_key,
                        receiver=policy.receiver,
                        actor=actor_id,
                        correlation_id=correlation_id,
                        incident_id=incident_id,
                        first_seen_at=previous["first_seen_at"],
                    )
                    state, _ = next_incident_state(previous["state"], alert.status)
                    row = await conn.fetchrow(
                        """
                        UPDATE middleware_observability_incidents SET
                          state=$3,last_seen_at=$4,source_deployment=$5,
                          correlation_id=$6,resource_version=resource_version+1,
                          updated_at=$4
                        WHERE tenant_id=$1 AND incident_id=$2 RETURNING *
                        """,
                        policy.tenant_id,
                        incident_id,
                        state,
                        now,
                        source_deployment,
                        correlation_id,
                    )
                    assert row is not None
                    queued_command = (
                        repeat_command(command, request_key)
                        if repeat_eligible
                        else command
                    )
                    scheduled_at = (
                        now
                        if repeat_eligible
                        else now
                        + timedelta(
                            seconds=(
                                policy.warning_group_wait_seconds
                                if notification_kind == "grouped"
                                else 0
                            )
                        )
                    )
                    operation = await self.command_store.submit_on_connection(
                        conn,
                        queued_command,
                        authenticated_client_id=authenticated_client_id,
                        next_attempt_at=scheduled_at,
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_observability_notification_intents (
                          tenant_id,incident_id,operation_id,notification_class,
                          idempotency_key,scheduled_at
                        ) VALUES ($1,$2,$3,$4,$5,$6)
                        """,
                        policy.tenant_id,
                        incident_id,
                        str(operation.command_id),
                        notification_kind,
                        queued_command.idempotency_key,
                        scheduled_at,
                    )
                    notification_event_type = (
                        "notification_repeat"
                        if repeat_eligible
                        else "firing"
                    )
                    notification_audit_action = (
                        "notification_repeat"
                        if repeat_eligible
                        else "notification_activated"
                    )
                    notification_event_key = (
                        repeat_event_identity(request_key)
                        if repeat_eligible
                        else activation_event_identity(request_key)
                    )
                    notification_event_id = await conn.fetchval(
                        """
                        INSERT INTO middleware_observability_incident_events (
                          tenant_id,incident_id,event_key,request_idempotency_key,
                          event_type,previous_state,new_state,actor_id,correlation_id,
                          source_deployment,operation_id,payload_sha256,safe_metadata,
                          occurred_at
                        ) VALUES (
                          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                          $13::jsonb,$14
                        ) RETURNING id
                        """,
                        policy.tenant_id,
                        incident_id,
                        notification_event_key,
                        request_key,
                        notification_event_type,
                        previous["state"],
                        state,
                        actor_id,
                        correlation_id,
                        source_deployment,
                        str(operation.command_id),
                        payload_digest,
                        json.dumps(
                            {
                                (
                                    "repeat_of_transition"
                                    if repeat_eligible
                                    else "activated_transition"
                                ): event_key
                            },
                            separators=(",", ":"),
                        ),
                        now,
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_observability_incident_audit (
                          tenant_id,incident_id,event_id,action,actor_id,
                          previous_state,new_state,correlation_id,safe_metadata
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
                        """,
                        policy.tenant_id,
                        incident_id,
                        notification_event_id,
                        notification_audit_action,
                        actor_id,
                        previous["state"],
                        state,
                        correlation_id,
                        json.dumps(
                            {
                                (
                                    "repeat_of_transition"
                                    if repeat_eligible
                                    else "activated_transition"
                                ): event_key
                            },
                            separators=(",", ":"),
                        ),
                    )
                    return IncidentIngestionResult(
                        incident=self._incident(row),
                        operation=operation,
                        notification_status=(
                            "scheduled"
                            if activation_eligible
                            and notification_kind == "grouped"
                            else "queued"
                        ),
                        timeline_event_id=notification_event_id,
                        duplicate=False,
                    )

                previous = current_projection
                previous_state = previous["state"] if previous else None
                state, event_type = next_incident_state(previous_state, alert.status)
                now = datetime.now(UTC)
                if (
                    alert.status == "resolved"
                    and notification_kind == "grouped"
                    and previous is not None
                ):
                    await self._cancel_pending_grouped_notifications(
                        conn,
                        tenant_id=policy.tenant_id,
                        incident_id=incident_id,
                        actor_id=actor_id,
                        now=now,
                        reason="warning resolved before group wait elapsed",
                    )
                row = await conn.fetchrow(
                    """
                    INSERT INTO middleware_observability_incidents (
                      tenant_id, incident_id, alert_fingerprint, group_key, state,
                      severity, service, environment, host, labels, annotations,
                      first_seen_at, last_seen_at, starts_at, ends_at, resolved_at,
                      source_deployment, correlation_id, resource_version,
                      created_at, updated_at
                    ) VALUES (
                      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,
                      $12,$13,$14,$15,$16,$17,$18,1,$13,$13
                    )
                    ON CONFLICT (tenant_id, incident_id) DO UPDATE SET
                      group_key=EXCLUDED.group_key, state=EXCLUDED.state,
                      severity=EXCLUDED.severity, service=EXCLUDED.service,
                      environment=EXCLUDED.environment, host=EXCLUDED.host,
                      labels=EXCLUDED.labels, annotations=EXCLUDED.annotations,
                      last_seen_at=EXCLUDED.last_seen_at, starts_at=EXCLUDED.starts_at,
                      ends_at=EXCLUDED.ends_at,
                      acknowledged_at=CASE WHEN EXCLUDED.state='acknowledged'
                        THEN middleware_observability_incidents.acknowledged_at ELSE NULL END,
                      acknowledged_by=CASE WHEN EXCLUDED.state='acknowledged'
                        THEN middleware_observability_incidents.acknowledged_by ELSE NULL END,
                      resolved_at=EXCLUDED.resolved_at,
                      source_deployment=EXCLUDED.source_deployment,
                      correlation_id=EXCLUDED.correlation_id,
                      resource_version=middleware_observability_incidents.resource_version+1,
                      updated_at=EXCLUDED.updated_at
                    RETURNING *
                    """,
                    policy.tenant_id,
                    incident_id,
                    alert.fingerprint,
                    group_key,
                    state,
                    alert.labels["severity"],
                    alert.labels["service"],
                    alert.labels["environment"],
                    alert.labels["host"],
                    json.dumps(alert.labels, separators=(",", ":"), sort_keys=True),
                    json.dumps(alert.annotations, separators=(",", ":"), sort_keys=True),
                    previous["first_seen_at"] if previous else alert.starts_at,
                    now,
                    alert.starts_at,
                    alert.ends_at if alert.status == "resolved" else None,
                    now if state == "resolved" else None,
                    source_deployment,
                    correlation_id,
                )
                assert row is not None

                operation = None
                scheduled_at = now
                if command is not None:
                    command = build_command(
                        policy=policy,
                        alert=alert,
                        group_key=group_key,
                        receiver=policy.receiver,
                        actor=actor_id,
                        correlation_id=correlation_id,
                        incident_id=incident_id,
                        first_seen_at=row["first_seen_at"],
                    )
                    if notification_kind == "grouped":
                        scheduled_at += timedelta(
                            seconds=policy.warning_group_wait_seconds
                        )
                    operation = await self.command_store.submit_on_connection(
                        conn,
                        command,
                        authenticated_client_id=authenticated_client_id,
                        next_attempt_at=scheduled_at,
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_observability_notification_intents (
                          tenant_id, incident_id, operation_id, notification_class,
                          idempotency_key, scheduled_at
                        ) VALUES ($1,$2,$3,$4,$5,$6)
                        """,
                        policy.tenant_id,
                        incident_id,
                        str(operation.command_id),
                        notification_kind,
                        command.idempotency_key,
                        scheduled_at,
                    )

                event_id = await conn.fetchval(
                    """
                    INSERT INTO middleware_observability_incident_events (
                      tenant_id, incident_id, event_key, request_idempotency_key,
                      event_type, previous_state,
                      new_state, actor_id, correlation_id, source_deployment,
                      operation_id, payload_sha256, safe_metadata, occurred_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14)
                    RETURNING id
                    """,
                    policy.tenant_id,
                    incident_id,
                    event_key,
                    request_key,
                    event_type,
                    previous_state,
                    state,
                    actor_id,
                    correlation_id,
                    source_deployment,
                    str(operation.command_id) if operation else None,
                    payload_digest,
                    json.dumps({"group_key": group_key}, separators=(",", ":")),
                    now,
                )
                await conn.execute(
                    """
                    INSERT INTO middleware_observability_incident_audit (
                      tenant_id, incident_id, event_id, action, actor_id,
                      previous_state, new_state, correlation_id, safe_metadata
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
                    """,
                    policy.tenant_id,
                    incident_id,
                    event_id,
                    event_type,
                    actor_id,
                    previous_state,
                    state,
                    correlation_id,
                    json.dumps(
                        {"source_deployment": source_deployment},
                        separators=(",", ":"),
                    ),
                )
                return IncidentIngestionResult(
                    incident=self._incident(row),
                    operation=operation,
                    notification_status=(
                        "scheduled"
                        if notification_kind == "grouped" and operation
                        else "queued"
                        if operation
                        else "state_only"
                        if notification_kind == "state_only"
                        else "disabled"
                    ),
                    timeline_event_id=event_id,
                    duplicate=False,
                )

    async def ingest_status(
        self,
        *,
        policy: AlertPolicy,
        item: AlertmanagerStatusItem,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        request_idempotency_key: str,
        observed_at: datetime,
    ) -> IncidentRecord:
        event_key = status_identity(item, observed_at)
        request_key = request_identity(
            ALERTMANAGER_CLIENT_ID,
            request_idempotency_key,
            item.fingerprint,
        )
        digest = canonical_payload_sha256(
            {
                "item": item.model_dump(mode="json"),
                "observed_at": observed_at.isoformat(),
            }
        )
        incident_id = incident_identity(policy.tenant_id, item.fingerprint)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                    f"{policy.tenant_id}:{item.fingerprint}",
                )
                replays = await conn.fetch(
                    """SELECT id,incident_id,payload_sha256,safe_metadata
                       FROM middleware_observability_incident_events
                       WHERE tenant_id=$1
                         AND (event_key=$2 OR request_idempotency_key=$3)
                       ORDER BY id""",
                    policy.tenant_id,
                    event_key,
                    request_key,
                )
                if replays:
                    if len({row["id"] for row in replays}) != 1 or any(
                        row["payload_sha256"] != digest for row in replays
                    ):
                        raise IncidentConflict(
                            "status identities disagree or contain different content"
                        )
                    replay = replays[0]
                    metadata = self._json(replay["safe_metadata"])
                    response_payload = metadata.get("response_payload")
                    if not isinstance(response_payload, dict):
                        raise IncidentConflict(
                            "status replay response evidence is missing"
                        )
                    return IncidentRecord.model_validate(response_payload).model_copy(
                        update={"duplicate": True}
                    )
                previous = await conn.fetchrow(
                    """SELECT * FROM middleware_observability_incidents
                       WHERE tenant_id=$1 AND incident_id=$2 FOR UPDATE""",
                    policy.tenant_id,
                    incident_id,
                )
                if previous is None or previous["group_key"] != item.group_key:
                    raise IncidentNotFound("status reconciliation incident was not found")
                if previous["starts_at"] != item.starts_at:
                    raise IncidentConflict(
                        "status evidence does not match the current alert occurrence"
                    )
                latest_observed = await conn.fetchval(
                    """
                    SELECT max(occurred_at)
                    FROM middleware_observability_incident_events
                    WHERE tenant_id=$1 AND incident_id=$2
                      AND safe_metadata->>'status_source'='alertmanager-status'
                    """,
                    policy.tenant_id,
                    incident_id,
                )
                evidence_times = [
                    value
                    for value in (
                        latest_observed,
                        previous["ends_at"]
                        if previous["state"] == "resolved"
                        else None,
                    )
                    if value is not None
                ]
                if evidence_times and observed_at <= max(evidence_times):
                    raise IncidentConflict(
                        "status observation is not newer than current evidence"
                    )
                state, event_type = next_incident_state(previous["state"], item.state)
                now = datetime.now(UTC)
                if item.state in {"resolved", "silenced", "inhibited"}:
                    await self._cancel_pending_grouped_notifications(
                        conn,
                        tenant_id=policy.tenant_id,
                        incident_id=incident_id,
                        actor_id=actor_id,
                        now=now,
                        reason="warning left firing state before group wait elapsed",
                    )
                row = await conn.fetchrow(
                    """
                    UPDATE middleware_observability_incidents SET
                      state=$3::text, last_seen_at=$4::timestamptz,
                      ends_at=CASE WHEN $7::text='firing'
                        THEN NULL::timestamptz ELSE ends_at END,
                      resolved_at=CASE WHEN $3::text='resolved'
                        THEN $4::timestamptz ELSE NULL::timestamptz END,
                      source_deployment=$5::text, correlation_id=$6::text,
                      resource_version=resource_version+1,
                      updated_at=$4::timestamptz
                    WHERE tenant_id=$1 AND incident_id=$2 RETURNING *
                    """,
                    policy.tenant_id,
                    incident_id,
                    state,
                    now,
                    source_deployment,
                    correlation_id,
                    item.state,
                )
                assert row is not None
                incident = self._incident(row)
                event_id = await conn.fetchval(
                    """
                    INSERT INTO middleware_observability_incident_events (
                      tenant_id, incident_id, event_key, request_idempotency_key,
                      event_type, previous_state,
                      new_state, actor_id, correlation_id, source_deployment,
                      payload_sha256, safe_metadata, occurred_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)
                    RETURNING id
                    """,
                    policy.tenant_id,
                    incident_id,
                    event_key,
                    request_key,
                    event_type,
                    previous["state"],
                    state,
                    actor_id,
                    correlation_id,
                    source_deployment,
                    digest,
                    json.dumps(
                        {
                            "silenced_by": sorted(item.silenced_by),
                            "inhibited_by": sorted(item.inhibited_by),
                            "status_source": "alertmanager-status",
                            "response_payload": incident.model_dump(mode="json"),
                        },
                        separators=(",", ":"),
                    ),
                    observed_at,
                )
                await conn.execute(
                    """INSERT INTO middleware_observability_incident_audit (
                         tenant_id, incident_id, event_id, action, actor_id,
                         previous_state, new_state, correlation_id, safe_metadata
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'{}'::jsonb)""",
                    policy.tenant_id,
                    incident_id,
                    event_id,
                    event_type,
                    actor_id,
                    previous["state"],
                    state,
                    correlation_id,
                )
                return incident

    async def get(self, tenant_id: str, incident_id: uuid.UUID) -> IncidentRecord:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT * FROM middleware_observability_incidents
                   WHERE tenant_id=$1 AND incident_id=$2""",
                tenant_id,
                incident_id,
            )
        if row is None:
            raise IncidentNotFound("incident was not found")
        return self._incident(row)

    async def list_incidents(
        self,
        tenant_id: str,
        *,
        limit: int,
        position: tuple[datetime, uuid.UUID] | None,
        state: str | None,
        severity: str | None,
        service: str | None,
    ) -> list[IncidentRecord]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM middleware_observability_incidents
                WHERE tenant_id=$1
                  AND ($2::text IS NULL OR state=$2)
                  AND ($3::text IS NULL OR severity=$3)
                  AND ($4::text IS NULL OR service=$4)
                  AND ($5::timestamptz IS NULL OR (updated_at,incident_id)<($5,$6))
                ORDER BY updated_at DESC, incident_id DESC LIMIT $7
                """,
                tenant_id,
                state,
                severity,
                service,
                position[0] if position else None,
                position[1] if position else None,
                limit,
            )
        return [self._incident(row) for row in rows]

    async def list_timeline(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        limit: int,
        after_event_id: int | None,
    ) -> list[IncidentTimelineEvent]:
        await self.get(tenant_id, incident_id)
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM middleware_observability_incident_events
                WHERE tenant_id=$1 AND incident_id=$2
                  AND ($3::bigint IS NULL OR id>$3)
                ORDER BY id ASC LIMIT $4
                """,
                tenant_id,
                incident_id,
                after_event_id,
                limit,
            )
        return [
            IncidentTimelineEvent(
                event_id=row["id"],
                incident_id=row["incident_id"],
                event_type=row["event_type"],
                previous_state=row["previous_state"],
                new_state=row["new_state"],
                actor_id=row["actor_id"],
                correlation_id=row["correlation_id"],
                source_deployment=row["source_deployment"],
                operation_id=row["operation_id"],
                safe_metadata=self._json(row["safe_metadata"]),
                occurred_at=row["occurred_at"],
            )
            for row in rows
        ]

    async def mutate(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        action: IncidentAction,
        actor_id: str,
        correlation_id: str,
        idempotency_key: str,
        expected_version: int,
        reason: str,
    ) -> IncidentRecord:
        request_digest = canonical_payload_sha256(
            {"expected_version": expected_version, "reason": reason}
        )
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    """SELECT * FROM middleware_observability_incidents
                       WHERE tenant_id=$1 AND incident_id=$2 FOR UPDATE""",
                    tenant_id,
                    incident_id,
                )
                if current is None:
                    raise IncidentNotFound("incident was not found")
                replay = await conn.fetchrow(
                    """SELECT request_sha256,response_payload
                       FROM middleware_observability_incident_mutations
                       WHERE tenant_id=$1 AND incident_id=$2 AND action=$3
                         AND actor_id=$4 AND idempotency_key=$5""",
                    tenant_id,
                    incident_id,
                    action,
                    actor_id,
                    idempotency_key,
                )
                if replay:
                    if replay["request_sha256"] != request_digest:
                        raise IncidentConflict(
                            "idempotency key was reused with different content"
                        )
                    payload = replay["response_payload"]
                    if isinstance(payload, str):
                        payload = json.loads(payload)
                    return IncidentRecord.model_validate(payload).model_copy(
                        update={"duplicate": True}
                    )
                if current["resource_version"] != expected_version:
                    raise IncidentConflict("expected_version is stale")
                allowed = {
                    "acknowledge": {"firing", "inhibited", "silenced"},
                    "resolve": {"firing", "acknowledged", "inhibited", "silenced"},
                    "reopen": {"resolved"},
                }
                if current["state"] not in allowed[action]:
                    raise IncidentConflict(f"incident cannot transition via {action}")
                target_states: dict[IncidentAction, IncidentState] = {
                    "acknowledge": "acknowledged", "resolve": "resolved", "reopen": "firing",
                }
                state = target_states[action]
                now = datetime.now(UTC)
                if action == "resolve":
                    await self._cancel_pending_grouped_notifications(
                        conn,
                        tenant_id=tenant_id,
                        incident_id=incident_id,
                        actor_id=actor_id,
                        now=now,
                        reason="warning was resolved before group wait elapsed",
                    )
                row = await conn.fetchrow(
                    """
                    UPDATE middleware_observability_incidents SET
                      state=$3::text,
                      acknowledged_at=CASE WHEN $4::text='acknowledge'
                        THEN $5::timestamptz ELSE NULL::timestamptz END,
                      acknowledged_by=CASE WHEN $4::text='acknowledge'
                        THEN $6::text ELSE NULL::text END,
                      resolved_at=CASE WHEN $4::text='resolve'
                        THEN $5::timestamptz ELSE NULL::timestamptz END,
                      ends_at=CASE WHEN $4::text='reopen'
                        THEN NULL::timestamptz ELSE ends_at END,
                      correlation_id=$7::text,
                      resource_version=resource_version+1,
                      updated_at=$5::timestamptz
                    WHERE tenant_id=$1 AND incident_id=$2 RETURNING *
                    """,
                    tenant_id,
                    incident_id,
                    state,
                    action,
                    now,
                    actor_id,
                    correlation_id,
                )
                assert row is not None
                event_key = "incident-mutation-v1:" + hashlib.sha256(
                    f"{tenant_id}:{incident_id}:{action}:{actor_id}:{idempotency_key}".encode()
                ).hexdigest()
                event_id = await conn.fetchval(
                    """INSERT INTO middleware_observability_incident_events (
                         tenant_id,incident_id,event_key,request_idempotency_key,
                         event_type,previous_state,
                         new_state,actor_id,correlation_id,source_deployment,
                         payload_sha256,safe_metadata,occurred_at
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)
                       RETURNING id""",
                    tenant_id,
                    incident_id,
                    event_key,
                    event_key,
                    action,
                    current["state"],
                    state,
                    actor_id,
                    correlation_id,
                    current["source_deployment"],
                    request_digest,
                    json.dumps({"reason": reason}, separators=(",", ":")),
                    now,
                )
                await conn.execute(
                    """INSERT INTO middleware_observability_incident_audit (
                         tenant_id,incident_id,event_id,action,actor_id,
                         previous_state,new_state,correlation_id,safe_metadata
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)""",
                    tenant_id,
                    incident_id,
                    event_id,
                    action,
                    actor_id,
                    current["state"],
                    state,
                    correlation_id,
                    json.dumps({"reason": reason}, separators=(",", ":")),
                )
                incident = self._incident(row)
                await conn.execute(
                    """INSERT INTO middleware_observability_incident_mutations (
                         tenant_id,incident_id,action,actor_id,idempotency_key,
                         request_sha256,response_payload
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)""",
                    tenant_id,
                    incident_id,
                    action,
                    actor_id,
                    idempotency_key,
                    request_digest,
                    json.dumps(incident.model_dump(mode="json"), separators=(",", ":"), sort_keys=True),
                )
                return incident

    async def list_notification_attempts(
        self,
        tenant_id: str,
        incident_id: uuid.UUID,
        *,
        limit: int,
    ) -> list[NotificationAttemptView]:
        await self.get(tenant_id, incident_id)
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT ni.id AS notification_id,ni.operation_id,
                       ni.notification_class,ni.scheduled_at,c.state AS operation_state,
                       a.attempt_number,a.state AS attempt_state,a.provider_operation_id,
                       a.error_code,a.started_at,a.finished_at
                FROM middleware_observability_notification_intents ni
                JOIN middleware_commands c ON c.tenant_id=ni.tenant_id
                  AND c.command_id=ni.operation_id
                LEFT JOIN middleware_command_attempts a ON a.tenant_id=ni.tenant_id
                  AND a.command_id=ni.operation_id
                WHERE ni.tenant_id=$1 AND ni.incident_id=$2
                ORDER BY ni.id DESC,a.attempt_number DESC NULLS LAST LIMIT $3
                """,
                tenant_id,
                incident_id,
                limit,
            )
        return [
            NotificationAttemptView(
                notification_id=row["notification_id"],
                operation_id=row["operation_id"],
                notification_class=row["notification_class"],
                operation_state=row["operation_state"],
                attempt_number=row["attempt_number"],
                attempt_state=row["attempt_state"],
                provider_operation_id=row["provider_operation_id"],
                safe_error_code=row["error_code"],
                reconciliation_required=row["operation_state"]
                == "reconciliation_required",
                scheduled_at=row["scheduled_at"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
            )
            for row in rows
        ]

    async def ready(self) -> bool:
        try:
            async with self.pool.acquire() as conn:
                head = await conn.fetchval(
                    "SELECT max(version) FROM middleware_schema_migrations"
                )
                table_rows = await conn.fetch(
                    """SELECT table_name FROM information_schema.tables
                       WHERE table_schema='public' AND table_name=ANY($1::text[])""",
                    list(self.REQUIRED_TABLES),
                )
                column_rows = await conn.fetch(
                    """SELECT table_name,column_name FROM information_schema.columns
                       WHERE table_schema='public' AND table_name=ANY($1::text[])""",
                    list(self.REQUIRED_TABLES),
                )
                key_rows = await conn.fetch(
                    """
                    SELECT tc.table_name,tc.constraint_type,
                           array_agg(kcu.column_name ORDER BY kcu.ordinal_position) AS columns
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                      ON tc.constraint_schema=kcu.constraint_schema
                     AND tc.constraint_name=kcu.constraint_name
                     AND tc.table_name=kcu.table_name
                    WHERE tc.table_schema='public'
                      AND tc.table_name=ANY($1::text[])
                      AND tc.constraint_type IN ('PRIMARY KEY','UNIQUE')
                    GROUP BY tc.table_name,tc.constraint_type,tc.constraint_name
                    """,
                    list(self.REQUIRED_TABLES),
                )
                foreign_key_rows = await conn.fetch(
                    """
                    SELECT conrelid::regclass::text AS table_name,
                           confrelid::regclass::text AS foreign_table,
                           ARRAY(
                             SELECT attname FROM pg_attribute
                             WHERE attrelid=conrelid AND attnum=ANY(conkey)
                             ORDER BY array_position(conkey,attnum)
                           ) AS columns,
                           ARRAY(
                             SELECT attname FROM pg_attribute
                             WHERE attrelid=confrelid AND attnum=ANY(confkey)
                             ORDER BY array_position(confkey,attnum)
                           ) AS foreign_columns
                    FROM pg_constraint
                    WHERE contype='f'
                      AND connamespace='public'::regnamespace
                      AND conrelid::regclass::text=ANY($1::text[])
                    """,
                    list(self.REQUIRED_TABLES),
                )
                triggers = await conn.fetch(
                    """SELECT tgname,tgenabled::text AS enabled FROM pg_trigger
                       WHERE NOT tgisinternal AND tgname=ANY($1::text[])""",
                    list(self.REQUIRED_TRIGGERS),
                )
            found_tables = {row["table_name"] for row in table_rows}
            found_columns: dict[str, set[str]] = {table: set() for table in self.REQUIRED_COLUMNS}
            for row in column_rows:
                found_columns[row["table_name"]].add(row["column_name"])
            found_keys = {
                (
                    row["table_name"],
                    row["constraint_type"],
                    tuple(row["columns"]),
                )
                for row in key_rows
            }
            found_foreign_keys = {
                (
                    row["table_name"],
                    tuple(row["columns"]),
                    row["foreign_table"],
                    tuple(row["foreign_columns"]),
                )
                for row in foreign_key_rows
            }
            found_triggers = {
                row["tgname"] for row in triggers if row["enabled"] == "O"
            }
            return (
                head is not None
                and head >= 9
                and found_tables == self.REQUIRED_TABLES
                and all(
                    required <= found_columns[table]
                    for table, required in self.REQUIRED_COLUMNS.items()
                )
                and self.REQUIRED_KEYS <= found_keys
                and self.REQUIRED_FOREIGN_KEYS <= found_foreign_keys
                and found_triggers == self.REQUIRED_TRIGGERS
            )
        except Exception:
            return False

    async def close(self) -> None:
        # The command store owns and closes this shared pool.
        return None


@dataclass(frozen=True)
class IncidentService:
    store: IncidentStore
    commands: CommandService
    policy: AlertPolicy
    delivery_enabled: bool

    async def ingest(
        self,
        *,
        group_key: str,
        alert: AlertmanagerAlert,
        actor_id: str,
        correlation_id: str,
        source_deployment: str,
        request_idempotency_key: str,
    ) -> IncidentIngestionResult:
        kind = notification_class(self.policy, alert.labels["severity"])
        command = None
        if self.delivery_enabled and kind != "state_only":
            command = build_command(
                policy=self.policy,
                alert=alert,
                group_key=group_key,
                receiver=self.policy.receiver,
                actor=actor_id,
                correlation_id=correlation_id,
                incident_id=incident_identity(
                    self.policy.tenant_id,
                    alert.fingerprint,
                ),
            )
            self.commands.validate_submission(
                command,
                authenticated_subject=actor_id,
                authenticated_client_id=ALERTMANAGER_CLIENT_ID,
            )
        return await self.store.ingest(
            policy=self.policy,
            group_key=group_key,
            alert=alert,
            actor_id=actor_id,
            correlation_id=correlation_id,
            source_deployment=source_deployment,
            request_idempotency_key=request_idempotency_key,
            command=command,
            authenticated_client_id=ALERTMANAGER_CLIENT_ID,
            notification_kind=kind,
        )
