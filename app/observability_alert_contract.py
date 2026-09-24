from __future__ import annotations

import hashlib
import html
import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Literal, Mapping
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .commands import CommandEnvelope, CommandNotFound, CommandOperation
from app.core.config import ConfigurationError, Settings


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "observability-alert-policy.v1.json"
COMMAND_TYPE = "observability.alert.email.send.v1"
COMMAND_PREFIX = "observability.alert."
COMMAND_TARGET = "klyrow-alert-email"
COMMAND_CAPABILITY = "OBSERVABILITY_ALERT_EMAIL_DELIVERY"
ALERTMANAGER_CLIENT_ID = "alertmanager"
DELIVERY_CLIENT_ID = "klyrow-alert-adapter"
OPERATOR_CLIENT_ID = "observability-operator"

SAFE_LABELS = frozenset(
    {
        "alertname",
        "severity",
        "service",
        "environment",
        "host",
        "cluster",
        "owner",
        "release_id",
        "codestra_business",
    }
)
SAFE_ANNOTATIONS = frozenset(
    {"summary", "description", "runbook_url", "dashboard_url"}
)
SENSITIVE_PARTS = (
    "authorization",
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "private_key",
    "api_key",
    "access_key",
    "session",
    "cookie",
)
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{7,179}$")
ACTIVATION_RE = re.compile(r"^[A-Z0-9][A-Z0-9._/-]{7,127}$")


class AlertPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    policy_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    receiver: str = Field(min_length=1, max_length=128)
    recipient_policy_id: str = Field(min_length=1, max_length=128)
    sender_policy_id: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=3, max_length=320)
    sender: str = Field(min_length=3, max_length=320)
    reply_to: str = Field(min_length=3, max_length=320)
    allowed_environments: list[str] = Field(min_length=1, max_length=4)
    allowed_severities: list[str] = Field(min_length=1, max_length=8)
    immediate_severities: list[str] = Field(max_length=4)
    grouped_severities: list[str] = Field(max_length=4)
    state_only_severities: list[str] = Field(max_length=4)
    warning_group_wait_seconds: int = Field(ge=30, le=3_600)
    warning_repeat_interval_seconds: int = Field(ge=900, le=86_400)
    max_alerts_per_request: int = Field(ge=1, le=100)
    max_body_bytes: int = Field(ge=4_096, le=1_048_576)
    normal_delivery_path: Literal["middleware-klyrow-adapter"]
    direct_smtp_allowed: Literal[False]
    delivery_enabled_by_default: Literal[False]

    @field_validator("recipient", "sender", "reply_to")
    @classmethod
    def require_email_shape(cls, value: str) -> str:
        candidate = value.strip().lower()
        if (
            candidate.count("@") != 1
            or candidate.startswith("@")
            or candidate.endswith("@")
        ):
            raise ValueError("policy email address is invalid")
        return candidate

    @field_validator(
        "allowed_environments",
        "allowed_severities",
        "immediate_severities",
        "grouped_severities",
        "state_only_severities",
    )
    @classmethod
    def normalize_unique_values(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().lower() for item in value]
        if any(not item or len(item) > 64 for item in normalized):
            raise ValueError("policy values must contain 1-64 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("policy values must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_severity_classes(self) -> "AlertPolicy":
        classes = (
            set(self.immediate_severities),
            set(self.grouped_severities),
            set(self.state_only_severities),
        )
        if any(left & right for index, left in enumerate(classes) for right in classes[index + 1 :]):
            raise ValueError("alert severity classes must be disjoint")
        if set().union(*classes) != set(self.allowed_severities):
            raise ValueError("every allowed severity must have exactly one delivery class")
        if self.warning_repeat_interval_seconds <= self.warning_group_wait_seconds:
            raise ValueError("warning repeat interval must exceed the group wait")
        return self


class AlertmanagerAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["firing", "resolved"]
    labels: dict[str, str]
    annotations: dict[str, str]
    starts_at: datetime = Field(alias="startsAt")
    ends_at: datetime = Field(alias="endsAt")
    generator_url: str = Field(alias="generatorURL", max_length=2_048)
    fingerprint: str = Field(min_length=1, max_length=128)

    @field_validator("starts_at", "ends_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("alert timestamps must include timezone")
        return value

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str]) -> dict[str, str]:
        return safe_map(
            value,
            allowed=SAFE_LABELS,
            maximum_items=24,
            maximum_value=512,
        )

    @field_validator("annotations")
    @classmethod
    def validate_annotations(cls, value: dict[str, str]) -> dict[str, str]:
        sanitized = safe_map(
            value,
            allowed=SAFE_ANNOTATIONS,
            maximum_items=12,
            maximum_value=4_096,
        )
        for key in ("runbook_url", "dashboard_url"):
            if key in sanitized:
                sanitized[key] = safe_url(sanitized[key])
        return sanitized

    @field_validator("generator_url")
    @classmethod
    def normalize_generator_url(cls, value: str) -> str:
        return safe_url(value)

    @model_validator(mode="after")
    def require_core_labels(self) -> "AlertmanagerAlert":
        required = {
            "alertname",
            "severity",
            "service",
            "environment",
            "host",
            "codestra_business",
            "owner",
        }
        missing = sorted(required - set(self.labels))
        if missing:
            raise ValueError("alert is missing required labels: " + ", ".join(missing))
        required_annotations = {"summary", "description", "runbook_url"}
        missing_annotations = sorted(required_annotations - set(self.annotations))
        if missing_annotations:
            raise ValueError(
                "alert is missing required annotations: "
                + ", ".join(missing_annotations)
            )
        if self.status == "resolved" and self.ends_at <= self.starts_at:
            raise ValueError("resolved alert endsAt must follow startsAt")
        return self


class AlertmanagerWebhook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["4"]
    group_key: str = Field(alias="groupKey", min_length=1, max_length=2_048)
    truncated_alerts: int = Field(alias="truncatedAlerts", ge=0)
    status: Literal["firing", "resolved"]
    receiver: str = Field(min_length=1, max_length=128)
    group_labels: dict[str, str] = Field(alias="groupLabels")
    common_labels: dict[str, str] = Field(alias="commonLabels")
    common_annotations: dict[str, str] = Field(alias="commonAnnotations")
    external_url: str = Field(alias="externalURL", max_length=2_048)
    alerts: list[AlertmanagerAlert]

    @field_validator("group_labels", "common_labels")
    @classmethod
    def validate_label_maps(cls, value: dict[str, str]) -> dict[str, str]:
        return safe_map(
            value,
            allowed=SAFE_LABELS,
            maximum_items=24,
            maximum_value=512,
        )

    @field_validator("common_annotations")
    @classmethod
    def validate_common_annotations(cls, value: dict[str, str]) -> dict[str, str]:
        return safe_map(
            value,
            allowed=SAFE_ANNOTATIONS,
            maximum_items=12,
            maximum_value=4_096,
        )

    @field_validator("external_url")
    @classmethod
    def normalize_external_url(cls, value: str) -> str:
        return safe_url(value)

    @model_validator(mode="after")
    def validate_group(self) -> "AlertmanagerWebhook":
        if not self.alerts:
            raise ValueError("alerts must not be empty")
        if self.truncated_alerts:
            raise ValueError("truncated Alertmanager payloads are not accepted")
        return self


class AlertDeliveryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=8, max_length=128)
    operation_id: uuid.UUID
    status: Literal[
        "accepted", "queued", "sent", "delivered", "failed", "indeterminate"
    ]
    provider_message_id: str | None = Field(default=None, max_length=256)
    occurred_at: datetime
    safe_metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def require_occurred_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include timezone")
        return value

    @field_validator("safe_metadata")
    @classmethod
    def validate_safe_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        return safe_map(value, allowed=None, maximum_items=16, maximum_value=512)


class AlertOperationView(BaseModel):
    incident_id: uuid.UUID
    operation_id: uuid.UUID | None
    alert_fingerprint: str
    alert_state: Literal["firing", "resolved"]
    operation_state: str
    notification_status: str
    duplicate: bool
    status_url: str | None
    events_url: str | None


class AlertSubmissionResponse(BaseModel):
    policy_id: str
    recipient_policy_id: str
    sender_policy_id: str
    operations: list[AlertOperationView]


def safe_map(
    value: Mapping[str, str],
    *,
    allowed: frozenset[str] | None,
    maximum_items: int,
    maximum_value: int,
) -> dict[str, str]:
    if len(value) > maximum_items:
        raise ValueError(f"map may contain at most {maximum_items} properties")
    result: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, str):
            raise ValueError("map keys and values must be strings")
        key = raw_key.strip()
        item = raw_value.strip()
        if not key or len(key) > 128 or len(item) > maximum_value:
            raise ValueError("map key or value is outside the allowed bounds")
        lowered = key.lower()
        if any(part in lowered for part in SENSITIVE_PARTS):
            raise ValueError("sensitive metadata keys are prohibited")
        if allowed is not None and lowered not in allowed:
            continue
        lowered_item = item.lower()
        if "bearer " in lowered_item or "-----begin " in lowered_item:
            raise ValueError("sensitive metadata values are prohibited")
        result[lowered] = item
    return result


def safe_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are prohibited")
    port = f":{parsed.port}" if parsed.port else ""
    host = parsed.hostname.lower()
    return urlunsplit((parsed.scheme.lower(), host + port, parsed.path or "/", "", ""))


def load_policy() -> AlertPolicy:
    try:
        value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError("observability alert policy cannot be loaded") from exc
    return AlertPolicy.model_validate(value)


def explicit_bool(name: str, *, env: Mapping[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    value = source.get(name, "false").strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off", ""}:
        return False
    raise ConfigurationError(f"{name} must be an explicit boolean")


def activation_enabled(
    settings: Settings,
    *,
    env: Mapping[str, str] | None = None,
) -> bool:
    source = os.environ if env is None else env
    enabled = explicit_bool("OBSERVABILITY_ALERT_EMAIL_DELIVERY", env=source)
    if not enabled:
        return False
    activation_id = source.get("OBSERVABILITY_ALERT_ACTIVATION_ID", "").strip()
    if not ACTIVATION_RE.fullmatch(activation_id):
        raise ConfigurationError(
            "OBSERVABILITY_ALERT_ACTIVATION_ID is required when alert delivery is enabled"
        )
    if (
        settings.app_env == "production"
        and settings.production_activation_id != activation_id
    ):
        raise ConfigurationError(
            "observability alert activation must match PRODUCTION_ACTIVATION_ID"
        )
    return True


def idempotency_identity(
    *,
    policy: AlertPolicy,
    alert: AlertmanagerAlert,
    group_key: str,
    receiver: str,
) -> str:
    canonical = "\n".join(
        (
            "codestra-observability-alert-v1",
            group_key,
            alert.fingerprint,
            alert.status,
            receiver,
            alert.labels["environment"],
            policy.recipient_policy_id,
            alert.starts_at.isoformat(),
        )
    ).encode("utf-8")
    return "obs-alert-v1:" + hashlib.sha256(canonical).hexdigest()


def subject(alert: AlertmanagerAlert) -> str:
    prefix = "FIRING" if alert.status == "firing" else "RESOLVED"
    return (
        f"[Codestra][{prefix}][{alert.labels['severity'].upper()}] "
        f"{alert.labels['alertname']} on {alert.labels['host']}"
    )[:998]


def text_body(
    alert: AlertmanagerAlert,
    correlation_id: str,
    incident_id: uuid.UUID,
    first_seen_at: datetime | None = None,
) -> str:
    first_seen = first_seen_at or alert.starts_at
    values = [
        f"State: {alert.status.upper()}",
        f"Severity: {alert.labels['severity']}",
        f"Environment: {alert.labels['environment']}",
        f"Business: {alert.labels['codestra_business']}",
        f"Service: {alert.labels['service']}",
        f"Host: {alert.labels['host']}",
        f"Incident ID: {incident_id}",
        f"Summary: {alert.annotations.get('summary', alert.labels['alertname'])}",
        f"Description: {alert.annotations.get('description', '')}",
        f"First seen: {first_seen.isoformat()}",
        f"Ended: {alert.ends_at.isoformat() if alert.status == 'resolved' else ''}",
        f"Fingerprint: {alert.fingerprint}",
        f"Runbook: {alert.annotations.get('runbook_url', '')}",
        f"Dashboard: {alert.annotations.get('dashboard_url', '')}",
        f"Correlation ID: {correlation_id}",
        f"Release ID: {alert.labels.get('release_id', '')}",
    ]
    return "\n".join(values)


def html_body(
    alert: AlertmanagerAlert,
    correlation_id: str,
    incident_id: uuid.UUID,
    first_seen_at: datetime | None = None,
) -> str:
    first_seen = first_seen_at or alert.starts_at
    fields = {
        "State": alert.status.upper(),
        "Severity": alert.labels["severity"],
        "Environment": alert.labels["environment"],
        "Business": alert.labels["codestra_business"],
        "Service": alert.labels["service"],
        "Host": alert.labels["host"],
        "Incident ID": str(incident_id),
        "Summary": alert.annotations.get("summary", alert.labels["alertname"]),
        "Description": alert.annotations.get("description", ""),
        "First seen": first_seen.isoformat(),
        "Ended": alert.ends_at.isoformat() if alert.status == "resolved" else "",
        "Fingerprint": alert.fingerprint,
        "Runbook": alert.annotations.get("runbook_url", ""),
        "Dashboard": alert.annotations.get("dashboard_url", ""),
        "Correlation ID": correlation_id,
        "Release ID": alert.labels.get("release_id", ""),
    }
    rows = "".join(
        f"<tr><th align='left'>{html.escape(key)}</th>"
        f"<td>{html.escape(value)}</td></tr>"
        for key, value in fields.items()
    )
    return (
        "<!doctype html><html><body>"
        "<h1>Codestra Observability Alert</h1>"
        f"<table>{rows}</table>"
        "</body></html>"
    )


def build_command(
    *,
    policy: AlertPolicy,
    alert: AlertmanagerAlert,
    group_key: str,
    receiver: str,
    actor: str,
    correlation_id: str,
    incident_id: uuid.UUID,
    first_seen_at: datetime | None = None,
) -> CommandEnvelope:
    first_seen = first_seen_at or alert.starts_at
    idempotency_key = idempotency_identity(
        policy=policy,
        alert=alert,
        group_key=group_key,
        receiver=receiver,
    )
    command_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://operations.codestra.co/observability/alerts/{idempotency_key}",
    )
    return CommandEnvelope(
        command_id=command_id,
        command_type=COMMAND_TYPE,
        command_version="1.0",
        target=COMMAND_TARGET,
        tenant_id=policy.tenant_id,
        requested_by=actor,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        capability=COMMAND_CAPABILITY,
        payload={
            "schema_version": "1.0",
            "message_id": str(command_id),
            "from": policy.sender,
            "to": [policy.recipient],
            "reply_to": policy.reply_to,
            "content": {
                "subject": subject(alert),
                "text": text_body(
                    alert,
                    correlation_id,
                    incident_id,
                    first_seen,
                ),
                "html": html_body(
                    alert,
                    correlation_id,
                    incident_id,
                    first_seen,
                ),
            },
            "classification": "operational-alert",
            "recipient_policy_id": policy.recipient_policy_id,
            "sender_policy_id": policy.sender_policy_id,
            "alert": {
                "incident_id": str(incident_id),
                "group_key": group_key,
                "fingerprint": alert.fingerprint,
                "state": alert.status,
                "severity": alert.labels["severity"],
                "service": alert.labels["service"],
                "host": alert.labels["host"],
                "environment": alert.labels["environment"],
                "codestra_business": alert.labels["codestra_business"],
                "first_seen_at": first_seen.isoformat(),
                "starts_at": alert.starts_at.isoformat(),
                "ends_at": alert.ends_at.isoformat(),
                "generator_url": alert.generator_url,
                "labels": alert.labels,
                "annotations": alert.annotations,
            },
        },
    )


def operation_view(
    operation: CommandOperation,
    alert: AlertmanagerAlert,
    *,
    incident_id: uuid.UUID,
    notification_status: str,
) -> AlertOperationView:
    return AlertOperationView(
        incident_id=incident_id,
        operation_id=operation.command_id,
        alert_fingerprint=alert.fingerprint,
        alert_state=alert.status,
        operation_state=operation.state,
        notification_status=notification_status,
        duplicate=operation.duplicate,
        status_url=f"/v1/observability/alerts/{operation.command_id}",
        events_url=f"/v1/observability/alerts/{operation.command_id}/events",
    )


def require_alert_operation(operation: CommandOperation) -> None:
    if operation.command_type != COMMAND_TYPE or operation.target != COMMAND_TARGET:
        raise CommandNotFound("observability alert operation was not found")
