"""Durable Alertmanager-to-Odoo projection enqueueing.

The alert API remains the incident authority. This adapter only writes the
existing Middleware integration event and Odoo delivery queue; it never calls
Odoo directly and never stores raw annotations, logs, traces, or message data.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any
from uuid import UUID, uuid4

from .observability_incidents import IncidentRecord


SAFE_LABEL_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_identifier(value: str, fallback: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r"[^A-Za-z0-9_.:/-]", "_", value)
    value = value[:128]
    return value if SAFE_IDENTIFIER.fullmatch(value) else fallback


def _safe_labels(labels: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in labels.items():
        key = str(key)
        if not SAFE_LABEL_KEY.fullmatch(key):
            continue
        if any(part in key.lower().replace("-", "_") for part in (
            "password",
            "secret",
            "token",
            "authorization",
            "cookie",
            "credential",
            "private_key",
            "api_key",
            "access_key",
            "message_body",
            "phone",
            "email",
        )):
            continue
        value = str(value)
        if len(value) <= 256:
            result[key] = value
    return result


def incident_payload(
    incident: IncidentRecord,
    *,
    event_id: str,
) -> dict[str, Any]:
    labels = _safe_labels(incident.labels)
    alertname = _safe_identifier(labels.get("alertname", "observability_incident"), "observability_incident")
    service_id = _safe_identifier(incident.service, "observability")
    summary = str(
        incident.annotations.get("summary")
        or incident.annotations.get("title")
        or alertname
    ).strip()[:512]
    if not summary:
        summary = alertname
    payload = {
        "event_id": event_id,
        "schema_version": "kyyow.observability.incident.v1",
        "tenant_id": incident.tenant_id,
        "incident_id": str(incident.incident_id),
        "fingerprint": incident.alert_fingerprint,
        "alertname": alertname,
        "group_key": incident.group_key[:2048],
        "severity": incident.severity,
        "state": incident.state,
        "service_id": service_id,
        "environment": incident.environment,
        "host": incident.host[:128],
        "summary": summary,
        "labels": labels,
        "first_seen_at": _timestamp(incident.first_seen_at),
        "last_seen_at": _timestamp(incident.last_seen_at),
        "resolved_at": _timestamp(incident.resolved_at),
        "source_deployment": incident.source_deployment,
        "resource_version": incident.resource_version,
        "source_payload_hash": "sha256:" + _digest(
            {
                "fingerprint": incident.alert_fingerprint,
                "resource_version": incident.resource_version,
                "state": incident.state,
                "source_deployment": incident.source_deployment,
            }
        ),
        "observed_at": _timestamp(incident.updated_at),
        "correlation_id": incident.correlation_id,
    }
    payload["projection_hash"] = "sha256:" + _digest(payload)
    return payload


class ObservabilityOdooProjection:
    def __init__(self, pool: Any | None) -> None:
        self.pool = pool

    @property
    def enabled(self) -> bool:
        return self.pool is not None

    async def enqueue_incident(self, incident: IncidentRecord) -> dict[str, Any]:
        if self.pool is None:
            return {"status": "disabled"}
        event_id = f"alert-incident-{incident.incident_id}-v{incident.resource_version}"
        payload = incident_payload(incident, event_id=event_id)
        request_hash = _digest(payload)
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                existing = await connection.fetchrow(
                    """
                    SELECT id, payload_hash
                      FROM integration_event
                     WHERE original_event_id=$1
                    """,
                    event_id,
                )
                if existing:
                    if existing["payload_hash"] != request_hash:
                        raise RuntimeError("incident projection identity conflict")
                    return {"status": "duplicate", "event_id": event_id}
                event = await connection.fetchrow(
                    """
                    INSERT INTO integration_event (
                        idempotency_key, event_type, schema_version,
                        original_event_id, entity_key, source_system,
                        correlation_id, payload_json, payload_hash, state
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,'queued')
                    RETURNING id
                    """,
                    event_id,
                    "kyyow.observability.incident.state.v1",
                    "1.0",
                    event_id,
                    f"{incident.tenant_id}:{incident.incident_id}",
                    "kyyow-observability-alerts",
                    incident.correlation_id,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    request_hash,
                )
                if event is None:
                    raise RuntimeError("incident projection event was not created")
                delivery = await connection.fetchrow(
                    """
                    INSERT INTO odoo_result_delivery (
                        integration_event_id, standard_result_json,
                        result_public_id, originating_outbox_public_id,
                        request_hash, status
                    ) VALUES (
                        $1,$2::jsonb,$3,$4,$5,'PENDING'
                    )
                    ON CONFLICT (integration_event_id) DO NOTHING
                    RETURNING result_delivery_id
                    """,
                    event["id"],
                    json.dumps(
                        {
                            "operation": "observability.incidents.upsert",
                            "idempotency_key": event_id,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    uuid4(),
                    event_id,
                    request_hash,
                )
                return {
                    "status": "accepted",
                    "event_id": event_id,
                    "delivery_id": str(delivery["result_delivery_id"]) if delivery else None,
                }
