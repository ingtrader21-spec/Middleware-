"""Kyyow KPI and incident projections with durable Odoo delivery.

Prometheus, Alertmanager, exporters and collectors never write Odoo. They may
submit a bounded normalized observation to Middleware. This module owns the
canonical event, idempotency record, local monitoring projection and durable
Odoo result-delivery queue in one database transaction.
"""

from __future__ import annotations

from app.api_inputs import optional_header
from app.core.header_authority import CORRELATION_ID

from datetime import UTC, datetime
import hashlib
import json
import math
from typing import Any, Literal
from types import SimpleNamespace

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IdempotencyRecord, IntegrationEvent, OdooResultDelivery
from app.db.session import get_session
from app.monitoring.auth import READ_ROLES, Principal, require
from app.monitoring.routes import COLLECTOR, validate_source
from app.monitoring.backends import load_config
from app.monitoring.models import Digest, Environment, Identifier
from app.monitoring.store import Store, utc


router = APIRouter(prefix="/v1/observability", tags=["kyyow-observability-sync"])
SCHEMA_KPI = "kyyow.observability.kpi.v1"
SCHEMA_INCIDENT = "kyyow.observability.incident.v1"
KPI_OPERATION = "observability.kpis.create"
INCIDENT_OPERATION = "observability.incidents.upsert"
KPI_EVENT_TYPE = "kyyow.observability.kpi.snapshot.v1"
INCIDENT_EVENT_TYPE = "kyyow.observability.incident.state.v1"
SAFE_KEY = r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$"
PROHIBITED_DATA_KEYS = {"body", "logs", "traces", "raw_samples", "raw_logs", "raw_traces", "samples"}
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
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
)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KpiSnapshot(Input):
    event_id: Identifier
    schema_version: Literal["kyyow.observability.kpi.v1"] = "kyyow.observability.kpi.v1"
    tenant_id: Identifier
    metric_code: str = Field(min_length=1, max_length=96, pattern=r"^[a-z][a-z0-9_.:-]*$")
    service_id: Identifier
    environment: Environment
    period_reference: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    period_start: AwareDatetime
    period_end: AwareDatetime
    value: float = Field(allow_inf_nan=False)
    unit: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z][A-Za-z0-9_.%/-]{0,31}$")
    dimensions: dict[str, Any] = Field(default_factory=dict, max_length=32)
    source: str = Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
    source_revision: int = Field(ge=1)
    source_payload_hash: Digest
    observed_at: AwareDatetime
    reconciliation_state: Literal["accepted", "reconciled", "drifted", "pending"]
    correlation_id: Identifier
    projection_hash: Digest

    @model_validator(mode="after")
    def validate_snapshot(self):
        if self.period_end <= self.period_start:
            raise ValueError("period_end must be after period_start")
        for key, value in self.dimensions.items():
            if not isinstance(key, str) or __import__("re").fullmatch(SAFE_KEY, key) is None:
                raise ValueError("dimension key is unsafe")
            if key.lower().replace("-", "_") in PROHIBITED_DATA_KEYS or any(part in key.lower().replace("-", "_") for part in SENSITIVE_KEY_PARTS):
                raise ValueError("dimension key is sensitive")
            if isinstance(value, (dict, list, tuple)) or value is None:
                raise ValueError("dimension values must be scalar")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("dimension value is not finite")
            if not isinstance(value, (str, int, float, bool)) or (
                isinstance(value, str) and (not value or len(value) > 128)
            ):
                raise ValueError("dimension value is invalid")
        if len(json.dumps(self.dimensions, sort_keys=True, separators=(",", ":"))) > 8192:
            raise ValueError("dimensions exceed the storage budget")
        return self


class IncidentState(Input):
    event_id: Identifier
    schema_version: Literal["kyyow.observability.incident.v1"] = "kyyow.observability.incident.v1"
    tenant_id: Identifier
    incident_id: Identifier
    fingerprint: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:/-]+$")
    alertname: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    group_key: str = Field(min_length=1, max_length=2048)
    severity: Literal["critical", "high", "warning", "info"]
    state: Literal["firing", "acknowledged", "resolved", "inhibited", "silenced"]
    service_id: Identifier
    environment: Environment
    host: str = Field(default="", max_length=128)
    summary: str = Field(min_length=1, max_length=512)
    labels: dict[str, Any] = Field(default_factory=dict, max_length=32)
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    resolved_at: AwareDatetime | None = None
    source_deployment: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]+$")
    resource_version: int = Field(ge=1)
    source_payload_hash: Digest
    observed_at: AwareDatetime
    correlation_id: Identifier
    projection_hash: Digest

    @model_validator(mode="after")
    def validate_incident(self):
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at must not precede first_seen_at")
        if self.state == "resolved" and self.resolved_at is None:
            raise ValueError("resolved incidents require resolved_at")
        if self.state != "resolved" and self.resolved_at is not None:
            raise ValueError("only resolved incidents may have resolved_at")
        for key, value in self.labels.items():
            if not isinstance(key, str) or __import__("re").fullmatch(SAFE_KEY, key) is None:
                raise ValueError("label key is unsafe")
            if key.lower().replace("-", "_") in PROHIBITED_DATA_KEYS or any(part in key.lower().replace("-", "_") for part in SENSITIVE_KEY_PARTS):
                raise ValueError("label key is sensitive")
            if not isinstance(value, (str, int, float, bool)) or (
                isinstance(value, str) and len(value) > 256
            ):
                raise ValueError("label value is invalid")
        if len(json.dumps(self.labels, sort_keys=True, separators=(",", ":"))) > 8192:
            raise ValueError("labels exceed the storage budget")
        return self


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _projection_hash(document: dict[str, Any]) -> str:
    value = dict(document)
    value.pop("projection_hash", None)
    for key in ("period_start", "period_end", "observed_at", "first_seen_at", "last_seen_at", "resolved_at"):
        if isinstance(value.get(key), datetime):
            value[key] = _timestamp(value[key])
    return _digest(value)


def _safe_payload(body: KpiSnapshot | IncidentState, principal: Principal, idempotency_key: str) -> dict[str, Any]:
    payload = body.model_dump(mode="json")
    for key in ("period_start", "period_end", "observed_at", "first_seen_at", "last_seen_at", "resolved_at"):
        raw_value = payload.get(key)
        if raw_value is None:
            continue
        if isinstance(raw_value, datetime):
            payload[key] = _timestamp(raw_value)
        elif isinstance(raw_value, str):
            payload[key] = _timestamp(
                datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
            )
    if payload["tenant_id"] != principal.tenant:
        raise HTTPException(403, "tenant scope denied")
    if body.service_id not in principal.services:
        raise HTTPException(403, "collector service authority denied")
    expected = _projection_hash(payload)
    supplied = body.projection_hash.removeprefix("sha256:")
    if supplied != expected:
        raise HTTPException(422, "projection hash does not match the canonical payload")
    return payload


def _operation_scope(tenant: str, operation: str) -> str:
    tenant_digest = hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:16]
    return f"kyyow-observability:{tenant_digest}:{operation}"


def _entity_key(payload: dict[str, Any]) -> str:
    value = f"{payload['tenant_id']}:{payload.get('incident_id', payload.get('metric_code'))}"
    if len(value) <= 256:
        return value
    return f"{value[:191]}:{_digest(value)[:64]}"


async def _enqueue(
    session: AsyncSession,
    *,
    principal: Principal,
    operation: str,
    event_type: str,
    payload: dict[str, Any],
    idempotency_key: str,
    correlation_id: str,
    commit: bool = True,
) -> dict[str, Any]:
    # Transaction-scoped locks also cover the absent-row case. Lock the event
    # before the incident so concurrent replays and different incident versions
    # use a consistent order and see committed predecessors under READ COMMITTED.
    keys = ["event:" + payload["event_id"]]
    if event_type == INCIDENT_EVENT_TYPE:
        keys.append("incident:" + _entity_key(payload))
    for key in keys:
        lock_id = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big", signed=True)
        await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_id})
    request_hash = _digest(payload)
    key_hash = _digest({"tenant": principal.tenant, "key": idempotency_key})
    scope = _operation_scope(principal.tenant, operation)

    prior = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.scope == scope,
            IdempotencyRecord.key_hash == key_hash,
        )
    )
    if prior:
        if prior.request_hash != request_hash:
            raise HTTPException(409, "idempotency payload conflict")
        result = dict(prior.response)
        result["duplicate"] = True
        return result

    existing = await session.scalar(
        select(IntegrationEvent).where(
            IntegrationEvent.original_event_id == payload["event_id"]
        )
    )
    if existing:
        if existing.payload_hash != request_hash:
            raise HTTPException(409, "event payload conflict")
        delivery = await session.scalar(
            select(OdooResultDelivery).where(
                OdooResultDelivery.integration_event_id == existing.id
            )
        )
        result = {
            "status": "accepted",
            "event_id": payload["event_id"],
            "operation": operation,
            "correlation_id": correlation_id,
            "delivery_id": str(delivery.result_delivery_id) if delivery else None,
            "odoo_sync_state": delivery.status.lower() if delivery else "unknown",
        }
        result["duplicate"] = True
        return result

    if event_type == INCIDENT_EVENT_TYPE:
        latest = await session.scalar(
            select(func.max(IntegrationEvent.payload_json["resource_version"].as_integer())).where(
                IntegrationEvent.event_type == INCIDENT_EVENT_TYPE,
                IntegrationEvent.entity_key == _entity_key(payload),
            )
        )
        if latest is not None and payload["resource_version"] <= latest:
            raise HTTPException(409, "incident resource version is stale")

    event = IntegrationEvent(
        idempotency_key=idempotency_key,
        event_type=event_type,
        schema_version="1.0",
        original_event_id=payload["event_id"],
        entity_key=_entity_key(payload),
        source_system="kyyow-observability",
        correlation_id=correlation_id,
        payload_json=payload,
        payload_hash=request_hash,
        state="queued",
    )
    session.add(event)
    await session.flush()
    delivery = OdooResultDelivery(
        integration_event_id=event.id,
        standard_result_json={
            "operation": operation,
            "idempotency_key": idempotency_key,
        },
        originating_outbox_public_id=payload["event_id"],
        request_hash=request_hash,
        status="PENDING",
    )
    session.add(delivery)
    await session.flush()
    result = {
        "status": "accepted",
        "event_id": payload["event_id"],
        "operation": operation,
        "correlation_id": correlation_id,
        "delivery_id": str(delivery.result_delivery_id),
        "odoo_sync_state": "pending",
        "duplicate": False,
    }
    session.add(
        IdempotencyRecord(
            scope=scope,
            key_hash=key_hash,
            request_hash=request_hash,
            response=result,
            status_code=status.HTTP_202_ACCEPTED,
            event_id=event.id,
        )
    )
    if commit:
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409, "observability event identity already exists") from None
    return result


@router.post("/kpis", status_code=status.HTTP_202_ACCEPTED)
async def submit_kpi(
    request: Request,
    body: KpiSnapshot,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=180),
    x_correlation_id: str = Header(..., alias="X-Correlation-ID", min_length=1, max_length=180),
    principal: Principal = Depends(require("observability.kpis.write", READ_ROLES | COLLECTOR)),
    session: AsyncSession = Depends(get_session),
    config: dict = Depends(load_config),
):
    validate_source(config, principal, SimpleNamespace(
        service_id=body.service_id, environment=body.environment,
        source_deployment=body.source if isinstance(body, KpiSnapshot) else body.source_deployment,
        observed_at=body.observed_at,
    ))
    if body.correlation_id != x_correlation_id:
        raise HTTPException(409, "correlation binding conflict")
    payload = _safe_payload(body, principal, idempotency_key)
    store = Store(session)
    key = f"{body.environment}:{body.service_id}:{body.metric_code}:{body.period_reference}"

    async def action(_operation_id):
        result = await _enqueue(
            session,
            principal=principal,
            operation=KPI_OPERATION,
            event_type=KPI_EVENT_TYPE,
            payload=payload,
            idempotency_key=idempotency_key,
            correlation_id=x_correlation_id,
            commit=False,
        )
        if result.get("duplicate"):
            return result
        await store.put(
            principal.tenant,
            "kpi",
            key,
            {
                **payload,
                "projection_hash": f"sha256:{body.projection_hash.removeprefix('sha256:')}",
            },
            service=body.service_id,
            environment=body.environment,
            source=body.source,
            sequence=body.source_revision,
            observed_at=body.observed_at,
        )
        await store.event(
            principal.tenant,
            "kpi.accepted",
            {
                "event_id": body.event_id,
                "metric_code": body.metric_code,
                "service_id": body.service_id,
                "source_revision": body.source_revision,
            },
        )
        await session.commit()
        return result

    return await action("")


@router.post("/incidents", status_code=status.HTTP_202_ACCEPTED)
async def submit_incident(
    request: Request,
    body: IncidentState,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=180),
    x_correlation_id: str = Header(..., alias="X-Correlation-ID", min_length=1, max_length=180),
    principal: Principal = Depends(require("observability.incidents.write", READ_ROLES | COLLECTOR)),
    session: AsyncSession = Depends(get_session),
    config: dict = Depends(load_config),
):
    validate_source(config, principal, SimpleNamespace(
        service_id=body.service_id, environment=body.environment,
        source_deployment=body.source if isinstance(body, KpiSnapshot) else body.source_deployment,
        observed_at=body.observed_at,
    ))
    if body.correlation_id != x_correlation_id:
        raise HTTPException(409, "correlation binding conflict")
    payload = _safe_payload(body, principal, idempotency_key)
    return await _enqueue(
        session,
        principal=principal,
        operation=INCIDENT_OPERATION,
        event_type=INCIDENT_EVENT_TYPE,
        payload=payload,
        idempotency_key=idempotency_key,
        correlation_id=x_correlation_id,
    )


@router.get("/kpis")
async def list_kpis(
    request: Request,
    service_id: str | None = Query(default=None, max_length=128),
    environment: Environment | None = None,
    cursor: str = Query(default="", max_length=512),
    limit: int = Query(default=100, ge=1, le=200),
    principal: Principal = Depends(require("observability.kpis.read")),
    session: AsyncSession = Depends(get_session),
):
    rows = await Store(session).list(
        principal.tenant,
        "kpi",
        service=service_id,
        environment=environment,
        cursor=cursor,
        limit=limit + 1,
    )
    more = len(rows) > limit
    rows = rows[:limit]
    return {
        "items": [
            {
                "resource_id": row["resource_key"],
                "service_id": row["service_id"],
                "environment": row["environment"],
                "observed_at": utc(row["observed_at"]).isoformat(),
                "revision": row["revision"],
                **row["payload"],
            }
            for row in rows
        ],
        "next_cursor": rows[-1]["resource_key"] if more else None,
        "correlation_id": optional_header(request, CORRELATION_ID, minimum=1, maximum=180),
    }


@router.get("/kpis/{event_id}")
async def get_kpi(
    event_id: str,
    request: Request,
    principal: Principal = Depends(require("observability.kpis.read")),
    session: AsyncSession = Depends(get_session),
):
    event = await session.scalar(
        select(IntegrationEvent).where(
            IntegrationEvent.original_event_id == event_id,
            IntegrationEvent.source_system == "kyyow-observability",
            IntegrationEvent.event_type == KPI_EVENT_TYPE,
        )
    )
    if event is None or event.payload_json.get("tenant_id") != principal.tenant:
        raise HTTPException(404, "KPI snapshot not found")
    delivery = await session.scalar(
        select(OdooResultDelivery).where(OdooResultDelivery.integration_event_id == event.id)
    )
    return {
        "data": event.payload_json,
        "event_id": event.original_event_id,
        "odoo_sync_state": delivery.status.lower() if delivery else "unknown",
        "delivery_id": str(delivery.result_delivery_id) if delivery else None,
        "correlation_id": optional_header(request, CORRELATION_ID, minimum=1, maximum=180),
    }


@router.get("/odoo-sync")
async def odoo_sync_status(
    request: Request,
    principal: Principal = Depends(require("observability.kpis.read")),
    session: AsyncSession = Depends(get_session),
):
    rows = (
        await session.execute(
            select(OdooResultDelivery.status, func.count())
            .join(IntegrationEvent, IntegrationEvent.id == OdooResultDelivery.integration_event_id)
            .where(
                IntegrationEvent.source_system == "kyyow-observability",
                IntegrationEvent.payload_json["tenant_id"].as_string() == principal.tenant,
            )
            .group_by(OdooResultDelivery.status)
        )
    ).all()
    latest = await session.scalar(
        select(IntegrationEvent)
        .where(
            IntegrationEvent.source_system == "kyyow-observability",
            IntegrationEvent.payload_json["tenant_id"].as_string() == principal.tenant,
        )
        .order_by(IntegrationEvent.created_at.desc())
    )
    return {
        "status": "ready",
        "tenant_id": principal.tenant,
        "delivery_counts": {str(status_value).lower(): count for status_value, count in rows},
        "latest_event_id": latest.original_event_id if latest else None,
        "latest_event_created_at": utc(latest.created_at).isoformat() if latest else None,
        "correlation_id": optional_header(request, CORRELATION_ID, minimum=1, maximum=180),
    }



def is_observability_sync_route(request: Request) -> bool:
    """Return true only for routes authenticated by this router."""
    from fastapi.routing import APIRoute

    return any(
        isinstance(route, APIRoute)
        and request.method in (route.methods or set())
        and route.path_regex.fullmatch(request.url.path)
        for route in router.routes
    )
