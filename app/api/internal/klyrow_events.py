"""Authenticated Klyrow business-event ingress backed by the durable inbox."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from copy import deepcopy
from datetime import UTC, date, datetime
from typing import Any, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.internal.telnexa_events import _read_secret, _runtime_setting
from app.db.session import get_session
from app.models import EventEnvelope
from app.storage import (
    KLYROW_ODOO_PROJECTION_DESTINATION,
    ReplayConflict,
    canonical_payload_sha256,
    event_ledger_hash,
)


PATH = "/api/v1/events/klyrow"
SOURCE = "klyrow"
PRODUCER_CLIENT_ID = "klyrow-gateway"
MAX_EVENT_ID_LENGTH = 200
KlyrowEventType = Literal[
    "klyrow.tenant.created",
    "klyrow.tenant.updated",
    "klyrow.subscription.changed",
    "klyrow.usage.daily",
    "klyrow.kpi.daily",
    "klyrow.campaign.summary",
    "klyrow.domain.status",
    "klyrow.provider.health",
    "klyrow.account.held",
    "klyrow.account.released",
]

KLYROW_EVENT_TYPES = frozenset(
    {
        "klyrow.tenant.created",
        "klyrow.tenant.updated",
        "klyrow.subscription.changed",
        "klyrow.usage.daily",
        "klyrow.kpi.daily",
        "klyrow.campaign.summary",
        "klyrow.domain.status",
        "klyrow.provider.health",
        "klyrow.account.held",
        "klyrow.account.released",
    }
)

KLYROW_REQUIRED_HEADERS = (
    {
        "name": "Authorization",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "minLength": 8, "maxLength": 8192},
    },
    {
        "name": "X-Event-Id",
        "in": "header",
        "required": True,
        "schema": {
            "type": "string",
            "pattern": r"^evt_[A-Za-z0-9_-]+$",
            "maxLength": MAX_EVENT_ID_LENGTH,
        },
    },
    {
        "name": "X-Timestamp",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "pattern": r"^[0-9]{1,12}$"},
    },
    {
        "name": "X-Signature",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "pattern": r"^sha256=[0-9a-f]{64}$"},
    },
    {
        "name": "Idempotency-Key",
        "in": "header",
        "required": True,
        "schema": {
            "type": "string",
            "minLength": 5,
            "maxLength": MAX_EVENT_ID_LENGTH,
        },
    },
    {
        "name": "X-Correlation-Id",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "minLength": 1, "maxLength": 200},
    },
)

router = APIRouter(tags=["klyrow-events"])


class TenantEventData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(min_length=1, max_length=200)
    name: str | None = Field(default=None, max_length=200)
    organization_id: str | None = Field(default=None, max_length=200)
    enabled: bool


class SubscriptionChangedData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subscription_id: str = Field(min_length=1, max_length=200)
    status: str = Field(min_length=1, max_length=50)
    plan_id: str | None = Field(default=None, max_length=200)
    price_id: str | None = Field(default=None, max_length=200)
    version: int = Field(ge=1)
    effective_at: AwareDatetime


class DailyUsageData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    date: date
    unit: Literal["accepted_message"]
    quantity: int = Field(ge=0)
    snapshot_at: AwareDatetime


class DailyKpiData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    date: date
    accepted: int = Field(ge=0)
    delivered: int = Field(ge=0)
    bounced: int = Field(ge=0)
    complained: int = Field(ge=0)
    snapshot_at: AwareDatetime


class CampaignSummaryData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    campaign_id: str = Field(min_length=1, max_length=200)
    campaign_version: int = Field(ge=1)
    status: Literal["COMPLETED", "CANCELLED", "FAILED"]
    audience_count: int = Field(ge=0)
    delivered_count: int = Field(ge=0)
    suppressed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)


class DomainStatusData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_id: str = Field(min_length=1, max_length=200)
    domain: str = Field(min_length=1, max_length=253)
    status: str = Field(min_length=1, max_length=50)
    verified_at: AwareDatetime | None = None


class ProviderHealthData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(min_length=1, max_length=100)
    status: Literal["HEALTHY", "DEGRADED", "UNAVAILABLE"]
    checked_at: AwareDatetime
    reason_code: str | None = Field(default=None, max_length=100)


class AccountStateData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["HELD", "RELEASED"]
    reason: str = Field(min_length=1, max_length=300)
    changed_at: AwareDatetime


KLYROW_EVENT_DATA_MODELS: dict[str, type[BaseModel]] = {
    "klyrow.tenant.created": TenantEventData,
    "klyrow.tenant.updated": TenantEventData,
    "klyrow.subscription.changed": SubscriptionChangedData,
    "klyrow.usage.daily": DailyUsageData,
    "klyrow.kpi.daily": DailyKpiData,
    "klyrow.campaign.summary": CampaignSummaryData,
    "klyrow.domain.status": DomainStatusData,
    "klyrow.provider.health": ProviderHealthData,
    "klyrow.account.held": AccountStateData,
    "klyrow.account.released": AccountStateData,
}


class KlyrowEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(
        pattern=r"^evt_[A-Za-z0-9_-]+$",
        min_length=5,
        max_length=MAX_EVENT_ID_LENGTH,
    )
    type: KlyrowEventType
    version: Literal[1]
    source: Literal["klyrow"]
    tenant_id: str = Field(min_length=1, max_length=200)
    correlation_id: str = Field(min_length=1, max_length=200)
    causation_id: str | None = Field(default=None, min_length=1, max_length=200)
    occurred_at: AwareDatetime
    data: dict[str, object]

    @field_validator("occurred_at")
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_event_data(self) -> "KlyrowEvent":
        model = KLYROW_EVENT_DATA_MODELS[self.type]
        self.data = model.model_validate(self.data).model_dump(mode="json")
        if (
            self.type.startswith("klyrow.tenant.")
            and self.data["tenant_id"] != self.tenant_id
        ):
            raise ValueError("event tenant does not match data tenant")
        if self.type == "klyrow.account.held" and self.data["status"] != "HELD":
            raise ValueError("held event must contain HELD status")
        if self.type == "klyrow.account.released" and self.data["status"] != "RELEASED":
            raise ValueError("released event must contain RELEASED status")
        return self


class KlyrowEventAck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: str = Field(pattern=r"^op_[a-f0-9]{32}$")
    status: Literal["ACCEPTED"] = "ACCEPTED"


def klyrow_event_schema() -> dict[str, Any]:
    """Return the exact wire schema, including event-specific data contracts."""

    schema = deepcopy(KlyrowEvent.model_json_schema())
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://contracts.codestra.co/klyrow/event-v1.schema.json"
    schema["title"] = "Klyrow business event v1"
    schema["required"] = [
        "id",
        "type",
        "version",
        "source",
        "tenant_id",
        "correlation_id",
        "occurred_at",
        "data",
    ]
    definitions = schema.setdefault("$defs", {})
    conditions: list[dict[str, Any]] = []
    for event_type, model in KLYROW_EVENT_DATA_MODELS.items():
        name = model.__name__
        data_schema = deepcopy(model.model_json_schema())
        definitions.update(data_schema.pop("$defs", {}))
        if name not in definitions:
            if model is DailyUsageData:
                data_schema["required"] = [
                    "date",
                    "unit",
                    "quantity",
                    "snapshot_at",
                ]
            definitions[name] = data_schema
        conditions.append(
            {
                "if": {
                    "properties": {"type": {"const": event_type}},
                    "required": ["type"],
                },
                "then": {"properties": {"data": {"$ref": f"#/$defs/{name}"}}},
            }
        )
    schema["allOf"] = conditions
    return schema


def operation_id_for_klyrow_event(event_id: str) -> str:
    digest = hashlib.sha256(f"{SOURCE}\0{event_id}".encode("utf-8")).hexdigest()
    return "op_" + digest[:32]


def _one_header(request: Request, name: str) -> str:
    raw_name = name.lower().encode("ascii")
    values = [
        value.decode("latin-1")
        for key, value in request.scope.get("headers", [])
        if key == raw_name
    ]
    if len(values) != 1 or not values[0]:
        raise HTTPException(401, "missing_or_duplicate_klyrow_header")
    return values[0]


async def _read_limited_body(request: Request, maximum: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > maximum:
                raise HTTPException(413, "klyrow_event_too_large")
        except ValueError as exc:
            raise HTTPException(400, "invalid_content_length") from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            raise HTTPException(413, "klyrow_event_too_large")
    return bytes(body)


def _authenticate(request: Request, body: bytes) -> tuple[str, str, str, str]:
    authorization = _one_header(request, "Authorization")
    scheme, separator, supplied_api_key = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not supplied_api_key:
        raise HTTPException(401, "invalid_klyrow_authorization")
    api_key = _read_secret(
        _runtime_setting(request, "klyrow_event_api_key", ""),
        _runtime_setting(request, "klyrow_event_api_key_file", ""),
        "klyrow_api_key_unavailable",
    )
    if not hmac.compare_digest(supplied_api_key.encode(), api_key):
        raise HTTPException(401, "invalid_klyrow_authorization")

    event_id = _one_header(request, "X-Event-Id")
    timestamp = _one_header(request, "X-Timestamp")
    supplied_signature = _one_header(request, "X-Signature")
    idempotency_key = _one_header(request, "Idempotency-Key")
    if (
        len(event_id) > MAX_EVENT_ID_LENGTH
        or not event_id.isascii()
        or not event_id.startswith("evt_")
        or any(
            char
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            for char in event_id
        )
    ):
        raise HTTPException(401, "invalid_klyrow_event_id")
    if not timestamp.isascii() or not timestamp.isdecimal() or len(timestamp) > 12:
        raise HTTPException(401, "invalid_klyrow_timestamp")
    secret = _read_secret(
        _runtime_setting(request, "klyrow_event_hmac_secret", ""),
        _runtime_setting(request, "klyrow_event_hmac_secret_file", ""),
        "klyrow_hmac_secret_unavailable",
    )
    if len(secret) < 32:
        raise HTTPException(503, "klyrow_hmac_secret_invalid")
    canonical = f"{timestamp}\n{event_id}\n{SOURCE}\n".encode("utf-8") + body
    expected = "sha256=" + hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied_signature):
        raise HTTPException(401, "invalid_klyrow_signature")
    return event_id, timestamp, idempotency_key, supplied_signature


def _signature_is_fresh(request: Request, timestamp: str) -> bool:
    try:
        ttl = int(
            cast(
                int | str,
                _runtime_setting(request, "klyrow_event_signature_ttl_seconds", 300),
            )
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(503, "klyrow_signature_configuration_invalid") from exc
    if ttl <= 0:
        raise HTTPException(503, "klyrow_signature_configuration_invalid")
    return abs(time.time() - int(timestamp)) <= ttl


def _parse_event(body: bytes) -> KlyrowEvent:
    try:
        raw = json.loads(body)
        if not isinstance(raw, dict):
            raise ValueError("event must be a JSON object")
        return KlyrowEvent.model_validate(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "invalid_klyrow_event") from exc


def _bounded_trace(request: Request) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, maximum in (("traceparent", 55), ("tracestate", 512)):
        value = request.headers.get(name, "")
        if (
            value
            and value.isascii()
            and "\r" not in value
            and "\n" not in value
            and len(value) <= maximum
        ):
            result[name] = value
    return result


def _normalized_envelope(event: KlyrowEvent, request: Request) -> EventEnvelope:
    operation_id = operation_id_for_klyrow_event(event.id)
    trace_context = _bounded_trace(request)
    return EventEnvelope(
        event_id=event.id,
        event_type="codestra." + event.type,
        event_version="1.0",
        occurred_at=event.occurred_at,
        received_at=datetime.now(UTC),
        source=PRODUCER_CLIENT_ID,
        tenant_id=event.tenant_id,
        correlation_id=event.correlation_id,
        causation_id=event.causation_id or event.id,
        idempotency_key=event.id,
        payload={
            "operation_id": operation_id,
            "source_event": event.model_dump(mode="json"),
            "trace_context": trace_context,
        },
        metadata={
            "operation_id": operation_id,
            "wire_event_type": event.type,
            "wire_source": SOURCE,
        },
    )


async def _accept_with_sql(
    db: AsyncSession,
    envelope: EventEnvelope,
    body_sha256: str,
) -> bool:
    """Compatibility path for entrypoints not composed with Runtime yet."""

    payload = envelope.model_dump(mode="json")
    semantic_sha256 = canonical_payload_sha256(payload)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
        {"value": f"{PRODUCER_CLIENT_ID}:{envelope.event_id}"},
    )
    existing = (
        (
            await db.execute(
                text(
                    "SELECT tenant_id,event_type,idempotency_key,payload,body_sha256 "
                    "FROM middleware_inbox "
                    "WHERE source_client_id=:source AND event_id=:event_id FOR UPDATE"
                ),
                {"source": PRODUCER_CLIENT_ID, "event_id": envelope.event_id},
            )
        )
        .mappings()
        .first()
    )
    if existing:
        if not hmac.compare_digest(str(existing["body_sha256"]), body_sha256):
            raise HTTPException(409, "klyrow_event_replay_conflict")
        # A matching retry repairs a missing projection from the immutable
        # accepted inbox payload. The unique outbox key makes this safe under
        # concurrent retries and preserves a previously completed row.
        persisted_payload = existing["payload"]
        if not isinstance(persisted_payload, str):
            persisted_payload = json.dumps(
                dict(persisted_payload),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        await db.execute(
            text("""INSERT INTO middleware_outbox
              (tenant_id,destination,event_type,payload,idempotency_key)
              VALUES (:tenant,:destination,:event_type,CAST(:payload AS jsonb),:idempotency)
              ON CONFLICT (tenant_id,destination,idempotency_key) DO NOTHING"""),
            {
                "tenant": existing["tenant_id"],
                "destination": KLYROW_ODOO_PROJECTION_DESTINATION,
                "event_type": existing["event_type"],
                "payload": persisted_payload,
                "idempotency": existing["idempotency_key"],
            },
        )
        await db.commit()
        return True

    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
        {"value": f"event-ledger:{envelope.tenant_id}"},
    )
    previous = (
        (
            await db.execute(
                text(
                    "SELECT tenant_sequence,entry_hash FROM middleware_event_ledger "
                    "WHERE tenant_id=:tenant ORDER BY tenant_sequence DESC LIMIT 1"
                ),
                {"tenant": envelope.tenant_id},
            )
        )
        .mappings()
        .first()
    )
    sequence = int(previous["tenant_sequence"]) + 1 if previous else 1
    previous_hash = str(previous["entry_hash"]) if previous else "0" * 64
    entry_hash = event_ledger_hash(
        tenant_id=envelope.tenant_id,
        tenant_sequence=sequence,
        event_id=envelope.event_id,
        semantic_sha256=semantic_sha256,
        previous_entry_hash=previous_hash,
    )
    await db.execute(
        text("""INSERT INTO middleware_inbox
          (event_id,tenant_id,source_client_id,event_type,body_sha256,semantic_sha256,
           idempotency_key,correlation_id,payload,received_at,status)
          VALUES (:event_id,:tenant,:source,:event_type,:body_hash,:semantic_hash,
                  :idempotency,:correlation,CAST(:payload AS jsonb),now(),'accepted')"""),
        {
            "event_id": envelope.event_id,
            "tenant": envelope.tenant_id,
            "source": PRODUCER_CLIENT_ID,
            "event_type": envelope.event_type,
            "body_hash": body_sha256,
            "semantic_hash": semantic_sha256,
            "idempotency": envelope.idempotency_key,
            "correlation": envelope.correlation_id,
            "payload": payload_json,
        },
    )
    await db.execute(
        text("""INSERT INTO middleware_event_ledger
          (tenant_id,tenant_sequence,event_id,event_type,event_version,source_client_id,
           correlation_id,causation_id,idempotency_key,semantic_sha256,
           previous_entry_hash,entry_hash,payload)
          VALUES (:tenant,:sequence,:event_id,:event_type,:event_version,:source,
                  :correlation,:causation,:idempotency,:semantic_hash,
                  :previous_hash,:entry_hash,CAST(:payload AS jsonb))"""),
        {
            "tenant": envelope.tenant_id,
            "sequence": sequence,
            "event_id": envelope.event_id,
            "event_type": envelope.event_type,
            "event_version": envelope.event_version,
            "source": PRODUCER_CLIENT_ID,
            "correlation": envelope.correlation_id,
            "causation": envelope.causation_id,
            "idempotency": envelope.idempotency_key,
            "semantic_hash": semantic_sha256,
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
            "payload": payload_json,
        },
    )
    await db.execute(
        text("""INSERT INTO middleware_outbox
          (tenant_id,destination,event_type,payload,idempotency_key)
          VALUES (:tenant,:destination,:event_type,CAST(:payload AS jsonb),:idempotency)"""),
        {
            "tenant": envelope.tenant_id,
            "destination": KLYROW_ODOO_PROJECTION_DESTINATION,
            "event_type": envelope.event_type,
            "payload": payload_json,
            "idempotency": envelope.idempotency_key,
        },
    )
    await db.commit()
    return False


async def _accept(
    request: Request,
    db: AsyncSession,
    envelope: EventEnvelope,
    body_sha256: str,
) -> bool:
    runtime = getattr(getattr(request.scope.get("app"), "state", None), "runtime", None)
    inbox = getattr(runtime, "inbox", None)
    if inbox is None:
        return await _accept_with_sql(db, envelope, body_sha256)
    try:
        result = await inbox.accept(
            envelope,
            producer_client_id=PRODUCER_CLIENT_ID,
            body_sha256=body_sha256,
            semantic_sha256=canonical_payload_sha256(envelope.model_dump(mode="json")),
            deduplication_sha256=body_sha256,
            destination=KLYROW_ODOO_PROJECTION_DESTINATION,
        )
    except ReplayConflict as exc:
        raise HTTPException(409, "klyrow_event_replay_conflict") from exc
    return bool(result.duplicate)


@router.post(
    PATH,
    status_code=202,
    response_model=KlyrowEventAck,
    openapi_extra={
        "security": [{"klyrowBearerApiKey": []}],
        "parameters": list(KLYROW_REQUIRED_HEADERS),
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": klyrow_event_schema()}},
        },
    },
)
async def receive_klyrow_event(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    if not _runtime_setting(request, "klyrow_event_ingress_enabled", False):
        raise HTTPException(503, "klyrow_event_ingress_disabled")
    try:
        request_max = int(
            cast(
                int | str,
                _runtime_setting(
                    request,
                    "klyrow_event_request_max_bytes",
                    1_048_576,
                ),
            )
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(503, "klyrow_request_configuration_invalid") from exc
    if request_max <= 0:
        raise HTTPException(503, "klyrow_request_configuration_invalid")
    body = await _read_limited_body(request, request_max)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type != "application/json":
        raise HTTPException(415, "application_json_required")

    event_id, timestamp, idempotency_key, _ = _authenticate(request, body)
    if not _signature_is_fresh(request, timestamp):
        raise HTTPException(401, "expired_klyrow_signature")
    event = _parse_event(body)
    correlation_id = _one_header(request, "X-Correlation-Id")
    if (
        event.id != event_id
        or event.id != idempotency_key
        or event.correlation_id != correlation_id
    ):
        raise HTTPException(409, "klyrow_header_body_binding_mismatch")

    envelope = _normalized_envelope(event, request)
    await _accept(request, db, envelope, hashlib.sha256(body).hexdigest())
    return {
        "operation_id": operation_id_for_klyrow_event(event.id),
        "status": "ACCEPTED",
    }
