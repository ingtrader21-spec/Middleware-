"""Authenticated, durable Telnexa delivery-event ingress.

Telnexa owns the wire contract for this callback.  This endpoint deliberately
does not translate the event through the generic Codestra event envelope: the
caller's private mTLS identity and the raw body are authenticated first and
then projected into the durable communications read model that Odoo already
polls.

Callbacks that arrive before their communication message exist stay in the
durable inbox as ``retry`` and are reconciled, in ``occurred_at`` order, by the
next callback for the same message or by the bounded reconciliation sweep.
After ``TELNEXA_EVENT_RECONCILE_MAX_ATTEMPTS`` they become ``dead_letter``.

``POST /api/v1/events/telnexa/verify`` runs the identical trust chain for
``synthetic-`` events without a database dependency, so callback trust can be
certified while live SMS stays disabled.  Synthetic events are refused by the
effectful ingress.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.communications import CommunicationMessage, MessageStatus
from app.core.config import settings
from app.db.session import get_session
from app.telnexa_callback_identity import (
    CLIENT_CERTIFICATE_HEADER_CONTRACT,
    TelnexaCallbackIdentity,
    trust_config,
    verify_callback_identity,
)


PATH = "/api/v1/events/telnexa"
VERIFY_PATH = "/api/v1/events/telnexa/verify"
SYNTHETIC_EVENT_PREFIX = "synthetic-"
SOURCE = "telnexa"
EVENT_VERSION = "1.0"
SCHEMA_VERSION = "1.0"
MAX_EVENT_ID_LENGTH = 200
TelnexaEventType = Literal[
    "sms.message.delivered.v1",
    "sms.message.failed.v1",
    "sms.message.status.v1",
    "sms.message.reconciled.v1",
]
TelnexaStatus = Literal[
    "accepted",
    "queued",
    "dispatched",
    "delivered",
    "failed",
    "cancelled",
    "suppressed",
    "expired",
    "indeterminate",
]

TELNEXA_EVENT_TYPES = frozenset(
    {
        "sms.message.delivered.v1",
        "sms.message.failed.v1",
        "sms.message.status.v1",
        "sms.message.reconciled.v1",
    }
)

TELNEXA_REQUIRED_HEADERS = (
    {
        "name": "Authorization",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "minLength": 8, "maxLength": 8192},
        "description": (
            "Bearer shared API key; the caller must also present the private "
            "Telnexa mTLS client identity."
        ),
    },
    CLIENT_CERTIFICATE_HEADER_CONTRACT,
    {
        "name": "X-Event-Id",
        "in": "header",
        "required": True,
        "schema": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_EVENT_ID_LENGTH,
        },
    },
    {
        "name": "X-Timestamp",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "pattern": "^[0-9]{1,12}$"},
    },
    {
        "name": "X-Signature",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "pattern": "^sha256=[0-9a-f]{64}$"},
    },
    {
        "name": "Idempotency-Key",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "minLength": 1, "maxLength": 255},
    },
)

router = APIRouter(tags=["telnexa-events"])
LOGGER = logging.getLogger(__name__)


class TelnexaDeliveryEvent(BaseModel):
    """The exact provider callback body, with no generic-envelope fields."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(
        min_length=1,
        max_length=MAX_EVENT_ID_LENGTH,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    event_type: TelnexaEventType
    event_version: str = Field(pattern=r"^1\.0$")
    schema_version: str = Field(pattern=r"^1\.0$")
    timestamp: str = Field(pattern=r"^[0-9]{1,12}$")
    occurred_at: datetime
    tenant_id: str = Field(min_length=1, max_length=200)
    correlation_id: str = Field(min_length=1, max_length=200)
    idempotency_key: str = Field(min_length=1, max_length=255)
    message_id: UUID
    provider_reference: str | None = Field(default=None, max_length=998)
    status: TelnexaStatus
    provider_status: str = Field(min_length=1, max_length=120)
    failure_code: str | None = Field(default=None, max_length=120)
    failure_message: str | None = Field(default=None, max_length=2000)

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, value: object) -> str:
        # Telnexa's worker currently serializes this value as a string.  The
        # integer form is accepted as a transport-compatible JSON equivalent
        # because the signed header remains the authoritative byte-for-byte
        # binding.
        if isinstance(value, bool):
            raise ValueError("timestamp must be unix seconds")
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            return value
        raise ValueError("timestamp must be unix seconds")

    @field_validator("occurred_at")
    @classmethod
    def require_aware_occurred_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_event_semantics(self) -> "TelnexaDeliveryEvent":
        if self.event_type == "sms.message.delivered.v1" and self.status != "delivered":
            raise ValueError("delivered events must carry delivered status")
        if self.event_type == "sms.message.failed.v1" and self.status != "failed":
            raise ValueError("failed events must carry failed status")
        return self


class TelnexaDeliveryAck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: Literal[True] = True
    duplicate: bool
    event_id: str
    status: Literal["complete", "dead_letter"] = "complete"
    message_id: UUID
    communication_status: MessageStatus | None = None
    reconciled_event_ids: list[str] = Field(default_factory=list)


class TelnexaCallbackIdentityEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    certificate_sha256: str
    certificate_serial: str
    uri_san: str
    not_valid_after: datetime


class TelnexaSyntheticVerification(BaseModel):
    """No-effect proof that a synthetic callback passes the full trust chain."""

    model_config = ConfigDict(extra="forbid")

    verified: Literal[True] = True
    effect: Literal["none"] = "none"
    persisted: Literal[False] = False
    event_id: str
    event_type: TelnexaEventType
    message_id: UUID
    tenant_id: str
    status: TelnexaStatus
    signature: Literal["valid"] = "valid"
    fresh: Literal[True] = True
    identity: TelnexaCallbackIdentityEvidence


def _runtime_setting(request: Request, name: str, default: object = None) -> object:
    """Resolve the active factory's setting, falling back to core settings."""

    app = request.scope.get("app")
    runtime = getattr(getattr(app, "state", None), "runtime", None)
    runtime_settings = getattr(runtime, "settings", None)
    if runtime_settings is not None and hasattr(runtime_settings, name):
        return getattr(runtime_settings, name)
    return getattr(settings, name, default)


def _one_header(request: Request, name: str) -> str:
    raw_name = name.lower().encode("ascii")
    values = [
        value.decode("latin-1")
        for key, value in request.scope.get("headers", [])
        if key == raw_name
    ]
    if len(values) != 1 or not values[0]:
        raise HTTPException(401, "missing_or_duplicate_telnexa_header")
    return values[0]


def _read_secret(value: object, filename: object, error_code: str) -> bytes:
    value = str(value or "")
    filename = str(filename or "")
    if filename:
        path = Path(filename)
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or path.stat().st_mode & 0o077
        ):
            raise HTTPException(503, error_code)
        try:
            secret = path.read_bytes().strip()
        except OSError as exc:
            raise HTTPException(503, error_code) from exc
    else:
        secret = value.encode()
    if not secret:
        raise HTTPException(503, error_code)
    return secret


def _authenticate(request: Request, body: bytes) -> tuple[str, str, str, str]:
    authorization = _one_header(request, "Authorization")
    scheme, separator, supplied_api_key = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not supplied_api_key:
        raise HTTPException(401, "invalid_telnexa_authorization")
    api_key = _read_secret(
        _runtime_setting(request, "telnexa_event_api_key", ""),
        _runtime_setting(request, "telnexa_event_api_key_file", ""),
        "telnexa_api_key_unavailable",
    )
    if not hmac.compare_digest(supplied_api_key.encode(), api_key):
        raise HTTPException(401, "invalid_telnexa_authorization")

    event_id = _one_header(request, "X-Event-Id")
    timestamp = _one_header(request, "X-Timestamp")
    supplied_signature = _one_header(request, "X-Signature")
    idempotency_key = _one_header(request, "Idempotency-Key")
    if (
        not event_id
        or len(event_id) > MAX_EVENT_ID_LENGTH
        or not event_id.isascii()
        or not event_id[0].isalnum()
        or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-" for char in event_id)
    ):
        raise HTTPException(401, "invalid_telnexa_event_id")
    if not timestamp.isascii() or not timestamp.isdecimal() or len(timestamp) > 12:
        raise HTTPException(401, "invalid_telnexa_timestamp")
    secret = _read_secret(
        _runtime_setting(request, "telnexa_event_hmac_secret", ""),
        _runtime_setting(request, "telnexa_event_hmac_secret_file", ""),
        "telnexa_hmac_secret_unavailable",
    )
    canonical = (
        f"{timestamp}\n{event_id}\n{SOURCE}\n".encode("utf-8") + body
    )
    expected = "sha256=" + hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied_signature):
        raise HTTPException(401, "invalid_telnexa_signature")
    return event_id, timestamp, idempotency_key, supplied_signature


def _callback_identity(request: Request) -> TelnexaCallbackIdentity:
    config = trust_config(
        trusted_proxy_cidrs=_runtime_setting(
            request, "telnexa_event_trusted_proxy_cidrs", ""
        ),
        client_ca_file=_runtime_setting(request, "telnexa_event_client_ca_file", ""),
        client_uri_san=_runtime_setting(request, "telnexa_event_client_uri_san", ""),
        pinned_certificate_sha256=_runtime_setting(
            request, "telnexa_event_client_cert_sha256", ""
        ),
    )
    return verify_callback_identity(request, config)


def _bounded_setting(request: Request, name: str, default: int, maximum: int) -> int:
    try:
        value = int(cast(int | str, _runtime_setting(request, name, default)))
    except (TypeError, ValueError) as exc:
        raise HTTPException(503, "telnexa_reconcile_configuration_invalid") from exc
    if value <= 0 or value > maximum:
        raise HTTPException(503, "telnexa_reconcile_configuration_invalid")
    return value


def _signature_is_fresh(request: Request, timestamp: str) -> bool:
    try:
        ttl = int(
            cast(
                int | str,
                _runtime_setting(request, "telnexa_event_signature_ttl_seconds", 300),
            )
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(503, "telnexa_signature_configuration_invalid") from exc
    if ttl <= 0:
        raise HTTPException(503, "telnexa_signature_configuration_invalid")
    return abs(time.time() - int(timestamp)) <= ttl


def _parse_event(body: bytes) -> TelnexaDeliveryEvent:
    try:
        raw = json.loads(body)
        if not isinstance(raw, dict):
            raise ValueError("event must be a JSON object")
        return TelnexaDeliveryEvent.model_validate(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "invalid_telnexa_delivery_event") from exc


def _event_message_uuid(tenant_id: str, event_id: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"codestra:telnexa:{tenant_id}:{event_id}")


_TERMINAL_STATUSES = frozenset(
    {"delivered", "failed", "cancelled", "suppressed", "expired"}
)
_NONTERMINAL_STATUS_RANK = {
    "accepted": 0,
    "queued": 1,
    "dispatched": 2,
}


def _effective_status(
    current: MessageStatus, incoming: TelnexaStatus
) -> tuple[MessageStatus, bool]:
    # Provider callbacks are allowed to arrive late or out of order.  A
    # terminal projection is sticky, and the accepted -> queued -> dispatched
    # progression cannot move backwards. The callback is still retained as
    # evidence in the immutable timeline and analytics table.
    if current in _TERMINAL_STATUSES and incoming != current:
        return current, True
    if (
        current in _NONTERMINAL_STATUS_RANK
        and incoming in _NONTERMINAL_STATUS_RANK
        and _NONTERMINAL_STATUS_RANK[incoming]
        < _NONTERMINAL_STATUS_RANK[current]
    ):
        return current, True
    return incoming, False


async def _read_limited_body(request: Request, maximum: int) -> bytes:
    """Read a request incrementally so chunked bodies cannot bypass the cap."""

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > maximum:
                raise HTTPException(413, "telnexa_event_too_large")
        except ValueError as exc:
            raise HTTPException(400, "invalid_content_length") from exc

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            raise HTTPException(413, "telnexa_event_too_large")
    return bytes(body)


def _payload_value(value: object) -> dict[str, object]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("communication payload is not an object")
    return value


def _project_message(
    event: TelnexaDeliveryEvent,
    payload: object,
    *,
    callback_identity: dict[str, str] | None = None,
    reconciled: bool = False,
) -> tuple[CommunicationMessage, MessageStatus, bool, UUID]:
    message = CommunicationMessage.model_validate(_payload_value(payload))
    if message.tenantId != event.tenant_id or message.messageId != event.message_id:
        raise HTTPException(409, "telnexa_message_binding_mismatch")
    if message.channel != "sms" or message.direction != "outbound":
        raise HTTPException(409, "telnexa_message_channel_mismatch")

    effective, ignored = _effective_status(message.status, event.status)
    now = datetime.now(UTC)
    metadata = dict(message.metadata)
    metadata.update(
        {
            "providerEventId": event.event_id,
            "providerEventType": event.event_type,
            "providerStatus": event.provider_status,
            "providerOccurredAt": event.occurred_at.isoformat(),
            "ignoredTransition": ignored,
            "reconciledFromInbox": reconciled,
        }
    )
    if callback_identity is not None:
        metadata["callbackIdentity"] = callback_identity
    update: dict[str, object] = {
        "status": effective,
        "providerReference": event.provider_reference or message.providerReference,
        "failureCode": event.failure_code or message.failureCode,
        "failureMessage": event.failure_message or message.failureMessage,
        "dispatchedAt": (
            message.dispatchedAt
            if effective != "dispatched" or message.dispatchedAt is not None
            else now
        ),
        "completedAt": (
            message.completedAt
            if effective not in _TERMINAL_STATUSES or message.completedAt is not None
            else now
        ),
        "updatedAt": now,
        "metadata": metadata,
    }
    updated = message.model_copy(update=update)
    timeline_event_id = _event_message_uuid(event.tenant_id, event.event_id)
    return updated, effective, ignored, timeline_event_id


async def _insert_inbox_if_new(
    db: AsyncSession,
    event: TelnexaDeliveryEvent,
    body_hash: str,
    payload_json: str,
    *,
    signature_fresh: bool,
) -> tuple[bool, str | None]:
    existing = (
        (
            await db.execute(
                text(
                    "SELECT payload_hash,processing_status FROM telnexa_delivery_event_inbox "
                    "WHERE event_id=:event_id FOR UPDATE"
                ),
                {"event_id": event.event_id},
            )
        )
        .mappings()
        .first()
    )
    if existing:
        if not hmac.compare_digest(str(existing["payload_hash"]), body_hash):
            raise HTTPException(409, "telnexa_event_replay_conflict")
        return True, str(existing["processing_status"])
    if not signature_fresh:
        raise HTTPException(401, "expired_telnexa_signature")
    await db.execute(
        text("""INSERT INTO telnexa_delivery_event_inbox
          (event_id,payload_hash,received_at,source,event_version,schema_version,
           timestamp,occurred_at,tenant_id,correlation_id,idempotency_key,message_id,
           provider_reference,event_type,status,provider_status,failure_code,failure_message,
           payload,processing_status,attempts)
          VALUES (:event_id,:hash,now(),'telnexa',:event_version,:schema_version,
                  :timestamp,CAST(:occurred_at AS timestamptz),:tenant,:correlation,
                  :idempotency,:message_id,:provider_reference,:event_type,:status,:provider_status,
                  :failure_code,:failure_message,CAST(:payload AS jsonb),'pending',0)"""),
        {
            "event_id": event.event_id,
            "hash": body_hash,
            "event_version": event.event_version,
            "schema_version": event.schema_version,
            "timestamp": int(event.timestamp),
            "occurred_at": event.occurred_at.isoformat(),
            "tenant": event.tenant_id,
            "correlation": event.correlation_id,
            "idempotency": event.idempotency_key,
            "message_id": event.message_id,
            "provider_reference": event.provider_reference,
            "event_type": event.event_type,
            "status": event.status,
            "provider_status": event.provider_status,
            "failure_code": event.failure_code,
            "failure_message": event.failure_message,
            "payload": payload_json,
        },
    )
    return False, None


_DRAIN_INBOX_SQL = """SELECT event_id,payload_hash,payload FROM telnexa_delivery_event_inbox
    WHERE tenant_id=:tenant_id AND message_id=:message_id
      AND processing_status='retry' AND event_id<>:event_id
    ORDER BY occurred_at,received_at,event_id
    LIMIT :limit
    FOR UPDATE SKIP LOCKED"""


@dataclass(frozen=True)
class _AppliedEvent:
    event: TelnexaDeliveryEvent
    message: CommunicationMessage
    status: MessageStatus
    ignored: bool
    timeline_event_id: UUID
    reconciled: bool


async def _lock_message(db: AsyncSession, tenant_id: str, message_id: UUID) -> object:
    row = (
        (
            await db.execute(
                text(
                    "SELECT payload FROM middleware_communication_messages "
                    "WHERE tenant_id=:tenant_id AND message_id=:message_id "
                    "FOR UPDATE"
                ),
                {"tenant_id": tenant_id, "message_id": message_id},
            )
        )
        .mappings()
        .first()
    )
    return None if row is None else row["payload"]


async def _record_analytics(db: AsyncSession, event: TelnexaDeliveryEvent) -> None:
    await db.execute(
        text("""INSERT INTO telnexa_delivery_analytics
            (event_id,tenant_id,message_id,event_type,status,provider_status,
             occurred_at,received_at)
            VALUES (:event_id,:tenant,:message,:event_type,:status,:provider_status,
                    CAST(:occurred_at AS timestamptz),now())
            ON CONFLICT (event_id) DO NOTHING"""),
        {
            "event_id": event.event_id,
            "tenant": event.tenant_id,
            "message": event.message_id,
            "event_type": event.event_type,
            "status": event.status,
            "provider_status": event.provider_status,
            "occurred_at": event.occurred_at.isoformat(),
        },
    )


async def _mark_unavailable(
    db: AsyncSession, event_id: str, max_attempts: int, error: str
) -> str:
    """Count a failed projection attempt; dead-letter it at the policy bound."""

    status = (
        await db.execute(
            text("""UPDATE telnexa_delivery_event_inbox
                SET attempts=attempts+1,
                    processing_status=CASE WHEN attempts+1 >= :max_attempts
                        THEN 'dead_letter' ELSE 'retry' END,
                    last_error=:error,updated_at=now()
                WHERE event_id=:event_id
                RETURNING processing_status"""),
            {"event_id": event_id, "max_attempts": max_attempts, "error": error},
        )
    ).scalar_one_or_none()
    return str(status or "retry")


async def _apply_event(
    db: AsyncSession,
    event: TelnexaDeliveryEvent,
    body_hash: str,
    message_payload: object,
    *,
    callback_identity: dict[str, str] | None,
    reconciled: bool,
) -> _AppliedEvent:
    """Project one authenticated inbox event inside the caller's transaction."""

    updated, effective_status, ignored, timeline_event_id = _project_message(
        event,
        message_payload,
        callback_identity=callback_identity,
        reconciled=reconciled,
    )
    await db.execute(
        text("""UPDATE middleware_communication_messages
            SET payload=CAST(:payload AS jsonb),updated_at=:updated_at
            WHERE tenant_id=:tenant_id AND message_id=:message_id"""),
        {
            "payload": updated.model_dump_json(),
            "updated_at": updated.updatedAt,
            "tenant_id": event.tenant_id,
            "message_id": event.message_id,
        },
    )
    timeline_metadata: dict[str, object] = {
        "providerStatus": event.provider_status,
        "providerEventId": event.event_id,
        "ignoredTransition": ignored,
        "reconciledFromInbox": reconciled,
    }
    if callback_identity is not None:
        timeline_metadata["callbackIdentity"] = callback_identity
    timeline_payload = {
        "eventId": str(timeline_event_id),
        "messageId": str(event.message_id),
        "type": event.event_type,
        "status": effective_status,
        "occurredAt": event.occurred_at.isoformat(),
        "provider": "telnexa",
        "providerReference": event.provider_reference,
        "metadata": timeline_metadata,
    }
    await db.execute(
        text("""INSERT INTO middleware_communication_events
            (tenant_id,event_id,message_id,occurred_at,payload)
            VALUES (:tenant,:event_id,:message,CAST(:occurred_at AS timestamptz),
                    CAST(:payload AS jsonb))
            ON CONFLICT (tenant_id,event_id) DO NOTHING"""),
        {
            "tenant": event.tenant_id,
            "event_id": timeline_event_id,
            "message": event.message_id,
            "occurred_at": event.occurred_at.isoformat(),
            "payload": json.dumps(timeline_payload, separators=(",", ":")),
        },
    )
    await db.execute(
        text("""INSERT INTO middleware_communication_provider_events
            (tenant_id,provider_event_id,request_sha256)
            VALUES (:tenant,:event_id,:hash)
            ON CONFLICT (tenant_id,provider_event_id) DO NOTHING"""),
        {"tenant": event.tenant_id, "event_id": event.event_id, "hash": body_hash},
    )
    await _record_analytics(db, event)
    await db.execute(
        text("""UPDATE telnexa_delivery_event_inbox
            SET processing_status='complete',attempts=attempts+1,
                updated_at=now(),last_error=NULL
            WHERE event_id=:event_id"""),
        {"event_id": event.event_id},
    )
    return _AppliedEvent(
        event=event,
        message=updated,
        status=effective_status,
        ignored=ignored,
        timeline_event_id=timeline_event_id,
        reconciled=reconciled,
    )


async def _pending_inbox_events(
    db: AsyncSession, event: TelnexaDeliveryEvent, limit: int
) -> list[tuple[TelnexaDeliveryEvent, str]]:
    """Lock earlier retry-state callbacks for the same message."""

    rows = (
        (
            await db.execute(
                text(_DRAIN_INBOX_SQL),
                {
                    "tenant_id": event.tenant_id,
                    "message_id": event.message_id,
                    "event_id": event.event_id,
                    "limit": limit,
                },
            )
        )
        .mappings()
        .all()
    )
    pending: list[tuple[TelnexaDeliveryEvent, str]] = []
    for row in rows:
        try:
            stored = TelnexaDeliveryEvent.model_validate(_payload_value(row["payload"]))
        except ValueError:
            await db.execute(
                text("""UPDATE telnexa_delivery_event_inbox
                    SET processing_status='dead_letter',last_error='invalid_inbox_payload',
                        updated_at=now()
                    WHERE event_id=:event_id"""),
                {"event_id": row["event_id"]},
            )
            continue
        if (
            stored.event_id != row["event_id"]
            or stored.tenant_id != event.tenant_id
            or stored.message_id != event.message_id
        ):
            continue
        pending.append((stored, str(row["payload_hash"])))
    return pending


async def _project_with_reconciliation(
    db: AsyncSession,
    event: TelnexaDeliveryEvent,
    body_hash: str,
    message_payload: object,
    *,
    callback_identity: dict[str, str] | None,
    reconciled: bool,
    batch_size: int,
) -> list[_AppliedEvent]:
    """Apply ``event`` plus earlier retry-state events in occurrence order."""

    batch = [(event, body_hash, callback_identity, reconciled)]
    batch.extend(
        (stored, stored_hash, None, True)
        for stored, stored_hash in await _pending_inbox_events(db, event, batch_size)
    )
    batch.sort(key=lambda item: (item[0].occurred_at, item[0].event_id))
    applied: list[_AppliedEvent] = []
    payload: object = message_payload
    for item_event, item_hash, identity, item_reconciled in batch:
        result = await _apply_event(
            db,
            item_event,
            item_hash,
            payload,
            callback_identity=identity,
            reconciled=item_reconciled,
        )
        payload = result.message.model_dump(mode="json")
        applied.append(result)
    return applied


def _refresh_cache(request: Request, applied: list[_AppliedEvent]) -> None:
    app = request.scope.get("app")
    runtime = getattr(getattr(app, "state", None), "runtime", None)
    communications = getattr(runtime, "communications", None)
    store = getattr(communications, "store", None)
    if store is None:
        return
    try:
        for item in applied:
            store.synchronize_durable_message(item.message)
            store.add_event(
                item.event.tenant_id,
                item.event.message_id,
                event_type=item.event.event_type,
                status=item.status,
                provider=SOURCE,
                provider_reference=item.event.provider_reference,
                metadata={
                    "providerStatus": item.event.provider_status,
                    "providerEventId": item.event.event_id,
                    "ignoredTransition": item.ignored,
                    "reconciledFromInbox": item.reconciled,
                },
                event_id=item.timeline_event_id,
                occurred_at=item.event.occurred_at,
            )
    except Exception:
        # The database transaction is already committed.  A cache refresh
        # failure must not make Telnexa retry a durable event.
        LOGGER.exception("failed to refresh communications cache after Telnexa event")


async def _authenticated_callback(
    request: Request,
) -> tuple[TelnexaDeliveryEvent, bytes, bool, TelnexaCallbackIdentity]:
    """Run the full trust chain shared by ingress and synthetic verification."""

    identity = _callback_identity(request)
    request_max = int(
        cast(
            int | str,
            _runtime_setting(request, "telnexa_event_request_max_bytes", 1_048_576),
        )
    )
    if request_max <= 0:
        raise HTTPException(503, "telnexa_request_configuration_invalid")
    body = await _read_limited_body(request, request_max)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type != "application/json":
        raise HTTPException(415, "application_json_required")

    event_id, timestamp, header_idempotency_key, _ = _authenticate(request, body)
    signature_fresh = _signature_is_fresh(request, timestamp)
    event = _parse_event(body)
    if (
        event.event_id != event_id
        or event.idempotency_key != header_idempotency_key
        or event.timestamp != timestamp
    ):
        raise HTTPException(409, "telnexa_header_body_binding_mismatch")
    return event, body, signature_fresh, identity


_TELNEXA_OPENAPI = {
    "security": [{"telnexaBearerApiKey": []}],
    "parameters": list(TELNEXA_REQUIRED_HEADERS),
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": TelnexaDeliveryEvent.model_json_schema(),
            }
        },
    },
}


@router.post(
    PATH,
    status_code=202,
    response_model=TelnexaDeliveryAck,
    responses={200: {"model": TelnexaDeliveryAck}},
    openapi_extra=_TELNEXA_OPENAPI,
)
async def receive_telnexa_event(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if not _runtime_setting(request, "telnexa_event_ingress_enabled", False):
        raise HTTPException(503, "telnexa_event_ingress_disabled")
    if not _runtime_setting(request, "sms_delivery", False):
        raise HTTPException(503, "sms_delivery_disabled")
    max_attempts = _bounded_setting(
        request, "telnexa_event_reconcile_max_attempts", 12, 100
    )
    batch_size = _bounded_setting(
        request, "telnexa_event_reconcile_batch_size", 100, 1000
    )
    event, body, signature_fresh, identity = await _authenticated_callback(request)
    if event.event_id.startswith(SYNTHETIC_EVENT_PREFIX):
        # Synthetic callbacks are only ever verified, never projected.
        raise HTTPException(422, "synthetic_telnexa_event_rejected")

    body_hash = hashlib.sha256(body).hexdigest()
    payload_json = json.dumps(
        event.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
    )
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
        {"value": f"telnexa-delivery:{event.event_id}"},
    )
    try:
        duplicate, previous_status = await _insert_inbox_if_new(
            db,
            event,
            body_hash,
            payload_json,
            signature_fresh=signature_fresh,
        )
        if duplicate and previous_status in {"complete", "dead_letter"}:
            await db.commit()
            response.status_code = 200
            return {
                "accepted": True,
                "duplicate": True,
                "event_id": event.event_id,
                "status": previous_status,
                "message_id": str(event.message_id),
            }

        message_payload = await _lock_message(db, event.tenant_id, event.message_id)
        if message_payload is None:
            await _record_analytics(db, event)
            outcome = await _mark_unavailable(
                db, event.event_id, max_attempts, "communication_message_unavailable"
            )
            await db.commit()
            if outcome != "dead_letter":
                raise HTTPException(503, "communication_message_unavailable")
            LOGGER.warning(
                "telnexa callback dead-lettered without communication message: %s",
                event.event_id,
            )
            response.status_code = 200 if duplicate else 202
            return {
                "accepted": True,
                "duplicate": duplicate,
                "event_id": event.event_id,
                "status": "dead_letter",
                "message_id": str(event.message_id),
            }

        applied = await _project_with_reconciliation(
            db,
            event,
            body_hash,
            message_payload,
            callback_identity=identity.evidence(),
            reconciled=False,
            batch_size=batch_size,
        )
        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(503, "telnexa_event_persistence_unavailable") from exc

    _refresh_cache(request, applied)
    response.status_code = 200 if duplicate else 202
    return {
        "accepted": True,
        "duplicate": duplicate,
        "event_id": event.event_id,
        "status": "complete",
        "message_id": str(event.message_id),
        "communication_status": applied[-1].message.status,
        "reconciled_event_ids": [
            item.event.event_id for item in applied if item.reconciled
        ],
    }


@router.post(
    VERIFY_PATH,
    status_code=200,
    response_model=TelnexaSyntheticVerification,
    openapi_extra=_TELNEXA_OPENAPI,
)
async def verify_synthetic_telnexa_callback(request: Request) -> dict[str, object]:
    """Verify a signed synthetic callback end to end with no durable effect.

    The handler has no database dependency and never touches the SMS runtime,
    so it is structurally incapable of projecting, persisting or sending.
    """

    if not _runtime_setting(request, "telnexa_event_synthetic_verify_enabled", False):
        raise HTTPException(503, "telnexa_synthetic_verify_disabled")
    event, _, signature_fresh, identity = await _authenticated_callback(request)
    if not signature_fresh:
        raise HTTPException(401, "expired_telnexa_signature")
    if not event.event_id.startswith(SYNTHETIC_EVENT_PREFIX):
        raise HTTPException(422, "non_synthetic_telnexa_event_rejected")
    return {
        "verified": True,
        "effect": "none",
        "persisted": False,
        "event_id": event.event_id,
        "event_type": event.event_type,
        "message_id": str(event.message_id),
        "tenant_id": event.tenant_id,
        "status": event.status,
        "signature": "valid",
        "fresh": True,
        "identity": {
            "certificate_sha256": identity.certificate_sha256,
            "certificate_serial": identity.certificate_serial,
            "uri_san": identity.uri_san,
            "not_valid_after": identity.not_valid_after,
        },
    }


async def reconcile_telnexa_inbox(
    db: AsyncSession, *, max_attempts: int, batch_size: int
) -> dict[str, object]:
    """Bounded durable sweep of retry-state callbacks; no provider effects.

    Each claimed row is re-projected from its stored, previously authenticated
    payload.  Rows whose message still does not exist consume an attempt and
    are dead-lettered at ``max_attempts``; rows that can never bind are
    dead-lettered immediately.  The caller owns scheduling.
    """

    if max_attempts not in range(1, 101) or batch_size not in range(1, 1001):
        raise ValueError("reconciliation bounds are outside policy")
    rows = (
        (
            await db.execute(
                text("""SELECT event_id,payload_hash,payload FROM telnexa_delivery_event_inbox
                    WHERE processing_status='retry'
                    ORDER BY occurred_at,received_at,event_id
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED"""),
                {"limit": batch_size},
            )
        )
        .mappings()
        .all()
    )
    completed: list[str] = []
    retried: list[str] = []
    dead_lettered: list[str] = []
    try:
        for row in rows:
            event_id = str(row["event_id"])
            if event_id in completed:
                continue
            try:
                event = TelnexaDeliveryEvent.model_validate(_payload_value(row["payload"]))
                if event.event_id != event_id:
                    raise ValueError("inbox key mismatch")
            except ValueError:
                await db.execute(
                    text("""UPDATE telnexa_delivery_event_inbox
                        SET processing_status='dead_letter',
                            last_error='invalid_inbox_payload',updated_at=now()
                        WHERE event_id=:event_id"""),
                    {"event_id": event_id},
                )
                dead_lettered.append(event_id)
                continue
            message_payload = await _lock_message(db, event.tenant_id, event.message_id)
            if message_payload is None:
                outcome = await _mark_unavailable(
                    db, event_id, max_attempts, "communication_message_unavailable"
                )
                (dead_lettered if outcome == "dead_letter" else retried).append(event_id)
                continue
            try:
                async with db.begin_nested():
                    applied = await _project_with_reconciliation(
                        db,
                        event,
                        str(row["payload_hash"]),
                        message_payload,
                        callback_identity=None,
                        reconciled=True,
                        batch_size=batch_size,
                    )
            except (HTTPException, ValueError) as exc:
                error = (
                    str(exc.detail)
                    if isinstance(exc, HTTPException)
                    else "invalid_communication_message"
                )
                await db.execute(
                    text("""UPDATE telnexa_delivery_event_inbox
                        SET processing_status='dead_letter',last_error=:error,
                            attempts=attempts+1,updated_at=now()
                        WHERE event_id=:event_id"""),
                    {"event_id": event_id, "error": error},
                )
                dead_lettered.append(event_id)
                continue
            completed.extend(item.event.event_id for item in applied)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return {
        "scanned": len(rows),
        "completed": completed,
        "retried": retried,
        "dead_lettered": dead_lettered,
    }
