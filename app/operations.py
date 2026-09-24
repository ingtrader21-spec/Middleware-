from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from .api_inputs import (
    authenticated_tenant,
    reject_duplicate_pairs,
    required_header,
)
from .commands import (
    API_OPERATION_STATES,
    OperationAttempt,
    OperationEvent,
    OperationMutationRequest,
)
from .security import RequestValidationError
from .storage import StorageError

router = APIRouter(prefix="/v1/operations", tags=["operations"])
OperationApiState = Literal[
    "RECEIVED",
    "QUEUED",
    "SUBMITTED",
    "ACCEPTED",
    "UNKNOWN",
    "COMPLETED",
    "FAILED",
    "RECONCILIATION_REQUIRED",
    "DEAD_LETTERED",
    "CANCELLED",
]
_PERSISTED_BY_API_STATE = {value: key for key, value in API_OPERATION_STATES.items()}
MAX_BIGINT = (1 << 63) - 1
MAX_INTEGER = (1 << 31) - 1


class OperationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: UUID
    tenant_id: str
    command_type: str
    command_version: str
    target: str
    requested_by: str
    correlation_id: str
    idempotency_key: str
    capability: str
    state: OperationApiState
    provider_operation_id: str | None = None
    readback_evidence: dict[str, Any] | None = None
    readback_evidence_sha256: str | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime
    resource_version: int = 1
    cancelled_at: datetime | None = None
    cancellation_reason: str | None = None
    reconciliation_requested_at: datetime | None = None
    reconciliation_reason: str | None = None
    duplicate: bool


class OperationListResponse(BaseModel):
    items: list[OperationResponse]
    next_cursor: str | None = None


class OperationEventResponse(OperationEvent):
    previous_state: OperationApiState | None
    new_state: OperationApiState


class OperationEventListResponse(BaseModel):
    items: list[OperationEventResponse]
    next_cursor: str | None = None


class OperationAttemptResponse(OperationAttempt):
    state: OperationApiState


class OperationAttemptListResponse(BaseModel):
    items: list[OperationAttemptResponse]
    next_cursor: str | None = None


def _operation_json(operation) -> dict[str, Any]:
    payload = operation.model_dump(mode="json")
    payload["state"] = API_OPERATION_STATES[operation.state]
    return payload


def _encode_cursor(kind: str, values: list[Any]) -> str:
    raw = json.dumps(
        {"v": 1, "kind": kind, "position": values}, separators=(",", ":")
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(value: str | None, kind: str) -> list[Any] | None:
    if value is None:
        return None
    try:
        if not 1 <= len(value) <= 512 or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        ):
            raise ValueError("cursor is not canonical base64url")
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
        data = json.loads(raw, object_pairs_hook=reject_duplicate_pairs)
        if (
            not isinstance(data, dict)
            or set(data) != {"v", "kind", "position"}
            or type(data["v"]) is not int
            or data["v"] != 1
            or data["kind"] != kind
            or not isinstance(data["position"], list)
            or len(data["position"]) != 2
            or _encode_cursor(kind, data["position"]) != value
        ):
            raise ValueError("cursor structure is invalid")
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise RequestValidationError("cursor is malformed") from exc
    return data["position"]


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise RequestValidationError("cursor is malformed")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RequestValidationError("cursor is malformed") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.isoformat() != value
    ):
        raise RequestValidationError("cursor is malformed")
    return parsed


def _positive_bigint(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_BIGINT:
        raise RequestValidationError("cursor is malformed")
    return value


def _positive_integer(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_INTEGER:
        raise RequestValidationError("cursor is malformed")
    return value


def _operation_position(decoded: list[Any] | None) -> tuple[datetime, UUID] | None:
    if decoded is None:
        return None
    timestamp = _timestamp(decoded[0])
    raw_id = decoded[1]
    if not isinstance(raw_id, str):
        raise RequestValidationError("cursor is malformed")
    try:
        command_id = UUID(raw_id)
    except ValueError as exc:
        raise RequestValidationError("cursor is malformed") from exc
    if str(command_id) != raw_id:
        raise RequestValidationError("cursor is malformed")
    return timestamp, command_id


def _event_position(decoded: list[Any] | None) -> tuple[datetime, int] | None:
    if decoded is None:
        return None
    return _timestamp(decoded[0]), _positive_bigint(decoded[1])


def _attempt_position(decoded: list[Any] | None) -> tuple[int, int] | None:
    if decoded is None:
        return None
    return _positive_integer(decoded[0]), _positive_bigint(decoded[1])


async def _context(request: Request):
    active = request.app.state.runtime
    _, _, tenant_id = await authenticated_tenant(request)
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    return active.commands, tenant_id


async def _mutation_context(request: Request):
    active = request.app.state.runtime
    _, claims, tenant_id = await authenticated_tenant(request, mutation=True)
    required_header(
        request,
        "X-Correlation-ID",
        minimum=1,
        maximum=180,
    )
    idempotency_key = required_header(
        request,
        "Idempotency-Key",
        minimum=8,
        maximum=180,
    )
    actor_id = claims.get("sub")
    if not isinstance(actor_id, str) or not actor_id:
        raise RequestValidationError("token subject is required")
    if active.commands is None:
        raise StorageError("command ledger is unavailable")
    return active.commands, tenant_id, actor_id, idempotency_key


@router.get("", response_model=OperationListResponse)
async def list_operations(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
    state: OperationApiState | None = None,
    command_type: str | None = Query(None, min_length=1, max_length=180),
) -> JSONResponse:
    service, tenant_id = await _context(request)
    position = _operation_position(_decode_cursor(cursor, "operations"))
    rows = await service.list_operations(
        tenant_id,
        limit=limit + 1,
        position=position,
        state=_PERSISTED_BY_API_STATE[state] if state else None,
        command_type=command_type,
    )
    more = len(rows) > limit
    items = rows[:limit]
    next_cursor = (
        _encode_cursor(
            "operations", [items[-1].created_at.isoformat(), str(items[-1].command_id)]
        )
        if more
        else None
    )
    return JSONResponse(
        content={
            "items": [_operation_json(item) for item in items],
            "next_cursor": next_cursor,
        }
    )


@router.get("/{command_id}", response_model=OperationResponse)
async def get_operation(command_id: UUID, request: Request) -> JSONResponse:
    service, tenant_id = await _context(request)
    operation = await service.get(tenant_id, command_id)
    return JSONResponse(
        content=_operation_json(operation),
        headers={"X-Correlation-ID": operation.correlation_id},
    )


@router.get("/{command_id}/events", response_model=OperationEventListResponse)
async def list_events(
    command_id: UUID,
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
) -> JSONResponse:
    service, tenant_id = await _context(request)
    position = _event_position(_decode_cursor(cursor, "events"))
    rows = await service.list_events(
        tenant_id, command_id, limit=limit + 1, position=position
    )
    items, more = rows[:limit], len(rows) > limit
    next_cursor = (
        _encode_cursor("events", [items[-1].created_at.isoformat(), items[-1].event_id])
        if more
        else None
    )
    payload = []
    for item in items:
        row = item.model_dump(mode="json")
        row["previous_state"] = API_OPERATION_STATES.get(
            item.previous_state,
            item.previous_state.upper() if item.previous_state else None,
        )
        row["new_state"] = API_OPERATION_STATES.get(
            item.new_state, item.new_state.upper()
        )
        payload.append(row)
    return JSONResponse(content={"items": payload, "next_cursor": next_cursor})


@router.get("/{command_id}/attempts", response_model=OperationAttemptListResponse)
async def list_attempts(
    command_id: UUID,
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
) -> JSONResponse:
    service, tenant_id = await _context(request)
    position = _attempt_position(_decode_cursor(cursor, "attempts"))
    rows = await service.list_attempts(
        tenant_id, command_id, limit=limit + 1, position=position
    )
    items, more = rows[:limit], len(rows) > limit
    next_cursor = (
        _encode_cursor("attempts", [items[-1].attempt_number, items[-1].attempt_id])
        if more
        else None
    )
    payload = []
    for item in items:
        row = item.model_dump(mode="json")
        row["state"] = API_OPERATION_STATES.get(item.state, item.state.upper())
        payload.append(row)
    return JSONResponse(content={"items": payload, "next_cursor": next_cursor})


@router.post("/{command_id}/cancel", response_model=OperationResponse)
async def cancel_operation(
    command_id: UUID, body: OperationMutationRequest, request: Request
) -> JSONResponse:
    service, tenant_id, actor_id, idempotency_key = await _mutation_context(request)
    operation = await service.mutate_operation(
        tenant_id,
        command_id,
        action="cancel",
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        expected_version=body.expected_version,
        reason=body.reason,
    )
    return JSONResponse(content=_operation_json(operation))


@router.post("/{command_id}/reconcile", response_model=OperationResponse)
async def reconcile_operation(
    command_id: UUID, body: OperationMutationRequest, request: Request
) -> JSONResponse:
    service, tenant_id, actor_id, idempotency_key = await _mutation_context(request)
    operation = await service.mutate_operation(
        tenant_id,
        command_id,
        action="reconcile",
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        expected_version=body.expected_version,
        reason=body.reason,
    )
    return JSONResponse(content=_operation_json(operation))
