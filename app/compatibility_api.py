from __future__ import annotations

import hashlib
import json
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .capability_resolution import effective_capability_enabled
from .commands import CommandConflict, OperationMutationRequest
from .control_api import ControlMutation, _auth, _detail, _list, _mutate, _pool, _safe_inbox, _safe_outbox
from .operations import OperationApiState, _context, _decode_cursor, _encode_cursor, _event_position, _mutation_context, _operation_json, _operation_position, _timestamp
from .security import RequestValidationError

router = APIRouter(prefix="/api/v1", tags=["canonical-compatibility"])


@router.get("/operations")
async def operations_list(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
    state: OperationApiState | None = None,
    command_type: str | None = Query(None, min_length=1, max_length=180),
):
    from .operations import _PERSISTED_BY_API_STATE
    service, tenant = await _context(request)
    position = _operation_position(_decode_cursor(cursor, "operations"))
    rows = await service.list_operations(
        tenant,
        limit=limit + 1,
        position=position,
        state=_PERSISTED_BY_API_STATE[state] if state else None,
        command_type=command_type,
    )
    items = rows[:limit]
    next_cursor = _encode_cursor(
        "operations", [items[-1].created_at.isoformat(), str(items[-1].command_id)]
    ) if len(rows) > limit else None
    return {"items": [_operation_json(item) for item in items], "next_cursor": next_cursor}


@router.get("/operations/{operation_id}")
async def operation_detail(operation_id: UUID, request: Request):
    service, tenant = await _context(request)
    return _operation_json(await service.get(tenant, operation_id))


async def _operation_mutation(
    operation_id: UUID,
    body: OperationMutationRequest,
    request: Request,
    action: Literal["cancel", "retry"],
):
    service, tenant, actor, key = await _mutation_context(request)
    operation = await service.mutate_operation(
        tenant,
        operation_id,
        action=action,
        actor_id=actor,
        idempotency_key=key,
        expected_version=body.expected_version,
        reason=body.reason,
    )
    return JSONResponse(content=_operation_json(operation))


@router.post("/operations/{operation_id}/cancel")
async def operation_cancel(operation_id: UUID, body: OperationMutationRequest, request: Request):
    return await _operation_mutation(operation_id, body, request, "cancel")


@router.post("/operations/{operation_id}/retry")
async def operation_retry(operation_id: UUID, body: OperationMutationRequest, request: Request):
    return await _operation_mutation(operation_id, body, request, "retry")


@router.get("/inbox")
async def inbox_list(request: Request, limit: int = Query(50, ge=1, le=100), cursor: str | None = None):
    return await _list(request, "inbox", limit, cursor)


@router.get("/inbox/{record_id}")
async def inbox_detail(record_id: str, request: Request):
    return await _detail(request, "inbox", record_id)


@router.get("/outbox")
async def outbox_list(request: Request, limit: int = Query(50, ge=1, le=100), cursor: str | None = None):
    return await _list(request, "outbox", limit, cursor)


@router.get("/outbox/{record_id}")
async def outbox_detail(record_id: int, request: Request):
    return await _detail(request, "outbox", str(record_id))


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability: str = Field(min_length=1, max_length=100)
    proposed_action: str = Field(min_length=1, max_length=180)


@router.post("/policy/decisions")
async def policy_decision(body: PolicyDecision, request: Request):
    from .control_api import _capabilities

    await _auth(request, mutation=True)
    enabled = effective_capability_enabled(
        _capabilities(request),
        body.capability,
    )
    return {
        "decision": "ALLOW" if enabled else "DENY",
        "capability": body.capability,
        "proposed_action": body.proposed_action,
        "external_effects": False,
        "reason": "capability_enabled" if enabled else "fail_closed",
    }


@router.get("/reconciliation/operations")
async def reconciliation_list(request: Request, limit: int = Query(50, ge=1, le=100), cursor: str | None = None):
    tenant = await _auth(request)
    position = _event_position(_decode_cursor(cursor, "reconciliation"))
    async with _pool(request).acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM middleware_outbox WHERE tenant_id=$1
               AND reconciliation_required_at IS NOT NULL
               AND ($2::timestamptz IS NULL OR (reconciliation_required_at,id) > ($2,$3))
               ORDER BY reconciliation_required_at,id LIMIT $4""",
            tenant,
            position[0] if position else None,
            position[1] if position else None,
            limit + 1,
        )
    items = rows[:limit]
    next_cursor = _encode_cursor("reconciliation", [items[-1]["reconciliation_required_at"].isoformat(), items[-1]["id"]]) if len(rows) > limit else None
    return {"items": [_safe_outbox(row) for row in items], "next_cursor": next_cursor}


@router.get("/reconciliation/operations/{record_id}")
async def reconciliation_detail(record_id: int, request: Request):
    row = await _detail(request, "outbox", str(record_id))
    if row["state"] != "RECONCILIATION_REQUIRED":
        raise CommandConflict("outbox record is not awaiting reconciliation")
    return row


class ReconciliationResolution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    action: Literal["retry", "complete", "dead_letter"]
    reason: str = Field(min_length=1, max_length=500, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: -]*$")


@router.post("/reconciliation/operations/{record_id}/resolve")
async def reconciliation_resolve(record_id: int, body: ReconciliationResolution, request: Request):
    tenant, actor, idem = await _auth(request, mutation=True)
    digest = hashlib.sha256(
        json.dumps(body.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    action = f"resolve:{body.action}"
    pool = _pool(request)
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM middleware_outbox WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                tenant,
                record_id,
            )
            if row is None:
                from .commands import CommandNotFound
                raise CommandNotFound("reconciliation operation was not found")
            replay = await conn.fetchrow(
                "SELECT request_sha256,response_payload FROM middleware_control_mutations WHERE tenant_id=$1 AND resource_kind='outbox' AND resource_id=$2 AND action=$3 AND actor_id=$4 AND api_version='v1' AND idempotency_key=$5",
                tenant,
                str(record_id),
                action,
                actor,
                idem,
            )
            if replay:
                if replay["request_sha256"] != digest:
                    raise CommandConflict("idempotency key was reused with different content")
                return json.loads(replay["response_payload"]) if isinstance(replay["response_payload"], str) else dict(replay["response_payload"])
            if row["resource_version"] != body.expected_version:
                raise CommandConflict("expected_version is stale")
            if row["reconciliation_required_at"] is None or row["completed_at"] or row["dead_lettered_at"] or row["cancelled_at"]:
                raise CommandConflict("outbox record is not awaiting reconciliation")
            if row["lease_until"] is not None:
                active = await conn.fetchval("SELECT $1::timestamptz > now()", row["lease_until"])
                if active:
                    raise CommandConflict("active dispatch cannot be manually reconciled")
            if body.action == "retry" and row["attempt_count"] >= 8:
                raise CommandConflict("outbox retry limit is exhausted")
            if body.action == "retry":
                update = "UPDATE middleware_outbox SET reconciliation_required_at=NULL,lease_owner=NULL,lease_until=NULL,next_attempt_at=now(),last_error='reconciliation approved retry',resource_version=resource_version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *"
            elif body.action == "complete":
                update = "UPDATE middleware_outbox SET reconciliation_required_at=NULL,lease_owner=NULL,lease_until=NULL,completed_at=now(),last_error=NULL,resource_version=resource_version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *"
            else:
                update = "UPDATE middleware_outbox SET reconciliation_required_at=NULL,lease_owner=NULL,lease_until=NULL,dead_lettered_at=now(),last_error='reconciliation dead-lettered',resource_version=resource_version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *"
            updated = await conn.fetchrow(update, tenant, record_id)
            await conn.execute(
                "INSERT INTO middleware_reconciliation_audit(outbox_id,tenant_id,action,operator_id,reason,attempt_count) VALUES($1,$2,$3,$4,$5,$6)",
                record_id, tenant, body.action, actor, body.reason, row["attempt_count"],
            )
            payload = _safe_outbox(updated)
            await conn.execute(
                "INSERT INTO middleware_control_audit(tenant_id,resource_kind,resource_id,action,actor_id,reason,previous_state,new_state,metadata) VALUES($1,'outbox',$2,$3,$4,$5,'RECONCILIATION_REQUIRED',$6,$7::jsonb)",
                tenant, str(record_id), action, actor, body.reason, payload["state"], json.dumps({"resource_version": updated["resource_version"]}),
            )
            await conn.execute(
                "INSERT INTO middleware_control_mutations(tenant_id,resource_kind,resource_id,action,actor_id,idempotency_key,request_sha256,response_status,response_payload) VALUES($1,'outbox',$2,$3,$4,$5,$6,200,$7::jsonb)",
                tenant, str(record_id), action, actor, idem, digest, json.dumps(jsonable_encoder(payload)),
            )
            return payload


@router.get("/quarantine/events")
async def quarantine_list(request: Request, limit: int = Query(50, ge=1, le=100), cursor: str | None = None):
    tenant = await _auth(request)
    decoded = _decode_cursor(cursor, "quarantine")
    position = None
    if decoded is not None:
        event_id = decoded[1]
        if not isinstance(event_id, str) or not 1 <= len(event_id) <= 128:
            raise RequestValidationError("cursor is malformed")
        position = (_timestamp(decoded[0]), event_id)
    async with _pool(request).acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM middleware_inbox WHERE tenant_id=$1 AND quarantined_at IS NOT NULL
               AND discarded_at IS NULL
               AND ($2::timestamptz IS NULL OR (quarantined_at,event_id) > ($2,$3))
               ORDER BY quarantined_at,event_id LIMIT $4""",
            tenant,
            position[0] if position else None,
            position[1] if position else None,
            limit + 1,
        )
    items = rows[:limit]
    next_cursor = _encode_cursor("quarantine", [items[-1]["quarantined_at"].isoformat(), items[-1]["event_id"]]) if len(rows) > limit else None
    return {"items": [_safe_inbox(row) for row in items], "next_cursor": next_cursor}


@router.get("/quarantine/events/{record_id}")
async def quarantine_detail(record_id: str, request: Request):
    row = await _detail(request, "inbox", record_id)
    if row["quarantined_at"] is None:
        raise CommandConflict("inbox event is not quarantined")
    return row


@router.post("/quarantine/events/{record_id}/release")
async def quarantine_release(record_id: str, body: ControlMutation, request: Request):
    return await _mutate(request, "inbox", record_id, "release", body)


@router.post("/quarantine/events/{record_id}/discard")
async def quarantine_discard(record_id: str, body: ControlMutation, request: Request):
    return await _mutate(request, "inbox", record_id, "discard", body)
