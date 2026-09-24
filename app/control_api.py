from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal, overload

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .api_inputs import (
    authenticated_tenant,
    reject_duplicate_pairs as _reject_duplicate_pairs,
    required_header,
)
from .capability_resolution import effective_capability_enabled
from .runtime_safety import runtime_safety_readback
from .security import RequestValidationError
from .storage import PostgresInboxStore, StorageError

router = APIRouter(tags=["durable-control"])

MAX_BIGINT = (1 << 63) - 1


class ControlMutation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    reason: str = Field(
        min_length=1, max_length=500, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: -]*$"
    )


def _cursor(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        if not 1 <= len(value) <= 128 or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        ):
            raise ValueError("cursor is not canonical base64url")
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
        raw = json.loads(decoded, object_pairs_hook=_reject_duplicate_pairs)
        if not isinstance(raw, dict) or set(raw) != {"v", "id"}:
            raise ValueError("cursor field set is invalid")
        row_id = raw["id"]
        if type(raw["v"]) is not int or raw["v"] != 1:
            raise ValueError("cursor version is invalid")
        if type(row_id) is not int or not 1 <= row_id <= MAX_BIGINT:
            raise ValueError("cursor ID is invalid")
        if _next(row_id) != value:
            raise ValueError("cursor encoding is not canonical")
        return row_id
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise RequestValidationError("cursor is malformed") from exc


def _next(row_id: int) -> str:
    if type(row_id) is not int or not 1 <= row_id <= MAX_BIGINT:
        raise ValueError("cursor ID is outside the PostgreSQL bigint range")
    return (
        base64.urlsafe_b64encode(
            json.dumps({"v": 1, "id": row_id}, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )


def _audit_next(created_at: datetime, authority: str, row_id: int) -> str:
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("audit cursor timestamp must be timezone-aware")
    if authority not in {"control", "command"}:
        raise ValueError("audit cursor authority is invalid")
    if type(row_id) is not int or not 1 <= row_id <= MAX_BIGINT:
        raise ValueError("audit cursor ID is outside the PostgreSQL bigint range")
    timestamp = created_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return (
        base64.urlsafe_b64encode(
            json.dumps(
                {"v": 1, "ts": timestamp, "authority": authority, "id": row_id},
                separators=(",", ":"),
            ).encode()
        )
        .decode()
        .rstrip("=")
    )


def _audit_cursor(value: str | None) -> tuple[datetime, str, int] | None:
    if value is None:
        return None
    try:
        if not 1 <= len(value) <= 256 or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        ):
            raise ValueError("cursor is not canonical base64url")
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
        raw = json.loads(decoded, object_pairs_hook=_reject_duplicate_pairs)
        if not isinstance(raw, dict) or set(raw) != {"v", "ts", "authority", "id"}:
            raise ValueError("audit cursor field set is invalid")
        if type(raw["v"]) is not int or raw["v"] != 1:
            raise ValueError("audit cursor version is invalid")
        timestamp_value = raw["ts"]
        authority = raw["authority"]
        row_id = raw["id"]
        if not isinstance(timestamp_value, str) or not timestamp_value.endswith("Z"):
            raise ValueError("audit cursor timestamp is invalid")
        created_at = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError("audit cursor timestamp is invalid")
        if not isinstance(authority, str):
            raise ValueError("audit cursor authority is invalid")
        canonical = _audit_next(created_at, authority, row_id)
        if canonical != value:
            raise ValueError("audit cursor encoding is not canonical")
        return created_at, authority, row_id
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise RequestValidationError("audit cursor is malformed") from exc


@overload
async def _auth(request: Request, *, mutation: Literal[False] = False) -> str: ...


@overload
async def _auth(
    request: Request,
    *,
    mutation: Literal[True],
) -> tuple[str, str, str]: ...


async def _auth(
    request: Request,
    *,
    mutation: bool = False,
) -> str | tuple[str, str, str]:
    _, claims, tenant = await authenticated_tenant(request, mutation=mutation)
    if mutation:
        required_header(
            request,
            "X-Correlation-ID",
            minimum=1,
            maximum=180,
        )
        idem = required_header(
            request,
            "Idempotency-Key",
            minimum=8,
            maximum=180,
        )
        actor = claims.get("sub")
        if not isinstance(actor, str) or not actor:
            raise RequestValidationError("token subject is required")
        return tenant, actor, idem
    return tenant


def _pool(request: Request):
    inbox = request.app.state.runtime.inbox
    if not isinstance(inbox, PostgresInboxStore):
        raise StorageError("durable control API requires PostgreSQL")
    return inbox.pool


def _safe_inbox(row) -> dict[str, Any]:
    return {
        k: row[k]
        for k in (
            "event_id",
            "tenant_id",
            "source_client_id",
            "event_type",
            "body_sha256",
            "semantic_sha256",
            "correlation_id",
            "received_at",
            "status",
            "processed_at",
            "last_error",
            "resource_version",
            "quarantined_at",
            "quarantine_reason",
            "released_at",
            "reprocess_requested_at",
            "discarded_at",
            "discard_reason",
        )
    }


def _safe_outbox(row) -> dict[str, Any]:
    state = (
        "COMPLETED"
        if row["completed_at"]
        else "CANCELLED"
        if row["cancelled_at"]
        else "DEAD_LETTERED"
        if row["dead_lettered_at"]
        else "RECONCILIATION_REQUIRED"
        if row["reconciliation_required_at"]
        else "LEASED"
        if row["lease_owner"]
        else "PENDING"
    )
    return {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "command_id": row["command_id"],
        "destination": row["destination"],
        "event_type": row["event_type"],
        "state": state,
        "attempt_count": row["attempt_count"],
        "created_at": row["created_at"],
        "next_attempt_at": row["next_attempt_at"],
        "completed_at": row["completed_at"],
        "cancelled_at": row["cancelled_at"],
        "dead_lettered_at": row["dead_lettered_at"],
        "reconciliation_required_at": row["reconciliation_required_at"],
        "safe_error_code": "delivery_error" if row["last_error"] else None,
        "resource_version": row["resource_version"],
    }


async def _list(request: Request, kind: str, limit: int, cursor: str | None):
    tenant = await _auth(request)
    position = _cursor(cursor)
    pool = _pool(request)
    # Inbox IDs are external strings, so its cursor follows immutable ledger sequence.
    async with pool.acquire() as conn:
        if kind == "inbox":
            rows = await conn.fetch(
                """SELECT i.*,l.tenant_sequence AS page_id FROM middleware_inbox i JOIN middleware_event_ledger l ON l.tenant_id=i.tenant_id AND l.event_id=i.event_id WHERE i.tenant_id=$1 AND ($2::bigint IS NULL OR l.tenant_sequence>$2) ORDER BY l.tenant_sequence LIMIT $3""",
                tenant,
                position,
                limit + 1,
            )
        else:
            rows = await conn.fetch(
                "SELECT *,id AS page_id FROM middleware_outbox WHERE tenant_id=$1 AND ($2::bigint IS NULL OR id>$2) ORDER BY id LIMIT $3",
                tenant,
                position,
                limit + 1,
            )
    items = rows[:limit]
    return {
        "items": [
            _safe_inbox(row) if kind == "inbox" else _safe_outbox(row) for row in items
        ],
        "next_cursor": _next(items[-1]["page_id"]) if len(rows) > limit else None,
    }


@router.get("/v1/inbox")
async def inbox_list(
    request: Request, limit: int = Query(50, ge=1, le=100), cursor: str | None = None
):
    return await _list(request, "inbox", limit, cursor)


@router.get("/v1/outbox")
async def outbox_list(
    request: Request, limit: int = Query(50, ge=1, le=100), cursor: str | None = None
):
    return await _list(request, "outbox", limit, cursor)


async def _detail(request: Request, kind: str, rid: str):
    tenant = await _auth(request)
    pool = _pool(request)
    table = "middleware_inbox" if kind == "inbox" else "middleware_outbox"
    key = "event_id" if kind == "inbox" else "id"
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT * FROM {table} WHERE tenant_id=$1 AND {key}=$2",
            tenant,
            rid if kind == "inbox" else int(rid),
        )
    if not row:
        from .commands import CommandNotFound

        raise CommandNotFound(f"{kind} record was not found")
    return _safe_inbox(row) if kind == "inbox" else _safe_outbox(row)


@router.get("/v1/inbox/{record_id}")
async def inbox_detail(record_id: str, request: Request):
    return await _detail(request, "inbox", record_id)


@router.get("/v1/outbox/{record_id}")
async def outbox_detail(record_id: int, request: Request):
    return await _detail(request, "outbox", str(record_id))


@router.get("/v1/inbox/{record_id}/events")
async def inbox_events(record_id: str, request: Request):
    tenant = await _auth(request)
    await _detail(request, "inbox", record_id)
    pool = _pool(request)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id,action,actor_id,reason,previous_state,new_state,metadata,created_at FROM middleware_control_audit WHERE tenant_id=$1 AND resource_kind='inbox' AND resource_id=$2 ORDER BY created_at,id",
            tenant,
            record_id,
        )
    return {"items": [dict(r) for r in rows], "next_cursor": None}


@router.get("/v1/outbox/{record_id}/attempts")
async def outbox_attempts(record_id: int, request: Request):
    tenant = await _auth(request)
    row = await _detail(request, "outbox", str(record_id))
    pool = _pool(request)
    async with pool.acquire() as conn:
        audit = await conn.fetch(
            "SELECT id AS attempt_event_id,attempt_number,event_type,worker_id,safe_error_code,created_at FROM middleware_outbox_attempt_events WHERE tenant_id=$1 AND outbox_id=$2 ORDER BY attempt_number,id",
            tenant,
            record_id,
        )
    return {
        "items": [dict(r) for r in audit],
        "attempt_count": row["attempt_count"],
        "next_cursor": None,
    }


async def _mutate(
    request: Request, kind: str, rid: str, action: str, body: ControlMutation
):
    tenant, actor, idem = await _auth(request, mutation=True)
    pool = _pool(request)
    digest = hashlib.sha256(
        json.dumps(body.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    key = int(rid) if kind == "outbox" else rid
    table = "middleware_outbox" if kind == "outbox" else "middleware_inbox"
    column = "id" if kind == "outbox" else "event_id"
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                f"SELECT * FROM {table} WHERE tenant_id=$1 AND {column}=$2 FOR UPDATE",
                tenant,
                key,
            )
            if not row:
                from .commands import CommandNotFound

                raise CommandNotFound(f"{kind} record was not found")
            replay = await conn.fetchrow(
                "SELECT request_sha256,response_payload FROM middleware_control_mutations WHERE tenant_id=$1 AND resource_kind=$2 AND resource_id=$3 AND action=$4 AND actor_id=$5 AND api_version='v1' AND idempotency_key=$6",
                tenant,
                kind,
                rid,
                action,
                actor,
                idem,
            )
            if replay:
                if replay["request_sha256"] != digest:
                    from .commands import CommandConflict

                    raise CommandConflict(
                        "idempotency key was reused with different content"
                    )
                return (
                    json.loads(replay["response_payload"])
                    if isinstance(replay["response_payload"], str)
                    else dict(replay["response_payload"])
                )
            if row["resource_version"] != body.expected_version:
                from .commands import CommandConflict

                raise CommandConflict("expected_version is stale")
            if kind == "inbox" and row["discarded_at"] is not None:
                from .commands import CommandConflict

                raise CommandConflict("discarded inbox evidence is terminal")
            previous = row["status"] if kind == "inbox" else _safe_outbox(row)["state"]
            if kind == "inbox":
                if action == "quarantine":
                    sql = "UPDATE middleware_inbox SET quarantined_at=now(),quarantine_reason=$3,status='rejected',resource_version=resource_version+1 WHERE tenant_id=$1 AND event_id=$2 RETURNING *"
                elif action == "release":
                    sql = "UPDATE middleware_inbox SET released_at=now(),quarantined_at=NULL,quarantine_reason=NULL,status='accepted',resource_version=resource_version+1 WHERE tenant_id=$1 AND event_id=$2 RETURNING *"
                elif action == "discard":
                    sql = "UPDATE middleware_inbox SET discarded_at=now(),discard_reason=$3,quarantined_at=NULL,quarantine_reason=NULL,status='rejected',processed_at=COALESCE(processed_at,now()),resource_version=resource_version+1 WHERE tenant_id=$1 AND event_id=$2 AND quarantined_at IS NOT NULL RETURNING *"
                else:
                    sql = "UPDATE middleware_inbox SET reprocess_requested_at=now(),status='accepted',resource_version=resource_version+1 WHERE tenant_id=$1 AND event_id=$2 RETURNING *"
            else:
                if (
                    row["completed_at"]
                    or row["dead_lettered_at"]
                    or row["cancelled_at"]
                ):
                    from .commands import CommandConflict

                    raise CommandConflict("outbox record is terminal")
                if row["reconciliation_required_at"]:
                    from .commands import CommandConflict

                    raise CommandConflict("ambiguous delivery requires reconciliation")
                if action == "cancel":
                    sql = "UPDATE middleware_outbox SET cancelled_at=now(),lease_owner=NULL,lease_until=NULL,resource_version=resource_version+1 WHERE tenant_id=$1 AND id=$2 AND (lease_until IS NULL OR lease_until<now()) RETURNING *"
                elif action == "reconcile":
                    sql = "UPDATE middleware_outbox SET reconciliation_required_at=now(),lease_owner=NULL,lease_until=NULL,resource_version=resource_version+1,last_error='manual reconciliation requested' WHERE tenant_id=$1 AND id=$2 AND (lease_until IS NULL OR lease_until<now()) RETURNING *"
                else:
                    if row["attempt_count"] >= 8:
                        from .commands import CommandConflict

                        raise CommandConflict("outbox retry limit is exhausted")
                    sql = "UPDATE middleware_outbox SET next_attempt_at=now(),lease_owner=NULL,lease_until=NULL,resource_version=resource_version+1 WHERE tenant_id=$1 AND id=$2 AND (lease_until IS NULL OR lease_until<now()) RETURNING *"
            updated = (
                await conn.fetchrow(sql, tenant, key, body.reason)
                if "$3" in sql
                else await conn.fetchrow(sql, tenant, key)
            )
            if not updated:
                from .commands import CommandConflict

                raise CommandConflict("resource has an active lease")
            if kind == "inbox" and action == "quarantine":
                await conn.execute(
                    "UPDATE middleware_outbox SET cancelled_at=now(),resource_version=resource_version+1 WHERE tenant_id=$1 AND idempotency_key=$2 AND completed_at IS NULL AND lease_owner IS NULL",
                    tenant,
                    row["idempotency_key"],
                )
            elif kind == "inbox" and action in {"release", "reprocess"}:
                work_key = f"inbox:{action}:{rid}:v{updated['resource_version']}"
                await conn.execute(
                    """INSERT INTO middleware_outbox(tenant_id,destination,event_type,payload,idempotency_key)
              VALUES($1,$2,$3,$4::jsonb,$5) ON CONFLICT DO NOTHING""",
                    tenant,
                    "nats-jetstream",
                    f"inbox.{action}.requested",
                    json.dumps({"event_id": rid, "action": action}),
                    work_key,
                )
            payload = _safe_inbox(updated) if kind == "inbox" else _safe_outbox(updated)
            new = payload["status"] if kind == "inbox" else payload["state"]
            await conn.execute(
                "INSERT INTO middleware_control_audit(tenant_id,resource_kind,resource_id,action,actor_id,reason,previous_state,new_state,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",
                tenant,
                kind,
                rid,
                action,
                actor,
                body.reason,
                previous,
                new,
                json.dumps({"resource_version": updated["resource_version"]}),
            )
            await conn.execute(
                "INSERT INTO middleware_control_mutations(tenant_id,resource_kind,resource_id,action,actor_id,idempotency_key,request_sha256,response_status,response_payload) VALUES($1,$2,$3,$4,$5,$6,$7,200,$8::jsonb)",
                tenant,
                kind,
                rid,
                action,
                actor,
                idem,
                digest,
                json.dumps(payload, default=str),
            )
            return payload


@router.post("/v1/inbox/{record_id}/reprocess")
async def inbox_reprocess(record_id: str, body: ControlMutation, request: Request):
    return await _mutate(request, "inbox", record_id, "reprocess", body)


@router.post("/v1/inbox/{record_id}/quarantine")
async def inbox_quarantine(record_id: str, body: ControlMutation, request: Request):
    return await _mutate(request, "inbox", record_id, "quarantine", body)


@router.post("/v1/inbox/{record_id}/release")
async def inbox_release(record_id: str, body: ControlMutation, request: Request):
    return await _mutate(request, "inbox", record_id, "release", body)


@router.post("/v1/inbox/{record_id}/discard")
async def inbox_discard(record_id: str, body: ControlMutation, request: Request):
    return await _mutate(request, "inbox", record_id, "discard", body)


@router.post("/v1/outbox/{record_id}/cancel")
async def outbox_cancel(record_id: int, body: ControlMutation, request: Request):
    return await _mutate(request, "outbox", str(record_id), "cancel", body)


@router.post("/v1/outbox/{record_id}/retry")
async def outbox_retry(record_id: int, body: ControlMutation, request: Request):
    return await _mutate(request, "outbox", str(record_id), "retry", body)


@router.post("/v1/outbox/{record_id}/reconcile")
@router.post("/v1/reconciliation/operations/{record_id}/request")
async def outbox_reconcile(record_id: int, body: ControlMutation, request: Request):
    return await _mutate(request, "outbox", str(record_id), "reconcile", body)


def _capabilities(request: Request):
    safety = runtime_safety_readback(request.app.state.runtime.settings)
    effects = safety["external_effects"]
    umbrella = safety["umbrella_controls"]
    return {
        "LIVE_ADVERTISING_ENABLED": umbrella["LIVE_ADVERTISING_ENABLED"],
        "EXTERNAL_DELIVERY_ENABLED": umbrella["EXTERNAL_DELIVERY_ENABLED"],
        "SOCIAL_PUBLISHING_ENABLED": umbrella["SOCIAL_PUBLISHING_ENABLED"],
        "EXTERNAL_MODEL_CALLS_ENABLED": umbrella["EXTERNAL_MODEL_CALLS_ENABLED"],
        "LIVE_SMS_DELIVERY": False,
        "LIVE_EMAIL_DELIVERY": False,
        "LIVE_PSTN_DIALING": False,
        "N8N_EXTERNAL_PROVIDER_WRITES": umbrella["N8N_EXTERNAL_PROVIDER_WRITES"],
        "PRODUCTION_DIALING": safety["production_dialing"] == "ENABLED",
        "CALLS_PLACED": 0,
        "evidence": "effective_runtime",
        "runtime": effects,
        "umbrella_controls": umbrella,
    }


@router.get("/v1/system/capabilities")
async def system_capabilities(request: Request):
    await _auth(request)
    return _capabilities(request)


@router.get("/v1/system/safety-state")
async def system_safety(request: Request):
    await _auth(request)
    return {
        "capabilities": _capabilities(request),
        "external_effects": "DISABLED",
        "unknown_evidence_fails_closed": True,
    }


@router.get("/v1/system/readiness")
async def system_readiness(request: Request):
    await _auth(request)
    report = await request.app.state.runtime.readiness()
    return JSONResponse(
        status_code=200 if report.ready else 503,
        content={
            "status": "ready" if report.ready else "not_ready",
            "components": report.components,
            "capabilities": _capabilities(request),
        },
    )


@router.get("/v1/policy/effective")
async def effective_policy(request: Request):
    await _auth(request)
    return {
        "default": "DENY",
        "external_effects": "DISABLED",
        "capabilities": _capabilities(request),
        "ambiguous_provider_effects": "MANUAL_RECONCILIATION_REQUIRED",
    }


class PolicyDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability: str = Field(min_length=1, max_length=100)
    proposed_action: str = Field(min_length=1, max_length=180)


@router.post("/v1/policy/decisions")
async def policy_decision(body: PolicyDecisionRequest, request: Request):
    await _auth(request, mutation=True)
    caps = _capabilities(request)
    enabled = effective_capability_enabled(caps, body.capability)
    return {
        "decision": "ALLOW" if enabled else "DENY",
        "capability": body.capability,
        "proposed_action": body.proposed_action,
        "external_effects": False,
        "reason": "capability_enabled" if enabled else "fail_closed",
    }


@router.get("/v1/reconciliation/operations")
async def reconciliation_list(request: Request, limit: int = Query(50, ge=1, le=100)):
    tenant = await _auth(request)
    pool = _pool(request)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM middleware_outbox WHERE tenant_id=$1 AND reconciliation_required_at IS NOT NULL ORDER BY reconciliation_required_at,id LIMIT $2",
            tenant,
            limit,
        )
    return {"items": [_safe_outbox(r) for r in rows], "next_cursor": None}


@router.get("/v1/audit/events")
async def audit_events(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
):
    tenant = await _auth(request)
    position = _audit_cursor(cursor)
    cursor_time = position[0] if position else None
    cursor_rank = {"control": 1, "command": 0}[position[1]] if position else None
    cursor_id = position[2] if position else None
    pool = _pool(request)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """WITH audit_events AS (
              SELECT id,1 AS authority_rank,'control' AS authority,resource_kind,
                     resource_id,action,actor_id,reason,created_at
                FROM middleware_control_audit WHERE tenant_id=$1
              UNION ALL
              SELECT id,0 AS authority_rank,'command' AS authority,'command',
                     command_id,new_state,actor_id,reason,created_at
                FROM middleware_command_audit WHERE tenant_id=$1
            )
            SELECT id,authority,resource_kind,resource_id,action,actor_id,reason,created_at
              FROM audit_events
             WHERE $2::timestamptz IS NULL
                OR (created_at,authority_rank,id) < ($2::timestamptz,$3::integer,$4::bigint)
             ORDER BY created_at DESC,authority_rank DESC,id DESC
             LIMIT $5""",
            tenant,
            cursor_time,
            cursor_rank,
            cursor_id,
            limit + 1,
        )
    items = [dict(row) for row in rows[:limit]]
    next_cursor = None
    if len(rows) > limit:
        last = items[-1]
        next_cursor = _audit_next(last["created_at"], last["authority"], last["id"])
    return {"items": items, "next_cursor": next_cursor}
