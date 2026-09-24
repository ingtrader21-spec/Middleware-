"""``GET /platform/v1/activity`` and ``GET /platform/v1/activity/{activity_id}``.

One unified activity timeline, per the platform spec's explicit "do not
build separate timeline services per channel" instruction. This codebase
currently has *two* independent audit tables that would otherwise become
two separate timelines if left alone:

  * ``audit_event``              - generic action/decision log (telephony
                                    call attempts, email/sms identity reads,
                                    and other ad-hoc call sites across this
                                    codebase all write here)
  * ``agent_provisioning_audit``  - the agent-provisioning saga's own
                                    append-only state-transition ledger
                                    (``from_state``/``to_state``/``action``)

This module reads both and merges them into one sorted, paginated feed
rather than adding a third table or exposing them as two APIs. Each item is
normalized to a common shape with a ``source`` field so a caller can still
tell which subsystem produced it.

Not wired to ``Websocket-`` (the separate real-time gateway repo): its
``POST /internal/v1/realtime/events`` only accepts a fixed, narrow set of
call/agent/callback event types (``call.ringing``, ``agent.logged_in``,
``callback.due``, etc. - see its ``EVENT_TYPES`` constant) and is scoped to
live call-state/screen-pop delivery, not a general provisioning/audit
timeline. Publishing arbitrary provisioning-state-change events into it
would violate its own schema (422) and stated scope ("transports authorized
call-state and screen-pop events only"). This read API is therefore
Middleware's own durable history, not a push integration - documented as a
deliberate scope boundary, not an oversight.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.agent_provisioning import AgentProvisioningRequest
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import AgentProvisioningAudit, AuditEvent
from app.db.session import get_session

router = APIRouter(prefix="/platform/v1/activity", tags=["activity"])

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def _audit_event_out(row: AuditEvent) -> dict[str, Any]:
    return {
        "activity_id": f"audit_event:{row.id}",
        "source": "audit_event",
        "type": row.action,
        "correlation_id": row.correlation_id,
        "subject": row.subject,
        "decision": row.decision,
        "created_at": row.created_at,
        "details": row.redacted_payload,
    }


def _provisioning_audit_out(
    row: AgentProvisioningAudit, tenant_id: str, employee_id: str | None,
) -> dict[str, Any]:
    return {
        "activity_id": f"agent_provisioning_audit:{row.id}",
        "source": "agent_provisioning_audit",
        "type": f"provisioning.{row.action}",
        "correlation_id": row.correlation_id,
        "subject": employee_id,
        "decision": row.to_state,
        "created_at": row.created_at,
        "details": {
            "tenant_id": tenant_id, "request_id": str(row.request_id),
            "from_state": row.from_state, "to_state": row.to_state,
        },
    }


def _encode_cursor(created_at: datetime, activity_id: str) -> str:
    return base64.urlsafe_b64encode(
        f"{created_at.isoformat()}|{activity_id}".encode()
    ).decode()


def _decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at, activity_id = raw.split("|", 1)
        return created_at, activity_id
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, "invalid cursor") from exc


@router.get("")
async def list_activity(
    tenant_id: str = Query(...),
    activity_type: str | None = Query(default=None, alias="type"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    fetch_n = max(limit * 3, limit)  # over-fetch each source before merge/sort

    provisioning_stmt = (
        select(AgentProvisioningAudit, AgentProvisioningRequest.employee_id)
        .join(
            AgentProvisioningRequest,
            AgentProvisioningRequest.id == AgentProvisioningAudit.request_id,
        )
        .where(AgentProvisioningRequest.tenant_id == tenant_id)
        .order_by(AgentProvisioningAudit.created_at.desc())
        .limit(fetch_n)
    )
    provisioning_rows = (await session.execute(provisioning_stmt)).all()
    items = [
        _provisioning_audit_out(audit, tenant_id, employee_id)
        for audit, employee_id in provisioning_rows
    ]

    # audit_event has no tenant/business_unit column of its own (same
    # limitation as app.api.v1.calls) - best-effort match via the JSONB
    # payload, excluding rows that don't carry a matching business_unit
    # rather than leaking cross-tenant rows.
    audit_stmt = (
        select(AuditEvent)
        .where(
            AuditEvent.redacted_payload["business_unit"].astext == tenant_id
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(fetch_n)
    )
    audit_rows = (await session.execute(audit_stmt)).scalars().all()
    items.extend(_audit_event_out(row) for row in audit_rows)

    if activity_type is not None:
        items = [item for item in items if item["type"] == activity_type]

    items.sort(key=lambda item: (item["created_at"], item["activity_id"]), reverse=True)

    if cursor is not None:
        cursor_created_at, cursor_id = _decode_cursor(cursor)
        items = [
            item for item in items
            if (item["created_at"].isoformat(), item["activity_id"]) < (cursor_created_at, cursor_id)
        ]

    has_more = len(items) > limit
    page = items[:limit]
    next_cursor = (
        _encode_cursor(page[-1]["created_at"], page[-1]["activity_id"])
        if has_more and page else None
    )
    for item in page:
        item["created_at"] = item["created_at"].isoformat()

    return {"items": page, "next_cursor": next_cursor}


@router.get("/{activity_id}")
async def get_activity(
    activity_id: str,
    tenant_id: str = Query(...),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    if ":" not in activity_id:
        raise HTTPException(422, "malformed activity_id")
    source, _, raw_id = activity_id.partition(":")

    if source == "agent_provisioning_audit":
        provisioning_stmt = (
            select(AgentProvisioningAudit, AgentProvisioningRequest.employee_id)
            .join(
                AgentProvisioningRequest,
                AgentProvisioningRequest.id == AgentProvisioningAudit.request_id,
            )
            .where(
                AgentProvisioningAudit.id == UUID(raw_id),
                AgentProvisioningRequest.tenant_id == tenant_id,
            )
        )
        provisioning_row = (await session.execute(provisioning_stmt)).first()
        if provisioning_row is None:
            raise HTTPException(404, "activity not found for this tenant")
        audit, employee_id = provisioning_row
        out = _provisioning_audit_out(audit, tenant_id, employee_id)
    elif source == "audit_event":
        audit_stmt = select(AuditEvent).where(
            AuditEvent.id == UUID(raw_id),
            AuditEvent.redacted_payload["business_unit"].astext == tenant_id,
        )
        audit_row = (await session.execute(audit_stmt)).scalar_one_or_none()
        if audit_row is None:
            raise HTTPException(404, "activity not found for this tenant")
        out = _audit_event_out(audit_row)
    else:
        raise HTTPException(422, "unrecognized activity source")

    out["created_at"] = out["created_at"].isoformat()
    return out
