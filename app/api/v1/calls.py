"""``GET /platform/v1/calls`` and ``GET /platform/v1/calls/{call_id}``.

Vicidialer-Codestra/Asterisk remain the runtime authority for call state
(per ``communication-platform-``'s own docs: it is explicitly not a second
runtime implementation and defers call/queue/campaign authority to
Vicidialer-Codestra). This module does NOT introduce a new Middleware-owned
call model - it reads the durable ``telephony_call_lifecycle`` table this
codebase's own ``POST /v1/telephony/calls/originate`` (``app.api.v1.
telephony``) already writes on every call attempt, denied or not.

Tenant scoping limitation, stated plainly rather than glossed over:
``telephony_call_lifecycle`` itself carries no tenant/business_unit column.
The only place ``business_unit`` is recorded is inside the sibling
``audit_event`` row's ``redacted_payload`` (written by the same originate
call, sharing ``correlation_id``). Listing therefore joins on
``correlation_id`` to recover business_unit for the tenant-boundary check.
If no matching audit row exists (should not happen given both rows are
written in the same transaction, but is not enforced by a foreign key), the
call is excluded from a tenant-scoped list rather than leaked - fail closed,
not fail open.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import AuditEvent, TelephonyCallLifecycle
from app.db.session import get_session, set_transaction_tenant_context

router = APIRouter(prefix="/platform/v1/calls", tags=["calls"])

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def _business_unit_column():
    return AuditEvent.redacted_payload["business_unit"].astext


def _call_out(call: TelephonyCallLifecycle) -> dict[str, Any]:
    return {
        "call_id": str(call.id),
        "correlation_id": call.correlation_id,
        "lifecycle_state": call.lifecycle_state,
        "source_extension": call.source_extension,
        "destination": call.destination,
        "dialplan_context": call.dialplan_context,
        "disposition": call.disposition,
        "hangup_cause": call.hangup_cause,
        "lead_model": call.lead_model,
        "lead_id": call.lead_id,
        "fine_state": call.fine_state,
        "fine_state_at": call.fine_state_at.isoformat() if call.fine_state_at else None,
        "last_event_sequence": call.last_event_sequence,
        "hangup_leg": call.hangup_leg,
        "last_event_type": call.last_event_type,
        "last_event_at": call.last_event_at.isoformat() if call.last_event_at else None,
        "started_at": call.started_at.isoformat() if call.started_at else None,
        "connected_at": call.connected_at.isoformat() if call.connected_at else None,
        "ended_at": call.ended_at.isoformat() if call.ended_at else None,
    }


def _encode_cursor(created_at: datetime, call_id: UUID) -> str:
    return base64.urlsafe_b64encode(
        f"{created_at.isoformat()}|{call_id}".encode()
    ).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_at_raw, call_id_raw = raw.split("|", 1)
        created_at = datetime.fromisoformat(created_at_raw)
        if created_at.tzinfo is None:
            raise ValueError("cursor timestamp must include a timezone")
        return created_at, UUID(call_id_raw)
    except Exception as exc:  # noqa: BLE001 - any malformed cursor is a 422
        raise HTTPException(422, "invalid cursor") from exc


@router.get("")
async def list_calls(
    tenant_id: str = Query(..., description="business_unit to scope results to"),
    campaign: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)

    stmt = (
        select(TelephonyCallLifecycle)
        .join(
            AuditEvent,
            AuditEvent.correlation_id == TelephonyCallLifecycle.correlation_id,
        )
        .where(
            AuditEvent.action == "telephony.calls.originate",
            _business_unit_column() == tenant_id,
        )
    )
    if campaign is not None:
        stmt = stmt.where(AuditEvent.redacted_payload["campaign"].astext == campaign)
    if cursor is not None:
        created_at, call_id = _decode_cursor(cursor)
        stmt = stmt.where(
            or_(
                TelephonyCallLifecycle.created_at < created_at,
                and_(
                    TelephonyCallLifecycle.created_at == created_at,
                    TelephonyCallLifecycle.id < call_id,
                ),
            )
        )
    stmt = stmt.order_by(
        TelephonyCallLifecycle.created_at.desc(), TelephonyCallLifecycle.id.desc()
    ).limit(limit + 1)

    rows = list((await session.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = (
        _encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    )

    return {
        "items": [_call_out(row) for row in rows],
        "next_cursor": next_cursor,
    }


@router.get("/{call_id}")
async def get_call(
    call_id: UUID,
    tenant_id: str = Query(..., description="business_unit expected to own this call"),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)

    stmt = (
        select(TelephonyCallLifecycle)
        .join(
            AuditEvent,
            AuditEvent.correlation_id == TelephonyCallLifecycle.correlation_id,
        )
        .where(
            TelephonyCallLifecycle.id == call_id,
            AuditEvent.action == "telephony.calls.originate",
            _business_unit_column() == tenant_id,
        )
    )
    call = (await session.execute(stmt)).scalar_one_or_none()
    if call is None:
        raise HTTPException(404, "call not found for this tenant")
    return _call_out(call)
