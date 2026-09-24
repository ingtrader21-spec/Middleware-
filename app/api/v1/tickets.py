"""``/platform/v1/tickets``.

Backed by Odoo's real ``cc.helpdesk.ticket`` model via
``codestra_middleware_bridge``'s ``tickets`` endpoints (numeric Odoo record
id, same addressing as contacts). No Middleware-owned ticket state exists or
is created here -- see ``app.adapters.odoo.crm_bridge_client``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from app.adapters.odoo.crm_bridge_client import (
    OdooCrmBridgeClient,
    get_crm_bridge_client,
)
from app.api.v1.crm_common import (
    call_bridge,
    correlation_id,
    ensure_bridge_tenant,
    submit_crm_command,
)
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)

router = APIRouter(prefix="/platform/v1/tickets", tags=["tickets"])


@router.get("")
async def list_tickets(
    request: Request,
    tenant_id: str = Query(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    client: OdooCrmBridgeClient = Depends(get_crm_bridge_client),
) -> JSONResponse:
    require_tenant_match(principal, tenant_id)
    ensure_bridge_tenant(client, tenant_id)
    cid = correlation_id(request)
    return await call_bridge(client.list_tickets(correlation_id=cid, limit=limit, offset=offset))


@router.post("")
async def create_ticket(
    request: Request,
    payload: dict[str, Any],
    tenant_id: str = Query(...),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
) -> JSONResponse:
    return await submit_crm_command(
        request,
        principal=principal,
        tenant_id=tenant_id,
        command_type="crm.ticket.create.v1",
        payload={"record": payload},
    )


@router.get("/{ticket_id}")
async def get_ticket(
    request: Request,
    ticket_id: int,
    tenant_id: str = Query(...),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    client: OdooCrmBridgeClient = Depends(get_crm_bridge_client),
) -> JSONResponse:
    require_tenant_match(principal, tenant_id)
    ensure_bridge_tenant(client, tenant_id)
    cid = correlation_id(request)
    return await call_bridge(client.get_ticket(ticket_id, correlation_id=cid))


@router.patch("/{ticket_id}")
async def update_ticket(
    request: Request,
    ticket_id: int,
    payload: dict[str, Any],
    tenant_id: str = Query(...),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
) -> JSONResponse:
    return await submit_crm_command(
        request,
        principal=principal,
        tenant_id=tenant_id,
        command_type="crm.ticket.update.v1",
        payload={"ticket_id": ticket_id, "record": payload},
    )
