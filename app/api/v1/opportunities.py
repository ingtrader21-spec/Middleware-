"""``/platform/v1/opportunities``.

Backed by Odoo's real ``crm.lead`` model via ``codestra_middleware_bridge``'s
``crm/leads`` endpoints -- addressed there by ``external_id``
(``codestra.crm.external.mapping``), not a raw Odoo record id, so
``opportunity_id`` in this router's URLs is that external id string. No new
Odoo-side business logic was added for reads/writes; the list endpoint
needed one small, minimal addition to the Odoo bridge controller (see
``app.adapters.odoo.crm_bridge_client`` and the Odoo-side PR).
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

router = APIRouter(prefix="/platform/v1/opportunities", tags=["opportunities"])


@router.get("")
async def list_opportunities(
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
    return await call_bridge(client.list_opportunities(correlation_id=cid, limit=limit, offset=offset))


@router.post("")
async def create_opportunity(
    request: Request,
    payload: dict[str, Any],
    tenant_id: str = Query(...),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
) -> JSONResponse:
    return await submit_crm_command(
        request,
        principal=principal,
        tenant_id=tenant_id,
        command_type="crm.opportunity.create.v1",
        payload={"record": payload},
    )


@router.get("/{opportunity_id}")
async def get_opportunity(
    request: Request,
    opportunity_id: str,
    tenant_id: str = Query(...),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    client: OdooCrmBridgeClient = Depends(get_crm_bridge_client),
) -> JSONResponse:
    require_tenant_match(principal, tenant_id)
    ensure_bridge_tenant(client, tenant_id)
    cid = correlation_id(request)
    return await call_bridge(client.get_opportunity(opportunity_id, correlation_id=cid))


@router.patch("/{opportunity_id}")
async def update_opportunity(
    request: Request,
    opportunity_id: str,
    payload: dict[str, Any],
    tenant_id: str = Query(...),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
) -> JSONResponse:
    return await submit_crm_command(
        request,
        principal=principal,
        tenant_id=tenant_id,
        command_type="crm.opportunity.update.v1",
        payload={"external_id": opportunity_id, "record": payload},
    )
