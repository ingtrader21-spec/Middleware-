"""Tenant directory and tenant-scoped operational projections.

Tenant identity and lifecycle remain authoritative in codestra-foundation.
Platform operators can page through that authority directly, while machine
callers can resolve only the tenant IDs already present in their verified
token. Campaign and recent-agent data comes from Middleware's existing
registry/read models; this module creates no competing tenant store.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.foundation.client import (
    FoundationClient,
    FoundationTenantNotFound,
    FoundationUnavailable,
)
from app.core.config import settings
from app.core.providers import get_http_client
from app.core.platform_auth import PlatformPrincipal, require_platform_scope
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import AgentCallState, CampaignRegistry
from app.db.session import get_session, set_transaction_tenant_context

router = APIRouter(prefix="/platform/v1/tenants", tags=["tenants"])
TENANT_DIRECTORY_ROLES = frozenset({"platform_admin", "platform_operator"})
RECENT_ACTIVE_WINDOW = timedelta(minutes=30)


def _tenant_out(record: Any) -> dict[str, str]:
    return {
        "id": record.id,
        "slug": record.slug,
        "name": record.name,
        "status": record.status,
    }


async def _resolve_tenant(
    foundation: FoundationClient,
    http: httpx.AsyncClient,
    tenant_id: str,
) -> dict[str, str] | None:
    try:
        return _tenant_out(await foundation.get_tenant(http, tenant_id))
    except FoundationTenantNotFound:
        return None
    except FoundationUnavailable as exc:
        raise HTTPException(503, "codestra-foundation is unavailable") from exc


@router.get("")
async def list_tenants(
    status: str | None = Query(default=None, pattern="^(ACTIVE|SUSPENDED|CLOSED)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: PlatformPrincipal = Depends(
        require_platform_scope(
            "platform.tenants.read", allowed_roles=TENANT_DIRECTORY_ROLES
        )
    ),
    http: httpx.AsyncClient = Depends(get_http_client),
) -> dict[str, Any]:
    """Return the real Foundation directory to authorized platform operators."""
    foundation = FoundationClient(settings)
    try:
        records = await foundation.list_tenants(
            http,
            status=status,
            limit=limit,
            offset=offset,
        )
    except FoundationUnavailable as exc:
        raise HTTPException(503, "codestra-foundation is unavailable") from exc
    return {
        "tenants": [_tenant_out(record) for record in records],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "returned": len(records),
        },
    }


@router.get("/authorized")
async def list_authorized_tenants(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    http: httpx.AsyncClient = Depends(get_http_client),
) -> dict[str, Any]:
    """Page through tenant grants carried by the verified machine token."""
    foundation = FoundationClient(settings)
    items: list[dict[str, str]] = []
    granted_ids = sorted(principal.tenant_ids)
    for tenant_id in granted_ids[offset : offset + limit]:
        tenant = await _resolve_tenant(foundation, http, tenant_id)
        if tenant is not None:
            items.append(tenant)
    return {
        "items": items,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "returned": len(items),
            "granted": len(granted_ids),
        },
    }


@router.get("/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    http: httpx.AsyncClient = Depends(get_http_client),
) -> dict[str, str]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    foundation = FoundationClient(settings)
    tenant = await _resolve_tenant(foundation, http, tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    return tenant


@router.get("/{tenant_id}/campaigns")
async def list_tenant_campaigns(
    tenant_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    rows = (
        (
            await session.execute(
                select(CampaignRegistry)
                .where(CampaignRegistry.campaign_code == tenant_id)
                .order_by(CampaignRegistry.campaign_number)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    total = int(
        await session.scalar(
            select(func.count())
            .select_from(CampaignRegistry)
            .where(CampaignRegistry.campaign_code == tenant_id)
        )
        or 0
    )
    return {
        "items": [
            {
                "campaign_id": row.vicidial_campaign_id,
                "campaign_number": row.campaign_number,
                "name": row.name,
                "registry_status": row.registry_status,
            }
            for row in rows
        ],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "returned": len(rows),
            "total": total,
        },
    }


@router.get("/{tenant_id}/health")
async def get_tenant_health(
    tenant_id: str,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    campaign_ids = list(
        (
            await session.execute(
                select(CampaignRegistry.vicidial_campaign_id).where(
                    CampaignRegistry.campaign_code == tenant_id
                )
            )
        ).scalars()
    )
    active_agents = 0
    if campaign_ids:
        since = datetime.now(UTC) - RECENT_ACTIVE_WINDOW
        active_agents = int(
            await session.scalar(
                select(func.count(func.distinct(AgentCallState.agent_id))).where(
                    AgentCallState.campaign_id.in_(campaign_ids),
                    AgentCallState.updated_at >= since,
                )
            )
            or 0
        )
    return {
        "tenant_id": tenant_id,
        "campaign_count": len(campaign_ids),
        "active_agents_last_30m": active_agents,
    }
