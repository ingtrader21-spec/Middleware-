"""Scoped campaign preview and approval routes. No provider execution."""

from typing import Annotated
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.campaign_design import (
    CampaignDesignService,
    DesignConflict,
    PostgresDesignStore,
)
from app.core.campaign_design_contract import CampaignDesignInput, CampaignApprovalInput
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs
from app.db.session import get_session
from app.security import authorize_tenant, AuthorizationError

router = APIRouter(prefix="/api/v1/campaign-designs", tags=["campaign-design"])


def authorize(
    authorization: str, *, unit: str, environment: str, scope: str, tenant_id: str
) -> str:
    if not settings.campaign_design_enabled:
        raise HTTPException(503, "campaign design is disabled")
    allowed = {
        x.strip() for x in settings.campaign_design_environments.split(",") if x.strip()
    }
    if environment not in allowed:
        raise HTTPException(403, "campaign design environment is disabled")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        raise HTTPException(401, "bearer token required")
    try:
        claims = KeycloakValidator(
            **identity_validator_kwargs(
                settings.identity,
                authorized_parties=frozenset({settings.campaign_design_client_id}),
                required_scopes=frozenset({scope}),
                required_environment=environment,
                required_business_unit=unit,
            )
        ).validate(token)
        authorize_tenant(claims, tenant_id)
        units = claims.get("business_units")
        subject = claims.get("sub")
        if not isinstance(units, list) or not all(isinstance(v, str) for v in units):
            raise JWTAuthError("invalid business-unit claim")
        if (
            "*" in units
            or unit not in units
            or not isinstance(subject, str)
            or not subject
        ):
            raise JWTAuthError("invalid campaign authority")
        return subject
    except (JWTAuthError, AuthorizationError) as exc:
        raise HTTPException(403, "campaign design authorization denied") from exc


@router.post("/preview")
async def preview(
    request: CampaignDesignInput,
    authorization: Annotated[str, Header(alias="Authorization")],
    business_unit: Annotated[str, Header(alias="X-Business-Unit")],
    tenant_id: Annotated[
        str, Header(alias="X-Tenant-ID", min_length=1, max_length=128)
    ],
    idempotency_key: Annotated[
        str, Header(alias="Idempotency-Key", min_length=8, max_length=180)
    ],
    correlation_id: Annotated[
        str, Header(alias="X-Correlation-ID", min_length=1, max_length=180)
    ],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    authorize(
        authorization,
        unit=request.business_unit,
        environment=request.environment,
        scope="campaign.design.preview",
        tenant_id=tenant_id,
    )
    if request.tenant_id is not None and request.tenant_id != tenant_id:
        raise HTTPException(403, "tenant assertion mismatch")
    if business_unit != request.business_unit:
        raise HTTPException(403, "business-unit assertion mismatch")
    if idempotency_key != request.event_id or correlation_id != request.correlation_id:
        raise HTTPException(409, "event identity assertion mismatch")
    try:
        scoped_request = request.model_copy(update={"tenant_id": tenant_id})
        return await CampaignDesignService(PostgresDesignStore(db)).consume(
            scoped_request
        )
    except DesignConflict as exc:
        raise HTTPException(409, "campaign design conflict") from exc


@router.post("/approvals")
async def approve(
    request: CampaignApprovalInput,
    authorization: Annotated[str, Header(alias="Authorization")],
    business_unit: Annotated[str, Header(alias="X-Business-Unit")],
    tenant_id: Annotated[
        str, Header(alias="X-Tenant-ID", min_length=1, max_length=128)
    ],
    idempotency_key: Annotated[
        str, Header(alias="Idempotency-Key", min_length=8, max_length=180)
    ],
    correlation_id: Annotated[
        str, Header(alias="X-Correlation-ID", min_length=1, max_length=180)
    ],
    db: Annotated[AsyncSession, Depends(get_session)],
):
    if len(idempotency_key) > 128 or len(correlation_id) > 128:
        raise HTTPException(400, "campaign approval identity exceeds storage bounds")
    actor = authorize(
        authorization,
        unit=request.business_unit,
        environment=request.environment,
        scope="campaign.design.approve",
        tenant_id=tenant_id,
    )
    if request.tenant_id is not None and request.tenant_id != tenant_id:
        raise HTTPException(403, "tenant assertion mismatch")
    if business_unit != request.business_unit:
        raise HTTPException(403, "business-unit assertion mismatch")
    try:
        return await CampaignDesignService(PostgresDesignStore(db)).approve(
            request.integration_uuid,
            request.design_revision,
            request.manifest_hash,
            actor,
            request.reason,
            idempotency_key,
            correlation_id,
            business_unit=request.business_unit,
            environment=request.environment,
            tenant_id=tenant_id,
        )
    except DesignConflict as exc:
        raise HTTPException(409, "campaign approval conflict") from exc
