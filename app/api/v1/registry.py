from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator
from app.core.endpoint_registry import (
    RegistryResolver,
    ResolutionDenied,
    ResolutionRequest,
    SignedSnapshotCache,
    SqlEndpointRepository,
)
from app.db.session import get_session

router = APIRouter(prefix="/api/v1/registry", tags=["endpoint-registry"])


class ResolveEndpointRequest(BaseModel):
    environment: str = Field(min_length=1, max_length=32)
    service_key: str = Field(min_length=1, max_length=64)
    endpoint_key: str = Field(min_length=1, max_length=96)
    api_version: str = Field(default="v1", min_length=1, max_length=16)
    organization_public_id: str = Field(default="", max_length=128)
    business_unit_public_id: str = Field(default="", max_length=128)
    campaign_public_id: str = Field(default="", max_length=128)
    workflow_key: str = Field(default="", max_length=128)
    event_type: str = Field(default="", max_length=128)
    mutation: bool = False


def _authorize(authorization: str) -> None:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="service token required")
    try:
        KeycloakValidator(
            issuer=settings.registry_service_issuer,
            audience=settings.registry_service_audience,
            jwks_url=settings.registry_service_jwks_url,
            authorized_parties=frozenset({settings.registry_service_client_id}),
            required_scopes=frozenset({"integration.registry.resolve"}),
            required_environment=settings.environment,
        ).validate(authorization[7:].strip())
    except JWTAuthError as exc:
        raise HTTPException(status_code=401, detail="service token rejected") from exc


async def registry_resolver(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> RegistryResolver:
    return RegistryResolver(SqlEndpointRepository(session), registry_cache())


@lru_cache(maxsize=1)
def registry_cache() -> SignedSnapshotCache:
    return SignedSnapshotCache(
        Redis.from_url(settings.redis_url, decode_responses=True),
        settings.load_registry_snapshot_key(),
        l1_ttl_seconds=settings.registry_l1_ttl_seconds,
        l2_ttl_seconds=settings.registry_l2_ttl_seconds,
        stale_grace_seconds=settings.registry_stale_grace_seconds,
    )


@router.post("/resolve")
async def resolve_endpoint(
    body: ResolveEndpointRequest,
    resolver: Annotated[RegistryResolver, Depends(registry_resolver)],
    authorization: Annotated[str, Header(alias="Authorization")],
):
    _authorize(authorization)
    try:
        endpoint = await resolver.resolve(ResolutionRequest(**body.model_dump()))
    except ResolutionDenied as exc:
        return JSONResponse(
            {
                "status": "REJECTED",
                "error": {
                    "code": exc.reason,
                    "classification": "DEPENDENCY" if exc.retryable else "ROUTING",
                    "retryable": exc.retryable,
                    "safe_message": "No valid current endpoint configuration is available.",
                },
            },
            status_code=503 if exc.retryable else 404,
        )
    return endpoint
