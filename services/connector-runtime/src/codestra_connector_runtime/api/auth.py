"""OAuth 2.0 JWT validation and authoritative tenant derivation."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any
from uuid import UUID

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

from .config import RuntimeSettings, get_settings
from .problems import ProblemError

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    issuer: str
    client_id: str
    tenant_ids: frozenset[UUID]
    scopes: frozenset[str]
    claims: dict[str, Any]

    def require_tenant(self) -> UUID:
        if len(self.tenant_ids) != 1:
            raise ProblemError(
                status=403,
                code="TENANT_CONTEXT_REQUIRED",
                title="Tenant context required",
                detail="The token must authorize exactly one tenant for this endpoint.",
            )
        return next(iter(self.tenant_ids))


@lru_cache(maxsize=4)
def _jwk_client(jwks_url: str, cache_seconds: int) -> PyJWKClient:
    return PyJWKClient(
        jwks_url,
        cache_keys=True,
        lifespan=cache_seconds,
        timeout=5,
    )


def _numeric_date(claims: dict[str, Any], name: str) -> float:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProblemError(
            status=401,
            code="TOKEN_INVALID",
            title="Invalid access token",
            detail=f"The token {name} claim is missing or invalid.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    number = float(value)
    if not math.isfinite(number):
        raise ProblemError(
            status=401,
            code="TOKEN_INVALID",
            title="Invalid access token",
            detail=f"The token {name} claim is invalid.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    return number


def _scopes(claims: dict[str, Any]) -> frozenset[str]:
    values: set[str] = set()
    raw_scope = claims.get("scope", "")
    if isinstance(raw_scope, str):
        values.update(item for item in raw_scope.split() if item)
    raw_scp = claims.get("scp", [])
    if isinstance(raw_scp, list):
        values.update(item for item in raw_scp if isinstance(item, str) and item)
    return frozenset(values)


def _tenant_ids(claims: dict[str, Any]) -> frozenset[UUID]:
    raw: list[Any] = []
    if "tenant_id" in claims:
        raw.append(claims["tenant_id"])
    if isinstance(claims.get("tenant_ids"), list):
        raw.extend(claims["tenant_ids"])
    tenants: set[UUID] = set()
    for value in raw:
        if value == "*":
            raise ProblemError(
                status=403,
                code="WILDCARD_TENANT_FORBIDDEN",
                title="Tenant authorization denied",
                detail="Wildcard tenant claims are not accepted.",
            )
        try:
            tenants.add(UUID(str(value)))
        except (ValueError, TypeError, AttributeError) as error:
            raise ProblemError(
                status=401,
                code="TOKEN_INVALID",
                title="Invalid access token",
                detail="The token contains an invalid tenant identifier.",
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
            ) from error
    return frozenset(tenants)


def _decode_token(token: str, settings: RuntimeSettings) -> dict[str, Any]:
    try:
        signing_key = _jwk_client(
            str(settings.keycloak_jwks_url),
            settings.jwks_cache_seconds,
        ).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=settings.oauth_audience,
            issuer=str(settings.keycloak_issuer).rstrip("/"),
            options={
                "require": ["exp", "iat", "iss", "sub", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
            },
            leeway=10,
        )
    except Exception as error:
        raise ProblemError(
            status=401,
            code="TOKEN_INVALID",
            title="Invalid access token",
            detail="The bearer token could not be validated.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        ) from error

    issued_at = _numeric_date(claims, "iat")
    expires_at = _numeric_date(claims, "exp")
    now = time.time()
    if expires_at <= issued_at or expires_at - issued_at > (
        settings.maximum_token_lifetime_seconds
    ):
        raise ProblemError(
            status=401,
            code="TOKEN_LIFETIME_INVALID",
            title="Invalid access token",
            detail="The token lifetime exceeds the service policy.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    if issued_at > now + 10:
        raise ProblemError(
            status=401,
            code="TOKEN_INVALID",
            title="Invalid access token",
            detail="The token issue time is in the future.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )
    return dict(claims)


async def principal_dependency(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer),
    ],
    settings: Annotated[RuntimeSettings, Depends(get_settings)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise ProblemError(
            status=401,
            code="AUTHENTICATION_REQUIRED",
            title="Authentication required",
            detail="A bearer access token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = _decode_token(credentials.credentials, settings)
    client_id = str(claims.get("azp") or claims.get("client_id") or "")
    if client_id not in settings.allowed_azp:
        raise ProblemError(
            status=403,
            code="CLIENT_NOT_AUTHORIZED",
            title="Client not authorized",
            detail="The token client is not authorized for this service.",
        )
    principal = Principal(
        subject=str(claims["sub"]),
        issuer=str(claims["iss"]),
        client_id=client_id,
        tenant_ids=_tenant_ids(claims),
        scopes=_scopes(claims),
        claims=claims,
    )
    request.state.principal = principal
    return principal


PrincipalDep = Annotated[Principal, Depends(principal_dependency)]


def require_scopes(*required: str):
    async def dependency(principal: PrincipalDep) -> Principal:
        missing = sorted(set(required) - principal.scopes)
        if missing:
            raise ProblemError(
                status=403,
                code="INSUFFICIENT_SCOPE",
                title="Insufficient scope",
                detail="The access token does not authorize this operation.",
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="insufficient_scope", scope="'
                        + " ".join(required)
                        + '"'
                    )
                },
                extensions={"required_scopes": list(required)},
            )
        return principal

    return dependency
