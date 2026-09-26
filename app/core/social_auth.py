"""Verified identity authority for the Social API.

Privileges and tenant authority come only from validated Keycloak claims.
Legacy X-Codestra-Permissions headers are intentionally not consulted.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs

BEARER = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class SocialPrincipal:
    subject: str
    authorized_party: str
    tenant_ids: frozenset[str]
    scopes: frozenset[str]

    def has(self, permission: str) -> bool:
        return permission in self.scopes or "social.admin" in self.scopes


def require_social_principal(
    credential: HTTPAuthorizationCredentials | None = Depends(BEARER),
) -> SocialPrincipal:
    if credential is None or credential.scheme.lower() != "bearer":
        raise HTTPException(
            401,
            "verified social bearer required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    identity = settings.identity
    if not identity.explicit or not identity.authorized_parties:
        raise HTTPException(503, "social identity authority is not configured")
    validator = KeycloakValidator(**identity_validator_kwargs(identity))
    try:
        claims = validator.validate(credential.credentials)
        subject = claims.get("sub")
        azp = claims.get("azp")
        scope = claims.get("scope")
        tenant_claim = claims.get("tenant_ids", claims.get("tenant_id", []))
        if isinstance(tenant_claim, str):
            tenant_claim = [tenant_claim]
        if (
            not isinstance(subject, str)
            or not subject.strip()
            or not isinstance(azp, str)
            or not azp.strip()
            or not isinstance(scope, str)
            or not isinstance(tenant_claim, list)
            or not all(isinstance(item, str) and item.strip() for item in tenant_claim)
        ):
            raise JWTAuthError("social authority claims malformed")
    except (JWTAuthError, AttributeError, TypeError, ValueError):
        raise HTTPException(403, "social authority denied") from None
    return SocialPrincipal(
        subject=subject.strip(),
        authorized_party=azp.strip(),
        tenant_ids=frozenset(item.strip() for item in tenant_claim),
        scopes=frozenset(item for item in scope.split() if item),
    )


def require_social_permission(principal: SocialPrincipal, permission: str) -> None:
    if not principal.has(permission):
        raise HTTPException(
            403,
            {
                "code": "SOCIAL_PERMISSION_DENIED",
                "message": f"Permission {permission} is required",
            },
        )
