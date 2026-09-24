"""Platform authority derived only from the verified original Keycloak token."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs

BEARER = HTTPBearer(auto_error=False)
PLATFORM_ROLES = frozenset({"platform_admin", "platform_reviewer", "platform_operator"})


@dataclass(frozen=True)
class PlatformPrincipal:
    subject: str
    role: str


def require_platform_scope(
    scope: str, allowed_roles: frozenset[str] = PLATFORM_ROLES,
) -> Callable[..., PlatformPrincipal]:
    """Each endpoint declares a scope; headers never supply identity or privilege.

    This synchronous dependency keeps JWKS I/O off the ASGI event loop. Missing
    issuer/audience/client configuration is unavailable, not shared-secret auth.
    """
    def authorize(
        credential: HTTPAuthorizationCredentials | None = Depends(BEARER),
    ) -> PlatformPrincipal:
        if credential is None or credential.scheme.lower() != "bearer":
            raise HTTPException(401, "verified platform bearer required", headers={"WWW-Authenticate": "Bearer"})
        identity = settings.identity
        if not identity.explicit or not identity.authorized_parties:
            raise HTTPException(503, "platform identity authority is not configured")
        validator = KeycloakValidator(**identity_validator_kwargs(identity, required_scopes=frozenset({scope})))
        try:
            claims = validator.validate(credential.credentials)
            subject = claims.get("sub")
            realm = claims.get("realm_access")
            roles = realm.get("roles") if isinstance(realm, dict) else None
            if not isinstance(subject, str) or not subject.strip() or subject != subject.strip() or len(subject) > 255:
                raise JWTAuthError("stable subject required")
            if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
                raise JWTAuthError("platform role claims malformed")
            if not isinstance(claims.get("scope"), str):
                raise JWTAuthError("platform scope claims malformed")
            eligible = allowed_roles.intersection(roles)
            if not eligible:
                raise JWTAuthError("platform role denied")
        except (JWTAuthError, AttributeError, TypeError, ValueError):
            # Never expose credentials, upstream JWKS details or claim contents.
            raise HTTPException(403, "platform authority denied") from None
        role = "platform_admin" if "platform_admin" in eligible else sorted(eligible)[0]
        return PlatformPrincipal(subject=subject, role=role)

    return authorize
