"""Verified integration-administrator authority.

Legacy X-Codestra-Role request headers are not accepted as privilege.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs

BEARER = HTTPBearer(auto_error=False)
ALLOWED_ROLES = frozenset({"integration_admin", "platform_admin"})


@dataclass(frozen=True)
class IntegrationAdminPrincipal:
    subject: str
    role: str


def require_integration_admin(
    credential: HTTPAuthorizationCredentials | None = Depends(BEARER),
) -> IntegrationAdminPrincipal:
    if credential is None or credential.scheme.lower() != "bearer":
        raise HTTPException(
            401,
            "verified integration administrator bearer required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    identity = settings.identity
    if not identity.explicit or not identity.authorized_parties:
        raise HTTPException(503, "integration administrator identity authority is not configured")
    validator = KeycloakValidator(**identity_validator_kwargs(identity))
    try:
        claims = validator.validate(credential.credentials)
        subject = claims.get("sub")
        realm = claims.get("realm_access")
        roles = realm.get("roles") if isinstance(realm, dict) else None
        if (
            not isinstance(subject, str)
            or not subject.strip()
            or not isinstance(roles, list)
            or not all(isinstance(role, str) for role in roles)
        ):
            raise JWTAuthError("integration administrator claims malformed")
        eligible = ALLOWED_ROLES.intersection(roles)
        if not eligible:
            raise JWTAuthError("integration administrator role denied")
    except (JWTAuthError, AttributeError, TypeError, ValueError):
        raise HTTPException(403, "integration administrator authority denied") from None
    role = "platform_admin" if "platform_admin" in eligible else "integration_admin"
    return IntegrationAdminPrincipal(subject=subject.strip(), role=role)
