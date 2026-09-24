"""Fail-closed Keycloak JWT validation with bounded JWKS caching.

Two verifiers exist on purpose and share one identity source
(:class:`app.core.config.IdentitySettings`):

* :class:`~app.security.KeycloakJwtVerifier` — machine tokens on the Appolon
  control plane (requires ``sub``/``azp``/``jti``/``scope`` and the 300-second
  lifetime, async, cached JWKS).
* :class:`KeycloakValidator` — interactive and service tokens on the
  integration routes (authorized-party, role, scope and tenant-claim
  checks, synchronous).

Both reject any issuer, audience or JWKS authority other than the configured
one; neither ever falls back to a guessed authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jwt

from app.core.config import IdentitySettings


class JWTAuthError(ValueError):
    pass


def identity_validator_kwargs(
    identity: IdentitySettings,
    *,
    authorized_parties: frozenset[str] | None = None,
    **requirements: Any,
) -> dict[str, Any]:
    """Constructor arguments binding a validator to the canonical identity.

    Fails closed when the identity is implicit: the integration routes only
    trust an explicitly configured issuer/audience/JWKS authority, never the
    derived default. ``requirements`` are the ``required_*`` fields.
    """
    if not identity.explicit:
        raise JWTAuthError("Keycloak validation is not configured")
    return {
        "issuer": identity.issuer,
        "audience": identity.audience,
        "jwks_url": identity.jwks_url,
        "authorized_parties": (
            identity.authorized_parties if authorized_parties is None else authorized_parties
        ),
        "algorithms": identity.algorithms,
        **requirements,
    }


@dataclass
class KeycloakValidator:
    issuer: str
    audience: str
    jwks_url: str
    authorized_parties: frozenset[str]
    required_roles: frozenset[str] = frozenset()
    required_scopes: frozenset[str] = frozenset()
    required_environment: str | None = None
    required_business_unit: str | None = None
    required_campaign: str | None = None
    algorithms: tuple[str, ...] = ("RS256",)

    @classmethod
    def from_identity(
        cls,
        identity: IdentitySettings,
        *,
        authorized_parties: frozenset[str] | None = None,
        required_roles: frozenset[str] = frozenset(),
        required_scopes: frozenset[str] = frozenset(),
        required_environment: str | None = None,
        required_business_unit: str | None = None,
        required_campaign: str | None = None,
    ) -> "KeycloakValidator":
        """Bind a validator to the canonical identity; fail closed if implicit."""
        return cls(
            **identity_validator_kwargs(
                identity,
                authorized_parties=authorized_parties,
                required_roles=required_roles,
                required_scopes=required_scopes,
                required_environment=required_environment,
                required_business_unit=required_business_unit,
                required_campaign=required_campaign,
            )
        )

    def validate(self, token: str) -> dict[str, Any]:
        if not all(
            (self.issuer, self.audience, self.jwks_url, self.authorized_parties)
        ):
            raise JWTAuthError("Keycloak validation is not configured")
        try:
            key = jwt.PyJWKClient(
                self.jwks_url, cache_jwk_set=True, lifespan=300
            ).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except Exception as exc:
            raise JWTAuthError("token validation failed") from exc
        if claims.get("azp") not in self.authorized_parties:
            raise JWTAuthError("authorized party denied")
        roles = set(claims.get("realm_access", {}).get("roles", []))
        if not self.required_roles.issubset(roles):
            raise JWTAuthError("required role denied")
        scopes = set(str(claims.get("scope", "")).split())
        if not self.required_scopes.issubset(scopes):
            raise JWTAuthError("required scope denied")
        if (
            self.required_environment is not None
            and claims.get("environment") != self.required_environment
        ):
            raise JWTAuthError("environment denied")
        business_units = set(claims.get("business_units", []))
        if (
            self.required_business_unit is not None
            and self.required_business_unit not in business_units
        ):
            raise JWTAuthError("business unit denied")
        campaigns = set(claims.get("campaigns", []))
        if (
            self.required_campaign is not None
            and self.required_campaign not in campaigns
        ):
            raise JWTAuthError("campaign denied")
        if (
            claims.get("typ") == "Bearer"
            and not claims.get("business_units")
            and not claims.get("client_id")
            and not claims.get("azp")
        ):
            raise JWTAuthError("business-unit or service-account claim required")
        return claims
