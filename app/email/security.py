from __future__ import annotations

from dataclasses import dataclass
import math

import jwt


class AuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    tenant_id: str
    service: str = "beyvra"
    environment: str = "production"


class TokenValidator:
    def __init__(self, issuer: str, audience: str, jwks_url: str):
        self.issuer, self.audience = issuer.rstrip("/"), audience
        self.keys = jwt.PyJWKClient(jwks_url)

    def validate(self, token: str, required_scope: str) -> Principal:
        try:
            key = self.keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256", "ES256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "iss",
                        "sub",
                        "aud",
                        "azp",
                        "scope",
                        "tenant_id",
                    ]
                },
            )
        except jwt.PyJWTError as exc:
            raise AuthorizationError("invalid_token") from exc

        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if (
            isinstance(issued_at, bool)
            or isinstance(expires_at, bool)
            or not isinstance(issued_at, (int, float))
            or not isinstance(expires_at, (int, float))
            or not math.isfinite(float(issued_at))
            or not math.isfinite(float(expires_at))
            or float(expires_at) <= float(issued_at)
            or float(expires_at) - float(issued_at) > 300
        ):
            raise AuthorizationError("invalid_token_lifetime")

        scopes_claim = claims.get("scope")
        if not isinstance(scopes_claim, str):
            raise AuthorizationError("invalid_scope")
        scopes = frozenset(scopes_claim.split())
        if required_scope not in scopes:
            raise AuthorizationError("insufficient_scope")

        service = claims.get("service")
        azp = claims.get("azp")
        expected = ("klyrow-email-provider", "klyrow-email-provider") if required_scope in {"email.inbound", "email.delivery_event"} else ("beyvra-email-production", "beyvra")
        if (
            not isinstance(azp, str)
            or not isinstance(service, str)
            or (azp, service) != expected
            or claims.get("environment") != "production"
        ):
            raise AuthorizationError("invalid_service_identity")

        subject = claims.get("sub")
        tenant_id = claims.get("tenant_id")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthorizationError("invalid_subject")
        if not isinstance(tenant_id, str) or not tenant_id.strip() or tenant_id == "*":
            raise AuthorizationError("tenant_required")
        return Principal(subject, scopes, tenant_id, service, "production")
