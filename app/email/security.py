from __future__ import annotations

from dataclasses import dataclass

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
            claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256"], audience=self.audience, issuer=self.issuer)
        except jwt.PyJWTError as exc:
            raise AuthorizationError("invalid_token") from exc
        scopes = frozenset(str(claims.get("scope", "")).split())
        if required_scope not in scopes:
            raise AuthorizationError("insufficient_scope")
        service = str(claims.get("service", ""))
        azp = str(claims.get("azp", ""))
        expected = ("klyrow-email-provider", "klyrow-email-provider") if required_scope in {"email.inbound", "email.delivery_event"} else ("beyvra-email-production", "beyvra")
        if (azp, service) != expected or claims.get("environment") != "production":
            raise AuthorizationError("invalid_service_identity")
        tenant_id = str(claims.get("tenant_id", ""))
        if not tenant_id:
            raise AuthorizationError("tenant_required")
        return Principal(str(claims["sub"]), scopes, tenant_id, service, "production")
