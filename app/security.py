from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient

from app.core.config import Settings


class SecurityError(RuntimeError):
    status_code = 401
    code = "security_error"
    retryable = False


class AuthenticationError(SecurityError):
    status_code = 401
    code = "authentication_failed"


class AuthorizationError(SecurityError):
    status_code = 403
    code = "authorization_denied"


class SignatureError(SecurityError):
    status_code = 401
    code = "webhook_signature_invalid"


class RequestValidationError(SecurityError):
    status_code = 400
    code = "invalid_request"


class TokenVerifier(Protocol):
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        ...

    async def ready(self) -> bool:
        ...


class KeycloakJwtVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Keep the JWKS document cache bounded, but never use PyJWT's
        # cache_keys=True path: that wraps get_signing_key() in an unbounded-
        # lifetime lru_cache, so a removed signing key can remain trusted after
        # the authoritative JWKS set refreshes. A 300-second set cache gives an
        # explicit maximum refresh delay while allowing key removal/replacement
        # to take effect on the next authority refresh.
        self._jwks = PyJWKClient(
            settings.jwks_uri,
            cache_keys=False,
            lifespan=300,
            timeout=settings.jwks_timeout_seconds,
        )
        self._last_ready_at = 0.0
        self._ready_ttl_seconds = 30.0
        self._ready_lock = asyncio.Lock()

    def _verify_sync(
        self,
        token: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        signing_key = self._jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.settings.audience,
            issuer=self.settings.issuer,
            options={
                "require": [
                    "exp",
                    "iat",
                    "iss",
                    "sub",
                    "aud",
                    "azp",
                    "jti",
                    "scope",
                ]
            },
        )
        validate_claims(
            claims,
            expected_client_id=expected_client_id,
            required_scope=required_scope,
        )
        return claims

    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationError("Authorization must be a Bearer token")
        try:
            return await asyncio.to_thread(
                self._verify_sync,
                token,
                expected_client_id=expected_client_id,
                required_scope=required_scope,
            )
        except SecurityError:
            raise
        except Exception as exc:
            raise AuthenticationError("invalid bearer token") from exc

    async def ready(self) -> bool:
        now = time.monotonic()
        if now - self._last_ready_at < self._ready_ttl_seconds:
            return True
        async with self._ready_lock:
            now = time.monotonic()
            if now - self._last_ready_at < self._ready_ttl_seconds:
                return True
            try:
                data = await asyncio.to_thread(self._jwks.fetch_data)
                keys = data.get("keys") if isinstance(data, dict) else None
                if not isinstance(keys, list) or not keys:
                    return False
            except Exception:
                return False
            self._last_ready_at = time.monotonic()
            return True


def _strict_numeric_timestamp(claims: dict[str, Any], name: str) -> float:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuthorizationError(f"machine token {name} must be a numeric timestamp")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise AuthorizationError(f"machine token {name} must be finite")
    return numeric


def validate_claims(
    claims: dict[str, Any],
    *,
    expected_client_id: str,
    required_scope: str,
) -> None:
    if claims.get("azp") != expected_client_id:
        raise AuthorizationError("token azp does not match producer")
    scopes = claims.get("scope")
    if isinstance(scopes, str):
        scope_set = set(scopes.split())
    elif isinstance(scopes, list) and all(isinstance(item, str) for item in scopes):
        scope_set = set(scopes)
    else:
        raise AuthorizationError("token scope claim is missing or malformed")
    if required_scope not in scope_set:
        raise AuthorizationError("required scope is missing")

    issued_at = _strict_numeric_timestamp(claims, "iat")
    expires_at = _strict_numeric_timestamp(claims, "exp")
    if expires_at <= issued_at or expires_at - issued_at > 300:
        raise AuthorizationError("machine token lifetime exceeds the 300-second policy")


def authorize_tenant(claims: dict[str, Any], tenant_id: str) -> None:
    authorized: set[str] = set()
    single = claims.get("tenant_id")
    if isinstance(single, str) and single.strip():
        authorized.add(single.strip())
    multiple = claims.get("tenant_ids")
    if isinstance(multiple, list) and all(isinstance(item, str) for item in multiple):
        authorized.update(item.strip() for item in multiple if item.strip())
    if "*" in authorized:
        raise AuthorizationError("wildcard tenant authorization is prohibited")
    if not authorized:
        raise AuthorizationError("token has no authoritative tenant claim")
    if tenant_id not in authorized:
        raise AuthorizationError("token is not authorized for the requested tenant")


def _parse_timestamp(raw: str) -> float:
    try:
        observed = float(raw)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RequestValidationError(
                "X-Codestra-Timestamp must be epoch seconds or ISO-8601"
            ) from exc
        if parsed.tzinfo is None:
            raise RequestValidationError("X-Codestra-Timestamp must include timezone")
        observed = parsed.astimezone(timezone.utc).timestamp()
    if not math.isfinite(observed):
        raise RequestValidationError("X-Codestra-Timestamp must be finite")
    return observed


@dataclass(frozen=True)
class SignedRequest:
    body_sha256: str
    event_id: str
    event_type: str
    source_client_id: str
    tenant_id: str
    correlation_id: str
    idempotency_key: str
    timestamp: str


def verify_signed_request(
    *,
    settings: Settings,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    expected_source_client_id: str,
) -> SignedRequest:
    required = (
        "authorization",
        "content-type",
        "idempotency-key",
        "x-codestra-event-id",
        "x-codestra-event-type",
        "x-codestra-source",
        "x-codestra-tenant-id",
        "x-codestra-timestamp",
        "x-codestra-signature",
        "x-correlation-id",
    )
    missing = [name for name in required if not headers.get(name)]
    if missing:
        raise RequestValidationError("missing required headers: " + ", ".join(missing))
    content_type = headers["content-type"].split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise RequestValidationError("Content-Type must be application/json")
    source = headers["x-codestra-source"]
    if source != expected_source_client_id:
        raise AuthorizationError("X-Codestra-Source does not match route producer")
    event_id = headers["x-codestra-event-id"]
    if headers["idempotency-key"] != event_id:
        raise RequestValidationError("Idempotency-Key must equal X-Codestra-Event-Id")
    timestamp = headers["x-codestra-timestamp"]
    observed = _parse_timestamp(timestamp)
    if abs(time.time() - observed) > settings.webhook_max_clock_skew_seconds:
        raise SignatureError("webhook timestamp is outside the allowed clock skew")
    body_sha = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        (
            "v1",
            method.upper(),
            path,
            timestamp,
            event_id,
            source,
            body_sha,
        )
    ).encode("utf-8")
    expected = hmac.new(
        settings.webhook_secret(expected_source_client_id),
        canonical,
        hashlib.sha256,
    ).hexdigest()
    supplied = headers["x-codestra-signature"]
    prefix = "sha256="
    if not supplied.startswith(prefix):
        raise SignatureError("X-Codestra-Signature must use sha256=<hex>")
    supplied_hex = supplied[len(prefix) :].lower()
    if len(supplied_hex) != 64 or any(char not in "0123456789abcdef" for char in supplied_hex):
        raise SignatureError("X-Codestra-Signature contains invalid hex")
    if not hmac.compare_digest(supplied_hex, expected):
        raise SignatureError("invalid webhook signature")
    return SignedRequest(
        body_sha256=body_sha,
        event_id=event_id,
        event_type=headers["x-codestra-event-type"],
        source_client_id=source,
        tenant_id=headers["x-codestra-tenant-id"],
        correlation_id=headers["x-correlation-id"],
        idempotency_key=headers["idempotency-key"],
        timestamp=timestamp,
    )
