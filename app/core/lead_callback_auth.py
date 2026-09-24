from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC, datetime

IDENTITY = "codestra-n8n-lead-automation"
AUDIENCE = "codestra-middleware-lead-automation"
SIGNATURE_VERSION = "HMAC-V2"
CALLBACK_SCOPE = "lead-automation.results.write"
CALLBACK_METHOD = "POST"
CALLBACK_PATH = "/api/v1/lead-automation/results"
_LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CallbackAuthenticationError(PermissionError):
    pass


def canonical_callback_material(
    *,
    signature_version: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    service_identity: str,
    service_audience: str,
    environment: str,
    scope: str,
    idempotency_key: str,
    body_sha256: str,
) -> bytes:
    """Return the exact HMAC-V2 callback material, without a final newline."""
    values = (
        signature_version,
        method,
        path,
        timestamp,
        nonce,
        service_identity,
        service_audience,
        environment,
        scope,
        idempotency_key,
        body_sha256,
    )
    if any(not value or "\n" in value or "\r" in value for value in values):
        raise CallbackAuthenticationError("invalid callback signing material")
    if method != method.upper() or not method.isascii():
        raise CallbackAuthenticationError("invalid callback method")
    if not path.isascii() or "?" in path or "#" in path or "%" in path:
        raise CallbackAuthenticationError("invalid callback path")
    if not _LOWER_SHA256.fullmatch(body_sha256):
        raise CallbackAuthenticationError("invalid callback body hash format")
    if signature_version != SIGNATURE_VERSION:
        raise CallbackAuthenticationError("unsupported callback signature version")
    return "\n".join(values).encode("ascii")


def sign_callback(
    *,
    body: bytes,
    secret: bytes,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    environment: str,
    method: str = CALLBACK_METHOD,
    path: str = CALLBACK_PATH,
) -> dict[str, str]:
    """Build callback headers for offline clients using the verifier's material."""
    body_hash = hashlib.sha256(body).hexdigest()
    material = canonical_callback_material(
        signature_version=SIGNATURE_VERSION,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        service_identity=IDENTITY,
        service_audience=AUDIENCE,
        environment=environment,
        scope=CALLBACK_SCOPE,
        idempotency_key=idempotency_key,
        body_sha256=body_hash,
    )
    return {
        "X-Codestra-Signature-Version": SIGNATURE_VERSION,
        "X-Service-Identity": IDENTITY,
        "X-Service-Audience": AUDIENCE,
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Nonce": nonce,
        "X-Codestra-Content-SHA256": body_hash,
        "X-Codestra-Signature": hmac.new(secret, material, hashlib.sha256).hexdigest(),
        "Idempotency-Key": idempotency_key,
        "X-Codestra-Environment": environment,
        "X-Codestra-Scope": CALLBACK_SCOPE,
    }


def verify_callback(
    *,
    method: str,
    path: str,
    query_string: bytes,
    body: bytes,
    headers: dict[str, str],
    secret: bytes,
    environment: str,
    used_nonces: set[tuple[str, str, str, str]],
    now: datetime | None = None,
) -> None:
    required = (
        "X-Codestra-Signature-Version",
        "X-Service-Identity",
        "X-Service-Audience",
        "X-Codestra-Timestamp",
        "X-Codestra-Nonce",
        "X-Codestra-Content-SHA256",
        "X-Codestra-Signature",
        "Idempotency-Key",
        "X-Codestra-Environment",
        "X-Codestra-Scope",
    )
    if any(not headers.get(name) for name in required):
        raise CallbackAuthenticationError("missing callback signature")
    if method != CALLBACK_METHOD:
        raise CallbackAuthenticationError("callback method mismatch")
    if path != CALLBACK_PATH:
        raise CallbackAuthenticationError("callback path mismatch")
    if query_string:
        raise CallbackAuthenticationError("callback query string is prohibited")
    if headers["X-Codestra-Signature-Version"] != SIGNATURE_VERSION:
        raise CallbackAuthenticationError("unsupported callback signature version")
    if (
        headers["X-Service-Identity"] != IDENTITY
        or headers["X-Service-Audience"] != AUDIENCE
    ):
        raise CallbackAuthenticationError("callback identity binding mismatch")
    if headers["X-Codestra-Environment"] != environment:
        raise CallbackAuthenticationError("callback environment mismatch")
    if headers["X-Codestra-Scope"] != CALLBACK_SCOPE:
        raise CallbackAuthenticationError("callback scope mismatch")
    body_hash = hashlib.sha256(body).hexdigest()
    if not _LOWER_SHA256.fullmatch(headers["X-Codestra-Content-SHA256"]):
        raise CallbackAuthenticationError("invalid callback body hash format")
    if not hmac.compare_digest(body_hash, headers["X-Codestra-Content-SHA256"]):
        raise CallbackAuthenticationError("callback body hash mismatch")
    try:
        occurred = datetime.fromisoformat(headers["X-Codestra-Timestamp"])
    except ValueError as exc:
        raise CallbackAuthenticationError("invalid callback timestamp") from exc
    now = now or datetime.now(UTC)
    if (
        occurred.tzinfo is None
        or abs((now - occurred.astimezone(UTC)).total_seconds()) > 300
    ):
        raise CallbackAuthenticationError("expired callback timestamp")
    nonce_key = (
        environment,
        CALLBACK_SCOPE,
        path,
        headers["X-Codestra-Nonce"],
    )
    if nonce_key in used_nonces:
        raise CallbackAuthenticationError("reused callback nonce")
    material = canonical_callback_material(
        signature_version=headers["X-Codestra-Signature-Version"],
        method=method,
        path=path,
        timestamp=headers["X-Codestra-Timestamp"],
        nonce=headers["X-Codestra-Nonce"],
        service_identity=headers["X-Service-Identity"],
        service_audience=headers["X-Service-Audience"],
        environment=headers["X-Codestra-Environment"],
        scope=headers["X-Codestra-Scope"],
        idempotency_key=headers["Idempotency-Key"],
        body_sha256=body_hash,
    )
    expected = hmac.new(secret, material, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, headers["X-Codestra-Signature"]):
        raise CallbackAuthenticationError("invalid callback signature")
    used_nonces.add(nonce_key)
