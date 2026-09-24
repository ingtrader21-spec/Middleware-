import hashlib
import hmac
import time
from collections.abc import MutableSet

from app.social.providers import SocialError


def verify_codestra_signature(
    *,
    body: bytes,
    timestamp: str,
    nonce: str,
    signature: str,
    secret: str,
    seen_nonces: MutableSet[str],
    ttl_seconds: int = 300,
) -> None:
    if not secret:
        raise SocialError(
            "SOCIAL_PROVIDER_NOT_CONFIGURED",
            "Request verification is not configured",
            status_code=503,
        )
    try:
        if abs(time.time() - int(timestamp)) > ttl_seconds:
            raise ValueError
    except ValueError as exc:
        raise SocialError(
            "SOCIAL_WEBHOOK_INVALID_SIGNATURE",
            "Request timestamp is invalid",
            status_code=401,
        ) from exc
    if not nonce or nonce in seen_nonces:
        raise SocialError(
            "SOCIAL_WEBHOOK_REPLAYED", "Request nonce is invalid", status_code=409
        )
    expected = hmac.new(
        secret.encode(),
        timestamp.encode() + b"." + nonce.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature.removeprefix("sha256=")):
        raise SocialError(
            "SOCIAL_WEBHOOK_INVALID_SIGNATURE",
            "Request signature is invalid",
            status_code=401,
        )
    seen_nonces.add(nonce)
