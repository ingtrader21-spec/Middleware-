import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


class AutomationSecurityError(ValueError):
    """An inbound automation request failed authentication or replay checks."""


SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "password",
        "phone",
        "phone_e164",
        "prompt",
        "secret",
        "token",
    }
)


def sign_exact_body(body: bytes, secret: str) -> str:
    """Return the lowercase HMAC-SHA256 digest for the exact transmitted bytes."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_exact_body(body: bytes, signature: str, secret: str) -> None:
    if not secret or not signature:
        raise AutomationSecurityError("missing signature credentials")
    supplied = signature.removeprefix("sha256=").lower()
    if not hmac.compare_digest(sign_exact_body(body, secret), supplied):
        raise AutomationSecurityError("invalid signature")


def verify_timestamp(
    timestamp: str, *, ttl_seconds: int, now: int | None = None
) -> None:
    try:
        parsed = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise AutomationSecurityError("invalid timestamp") from exc
    current = int(time.time()) if now is None else now
    if abs(current - parsed) > ttl_seconds:
        raise AutomationSecurityError("stale timestamp")


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


@dataclass(frozen=True)
class IdempotencyDecision:
    duplicate: bool
    conflict: bool


def compare_idempotency(previous_hash: str | None, payload: Any) -> IdempotencyDecision:
    if previous_hash is None:
        return IdempotencyDecision(False, False)
    return IdempotencyDecision(
        previous_hash == canonical_hash(payload),
        previous_hash != canonical_hash(payload),
    )
