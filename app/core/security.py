import hashlib
import hmac
import time


class SecurityError(ValueError):
    pass


def payload_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verify_ingestion_signature(
    payload: bytes,
    timestamp: str,
    signature: str,
    secret: str,
    now: int | None = None,
    ttl: int = 300,
) -> None:
    if not secret or not timestamp or not signature:
        raise SecurityError("missing signature credentials")
    expected = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature.removeprefix("sha256=")):
        raise SecurityError("invalid signature")
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise SecurityError("invalid signature timestamp") from exc
    current = int(time.time()) if now is None else now
    if abs(current - ts) > ttl:
        raise SecurityError("expired signature")
