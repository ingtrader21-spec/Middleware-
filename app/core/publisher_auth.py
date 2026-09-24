import base64
import hashlib
import hmac
import time


class PublisherAuthenticationError(ValueError):
    pass


def _header(headers, name):
    value = headers.get(name)
    if not value:
        raise PublisherAuthenticationError("missing_authentication")
    return value


def verify_publisher_signature(body, headers, keys):
    key_id = _header(headers, "X-Codestra-Key-ID")
    secret = keys.get(key_id)
    if secret is None:
        raise PublisherAuthenticationError("unknown_key")
    timestamp_text = _header(headers, "X-Codestra-Timestamp")
    nonce = _header(headers, "X-Codestra-Nonce")
    supplied_hash = _header(headers, "X-Codestra-Body-SHA256")
    event_id = _header(headers, "X-Codestra-Event-ID")
    supplied = _header(headers, "X-Codestra-Signature")
    try:
        timestamp = int(timestamp_text)
    except ValueError as exc:
        raise PublisherAuthenticationError("invalid_timestamp") from exc
    digest = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(digest, supplied_hash):
        raise PublisherAuthenticationError("altered_body")
    canonical = "\n".join(
        ("v2", key_id, timestamp_text, nonce, event_id, digest)
    ).encode()
    raw = hmac.new(secret, canonical, hashlib.sha256).digest()
    expected = "v2=" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
    if not hmac.compare_digest(expected, supplied):
        raise PublisherAuthenticationError("invalid_signature")
    return key_id, nonce, timestamp, event_id


def validate_publisher_timestamp(timestamp, now=None, window=300):
    current = int(time.time()) if now is None else int(now)
    if timestamp < current - window:
        raise PublisherAuthenticationError("expired_timestamp")
    if timestamp > current + window:
        raise PublisherAuthenticationError("future_timestamp")


def verify_publisher_request(body, headers, keys, now=None, window=300):
    result = verify_publisher_signature(body, headers, keys)
    validate_publisher_timestamp(result[2], now=now, window=window)
    return result
