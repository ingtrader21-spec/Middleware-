import base64
import hashlib
import hmac
import time
import pytest

from app.core.publisher_auth import (
    PublisherAuthenticationError,
    verify_publisher_request,
    verify_publisher_signature,
)


def headers(body, key_id, secret, timestamp, nonce="nonce"):
    digest = hashlib.sha256(body).hexdigest()
    event_id = "00000000-0000-4000-8000-000000000001"
    canonical = "\n".join(
        ("v2", key_id, str(timestamp), nonce, event_id, digest)
    ).encode()
    signature = (
        base64.urlsafe_b64encode(hmac.new(secret, canonical, hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    return {
        "X-Codestra-Key-ID": key_id,
        "X-Codestra-Timestamp": str(timestamp),
        "X-Codestra-Nonce": nonce,
        "X-Codestra-Body-SHA256": digest,
        "X-Codestra-Event-ID": event_id,
        "X-Codestra-Signature": "v2=" + signature,
    }


def test_valid_rotation_and_authentication_failures():
    now = int(time.time())
    keys = {"current": b"a" * 32, "next": b"b" * 32}
    body = b"{}"
    for key_id in keys:
        assert (
            verify_publisher_request(
                body, headers(body, key_id, keys[key_id], now), keys, now=now
            )[0]
            == key_id
        )
    cases = [
        ({}, "missing_authentication"),
        (headers(body, "unknown", b"x" * 32, now), "unknown_key"),
        (headers(body, "current", keys["current"], now - 301), "expired_timestamp"),
        (headers(body, "current", keys["current"], now + 301), "future_timestamp"),
    ]
    invalid = headers(body, "current", keys["current"], now)
    invalid["X-Codestra-Signature"] = "v2=bad"
    cases.append((invalid, "invalid_signature"))
    for candidate, reason in cases:
        with pytest.raises(PublisherAuthenticationError, match=reason):
            verify_publisher_request(body, candidate, keys, now=now)


def test_signature_is_verified_before_timestamp_freshness():
    now = int(time.time())
    body = b"{}"
    keys = {"current": b"a" * 32}
    candidate = headers(body, "current", keys["current"], now - 999)
    candidate["X-Codestra-Signature"] = "v2=invalid"
    with pytest.raises(PublisherAuthenticationError, match="invalid_signature"):
        verify_publisher_signature(body, candidate, keys)
    with pytest.raises(PublisherAuthenticationError, match="expired_timestamp"):
        verify_publisher_request(
            body,
            headers(body, "current", keys["current"], now - 999),
            keys,
            now=now,
        )
