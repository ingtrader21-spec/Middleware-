"""Proves ProvisioningServiceAdapter's HMAC signing matches exactly what
codestra-provisioning-service's ``verify_middleware_invocation``
(app/security.py, PR #31) computes server-side, without either service
calling the other over the network.

The reference implementation below is a literal transcription of that
function's verification arithmetic (not an import, since it lives in a
different repository): ``hmac_sha256(secret, timestamp + "." + body)``,
hex digest, compared against a ``sha256=``-prefixed header value.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat

import pytest

from app.provisioning_service_adapter import (
    ProvisioningServiceAdapterError,
    _read_private_secret,
    sign_middleware_invocation,
)

_TEST_SECRET = b"test-secret-not-real-0123456789ab"  # >=32 bytes, test-only


def _reference_verify(secret: bytes, *, timestamp: str, signature_header: str, body: bytes) -> bool:
    expected = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    prefix = "sha256="
    if not signature_header.startswith(prefix):
        return False
    return hmac.compare_digest(signature_header[len(prefix):], expected)


def test_signature_matches_provisioning_service_verification() -> None:
    body = b'{"foo":"bar"}'
    timestamp = "1234567890"
    signature = sign_middleware_invocation(_TEST_SECRET, timestamp=timestamp, body=body)
    header_value = f"sha256={signature}"

    assert _reference_verify(_TEST_SECRET, timestamp=timestamp, signature_header=header_value, body=body)


def test_signature_rejects_tampered_body() -> None:
    timestamp = "1234567890"
    signature = sign_middleware_invocation(_TEST_SECRET, timestamp=timestamp, body=b'{"foo":"bar"}')
    header_value = f"sha256={signature}"

    assert not _reference_verify(
        _TEST_SECRET, timestamp=timestamp, signature_header=header_value, body=b'{"foo":"tampered"}'
    )


def test_signature_rejects_wrong_secret() -> None:
    timestamp = "1234567890"
    body = b'{"foo":"bar"}'
    signature = sign_middleware_invocation(_TEST_SECRET, timestamp=timestamp, body=body)
    header_value = f"sha256={signature}"

    assert not _reference_verify(
        b"a-different-test-secret-0123456789", timestamp=timestamp, signature_header=header_value, body=body
    )


def test_read_private_secret_rejects_relative_path(tmp_path) -> None:
    with pytest.raises(ProvisioningServiceAdapterError, match="absolute"):
        _read_private_secret("relative/path")


def test_read_private_secret_rejects_loose_permissions(tmp_path) -> None:
    secret_path = tmp_path / "secret"
    secret_path.write_text("x" * 40)
    os.chmod(secret_path, 0o644)
    with pytest.raises(ProvisioningServiceAdapterError, match="0600"):
        _read_private_secret(str(secret_path))


def test_read_private_secret_rejects_short_secret(tmp_path) -> None:
    secret_path = tmp_path / "secret"
    secret_path.write_text("short")
    os.chmod(secret_path, stat.S_IRUSR | stat.S_IWUSR)
    with pytest.raises(ProvisioningServiceAdapterError, match="at least"):
        _read_private_secret(str(secret_path))


def test_read_private_secret_accepts_valid_file(tmp_path) -> None:
    secret_path = tmp_path / "secret"
    secret_path.write_text("y" * 40)
    os.chmod(secret_path, stat.S_IRUSR | stat.S_IWUSR)
    secret = _read_private_secret(str(secret_path))
    assert secret == b"y" * 40
