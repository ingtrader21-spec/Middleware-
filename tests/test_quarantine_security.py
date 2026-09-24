import json
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.v1 import quarantine as quarantine_api
from app.core.quarantine import (
    EncryptedPayload,
    QuarantineIntegrityError,
    decrypt_payload,
    encrypt_payload,
    fingerprint,
    sanitized_preview,
    transition,
)


def test_keyed_fingerprint_encryption_and_integrity():
    raw = b'{"event_id":"synthetic","telephone_number":"+18095550123"}'
    fingerprint_key = b"f" * 32
    encryption_key = b"e" * 32
    digest = fingerprint(raw, fingerprint_key)
    encrypted = encrypt_payload(raw, encryption_key, "test-v1", digest)
    assert encrypted.ciphertext != raw
    assert raw not in encrypted.ciphertext
    assert decrypt_payload(encrypted, encryption_key, digest, fingerprint_key) == raw
    tampered = EncryptedPayload(
        encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]),
        encrypted.nonce,
        encrypted.key_version,
    )
    with pytest.raises(QuarantineIntegrityError):
        decrypt_payload(tampered, encryption_key, digest, fingerprint_key)
    with pytest.raises(QuarantineIntegrityError):
        decrypt_payload(encrypted, encryption_key, "0" * 64, fingerprint_key)


def test_preview_never_contains_raw_pii_or_secrets():
    raw = json.dumps(
        {
            "event_id": "synthetic-event",
            "event_type": "synthetic.publisher_canary",
            "business_unit": "MOY",
            "telephone_number": "+18095550123",
            "authorization": "Bearer do-not-leak",
            "payload": {"email": "customer@example.invalid"},
        }
    ).encode()
    preview = sanitized_preview(raw)
    serialized = json.dumps(preview)
    assert "synthetic.publisher_canary" in serialized
    for secret in ("+18095550123", "do-not-leak", "customer@example.invalid"):
        assert secret not in serialized


def test_malformed_preview_is_bounded_metadata_only():
    raw = b"{not-json:secret-value}"
    assert sanitized_preview(raw) == {
        "format": "invalid-json",
        "byte_length": len(raw),
    }


def test_controlled_state_machine_rejects_shortcuts_and_duplicate_replay():
    transition("PENDING_REVIEW", "UNDER_REVIEW")
    transition("UNDER_REVIEW", "REPLAY_APPROVED")
    transition("REPLAY_APPROVED", "REPLAYING")
    transition("REPLAYING", "REPLAYED")
    with pytest.raises(ValueError):
        transition("PENDING_REVIEW", "REPLAYING")
    with pytest.raises(ValueError):
        transition("REPLAYED", "REPLAYING")


class _ScalarSequence:
    def __init__(self, *values):
        self._values = iter(values)

    async def scalar(self, _statement):
        return next(self._values)

    async def flush(self):
        return None

    async def rollback(self):
        return None


def test_reprocess_rejects_missing_business_unit_after_authorization(monkeypatch):
    record = SimpleNamespace(business_unit=None)
    monkeypatch.setattr(quarantine_api, "_authorize", lambda *args: None)
    with pytest.raises(HTTPException, match="business unit unavailable") as error:
        asyncio.run(
            quarantine_api.reprocess(
                record_id=__import__("uuid").uuid4(),
                scopes="quarantine:replay",
                reviewer="reviewer-test",
                authorized_units="",
                authorization_context="authorized",
                db=_ScalarSequence(record),
            )
        )
    assert error.value.status_code == 409


def test_reprocess_rejects_nullable_correction_payload_components(monkeypatch):
    record = SimpleNamespace(
        id=__import__("uuid").uuid4(),
        business_unit="MOY",
        status="REPLAY_APPROVED",
        authentication_state="VERIFIED",
        original_signature_verification="VERIFIED",
        encrypted_payload=b"ciphertext",
        encryption_nonce=b"nonce",
        encryption_key_version="test-v1",
    )
    correction = SimpleNamespace(
        encrypted_payload=None,
        encryption_nonce=b"nonce",
        encryption_key_version="test-v1",
    )
    monkeypatch.setattr(quarantine_api, "_authorize", lambda *args: None)
    with pytest.raises(HTTPException, match="immutable payload unavailable") as error:
        asyncio.run(
            quarantine_api.reprocess(
                record_id=record.id,
                scopes="quarantine:replay",
                reviewer="reviewer-test",
                authorized_units="MOY",
                authorization_context="authorized",
                db=_ScalarSequence(record, correction),
            )
        )
    assert error.value.status_code == 409
