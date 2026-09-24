"""Cryptographic and state-machine primitives for authenticated invalid events."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


STATES = frozenset(
    {
        "PENDING_REVIEW",
        "UNDER_REVIEW",
        "CORRECTABLE",
        "REPLAY_APPROVED",
        "REPLAYING",
        "REPLAYED",
        "RESOLVED_NO_REPLAY",
        "EXPIRED",
        "REJECTED",
    }
)
TRANSITIONS = {
    "PENDING_REVIEW": frozenset({"UNDER_REVIEW", "EXPIRED", "REJECTED"}),
    "UNDER_REVIEW": frozenset(
        {"CORRECTABLE", "REPLAY_APPROVED", "RESOLVED_NO_REPLAY", "REJECTED"}
    ),
    "CORRECTABLE": frozenset({"REPLAY_APPROVED", "RESOLVED_NO_REPLAY", "REJECTED"}),
    "REPLAY_APPROVED": frozenset({"REPLAYING", "RESOLVED_NO_REPLAY"}),
    "REPLAYING": frozenset({"REPLAYED", "REPLAY_APPROVED", "REJECTED"}),
    "REPLAYED": frozenset(),
    "RESOLVED_NO_REPLAY": frozenset(),
    "EXPIRED": frozenset(),
    "REJECTED": frozenset(),
}
PII_KEYS = frozenset(
    {
        "authorization",
        "telephone_number",
        "phone",
        "email",
        "token",
        "secret",
        "password",
        "private_key",
        "recording",
        "customer_reference",
    }
)
PREVIEW_KEYS = frozenset(
    {
        "schema_version",
        "event_id",
        "event_type",
        "source_system",
        "client_instance",
        "business_unit",
        "campaign",
        "correlation_id",
    }
)


class QuarantineIntegrityError(ValueError):
    pass


def fingerprint(raw: bytes, secret: bytes) -> str:
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes
    key_version: str


def encrypt_payload(
    raw: bytes, key: bytes, key_version: str, digest: str
) -> EncryptedPayload:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, raw, digest.encode())
    return EncryptedPayload(ciphertext, nonce, key_version)


def decrypt_payload(
    value: EncryptedPayload, key: bytes, digest: str, secret: bytes
) -> bytes:
    try:
        raw = AESGCM(key).decrypt(value.nonce, value.ciphertext, digest.encode())
    except Exception as exc:
        raise QuarantineIntegrityError("authenticated decryption failed") from exc
    if not hmac.compare_digest(fingerprint(raw, secret), digest):
        raise QuarantineIntegrityError("payload fingerprint mismatch")
    return raw


def sanitized_preview(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"format": "invalid-json", "byte_length": len(raw)}
    if not isinstance(value, dict):
        return {"format": "json", "type": type(value).__name__, "byte_length": len(raw)}
    preview: dict[str, Any] = {"format": "json", "byte_length": len(raw)}
    for key in PREVIEW_KEYS:
        item = value.get(key)
        if item is not None and key not in PII_KEYS:
            preview[key] = str(item)[:128]
    return preview


def transition(current: str, target: str) -> None:
    if current not in STATES or target not in TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid quarantine transition: {current} -> {target}")
