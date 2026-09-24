"""Opaque HMAC-authenticated cursor encoding."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from .problems import ProblemError


@dataclass(frozen=True, slots=True)
class CursorCodec:
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) < 32:
            raise ValueError("cursor HMAC key must be at least 32 bytes")

    @staticmethod
    def _b64encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        try:
            return base64.urlsafe_b64decode(value + padding)
        except Exception as error:
            raise ProblemError(
                status=400,
                code="CURSOR_INVALID",
                title="Invalid cursor",
                detail="The pagination cursor is malformed.",
            ) from error

    def encode(self, payload: dict[str, Any]) -> str:
        body = json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=True,
        ).encode("utf-8")
        signature = hmac.new(self.key, body, hashlib.sha256).digest()
        return self._b64encode(body) + "." + self._b64encode(signature)

    def decode(self, cursor: str | None) -> dict[str, Any] | None:
        if cursor is None:
            return None
        try:
            body_part, signature_part = cursor.split(".", 1)
        except ValueError as error:
            raise ProblemError(
                status=400,
                code="CURSOR_INVALID",
                title="Invalid cursor",
                detail="The pagination cursor is malformed.",
            ) from error
        body = self._b64decode(body_part)
        signature = self._b64decode(signature_part)
        expected = hmac.new(self.key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise ProblemError(
                status=400,
                code="CURSOR_INVALID",
                title="Invalid cursor",
                detail="The pagination cursor signature is invalid.",
            )
        try:
            payload = json.loads(body)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProblemError(
                status=400,
                code="CURSOR_INVALID",
                title="Invalid cursor",
                detail="The pagination cursor payload is invalid.",
            ) from error
        if not isinstance(payload, dict):
            raise ProblemError(
                status=400,
                code="CURSOR_INVALID",
                title="Invalid cursor",
                detail="The pagination cursor payload is invalid.",
            )
        return payload
