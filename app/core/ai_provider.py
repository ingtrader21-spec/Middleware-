"""Provider-neutral, secret-safe AI inference boundary."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Literal, Protocol

REDACTIONS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)\b(bearer|password|api[_-]?key|token)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


class AIProviderError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        retryable: bool = False,
        http_status: int | None = None,
        provider_error_code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.http_status = http_status
        self.provider_error_code = provider_error_code
        self.request_id = request_id

    def safe_details(self) -> dict[str, str | int]:
        """Return bounded provider metadata without messages or request content."""
        details: dict[str, str | int] = {"component": "openai-responses"}
        if self.http_status is not None:
            details["http_status"] = self.http_status
        if self.provider_error_code is not None:
            details["provider_error_code"] = self.provider_error_code
        if self.request_id is not None:
            details["provider_request_id"] = self.request_id
        return details


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    model: str
    reasoning_effort: Literal["low", "medium"]
    input_text: str
    safety_identifier: str
    max_output_tokens: int


@dataclass(frozen=True, slots=True)
class ProviderEvent:
    kind: Literal["delta", "completed"]
    delta: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


class AIProvider(Protocol):
    def stream(self, request: ProviderRequest) -> AsyncIterator[ProviderEvent]: ...


def redact_provider_input(value: str) -> str:
    redacted = value
    for pattern in REDACTIONS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def safety_identifier(actor_id: str, salt: bytes) -> str:
    if len(salt) < 32:
        raise ValueError("safety identifier salt is too short")
    return hmac.new(salt, actor_id.encode(), hashlib.sha256).hexdigest()


@dataclass(slots=True)
class CircuitBreaker:
    failure_threshold: int = 3
    cooldown_seconds: float = 30.0
    failures: int = 0
    opened_at: float | None = None

    def allow(self) -> bool:
        if self.opened_at is None:
            return True
        if time.monotonic() - self.opened_at >= self.cooldown_seconds:
            self.failures = 0
            self.opened_at = None
            return True
        return False

    def succeeded(self) -> None:
        self.failures = 0
        self.opened_at = None

    def failed(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = time.monotonic()
