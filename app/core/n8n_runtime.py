"""Governed n8n runtime contracts, signatures, retries, and state rules."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ExecutionStatus(StrEnum):
    PENDING = "PENDING"
    DISPATCHING = "DISPATCHING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRY = "RETRY"
    DEAD_LETTER = "DEAD_LETTER"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


TERMINAL_STATUSES = {
    ExecutionStatus.COMPLETED,
    ExecutionStatus.FAILED,
    ExecutionStatus.DEAD_LETTER,
    ExecutionStatus.CANCELLED,
    ExecutionStatus.TIMED_OUT,
}
RETRYABLE_HTTP = {408, 429, 502, 503, 504}
NON_RETRYABLE_HTTP = {400, 401, 403, 404, 409, 422}


class DispatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["codestra.n8n.dispatch.v1"]
    tenant_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$", max_length=128)
    source_event_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    causation_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=16, max_length=128)
    idempotency_key: str = Field(min_length=16, max_length=255)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def bounded_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, separators=(",", ":")).encode()
        if len(encoded) > 131072:
            raise ValueError("workflow payload exceeds limit")
        return value


class ResultContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["codestra.n8n.result.v1"]
    workflow_code: str = Field(pattern=r"^[A-Z][A-Z0-9_.-]+$", max_length=128)
    workflow_version: str = Field(min_length=1, max_length=32)
    execution_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=64)
    status: Literal["running", "completed", "failed", "retry", "dead_letter"]
    occurred_at: datetime
    result: dict[str, Any] = Field(default_factory=dict)
    error_code: str | None = Field(default=None, max_length=64)

    @field_validator("occurred_at")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("UTC timestamp required")
        return value.astimezone(UTC)


class SocialEventEnvelope(BaseModel):
    """Strict provider-neutral social event accepted by the n8n router."""

    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(pattern=r"^social\.[a-z0-9_.-]+$", max_length=128)
    event_version: Literal[1]
    occurred_at: datetime
    correlation_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=64)
    source: Literal["social"]
    provider: Literal["postly", "hootsuite"]
    subject_id: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def bounded_social_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, separators=(",", ":")).encode()
        if len(encoded) > 65536:
            raise ValueError("social event payload exceeds limit")
        forbidden = {
            "authorization",
            "access_token",
            "refresh_token",
            "api_key",
            "password",
            "client_secret",
            "cookie",
        }

        def contains_secret(document: Any) -> bool:
            if isinstance(document, dict):
                return any(
                    str(key).lower() in forbidden or contains_secret(item)
                    for key, item in document.items()
                )
            if isinstance(document, list):
                return any(contains_secret(item) for item in document)
            return False

        if contains_secret(value):
            raise ValueError("social event payload contains forbidden credentials")
        return value


def canonical_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    document = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_secret(filename: str) -> bytes:
    path = Path(filename)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise RuntimeError("n8n runtime signing secret is unavailable")
    value = path.read_bytes().strip()
    if len(value) < 32:
        raise RuntimeError("n8n runtime signing secret is invalid")
    return value


def signature_payload(
    *,
    identity: str,
    tenant_id: str,
    workflow_code: str,
    execution_id: str,
    correlation_id: str,
    timestamp: str,
    nonce: str,
    body_hash: str,
) -> bytes:
    return "\n".join(
        (
            "v1",
            identity,
            tenant_id,
            workflow_code,
            execution_id,
            correlation_id,
            timestamp,
            nonce,
            body_hash,
        )
    ).encode()


def sign_runtime(**values: str | bytes) -> str:
    secret = values.pop("secret")
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    return hmac.new(secret, signature_payload(**values), hashlib.sha256).hexdigest()  # type: ignore[arg-type]


def verify_runtime(signature: str, secret: bytes, **values: str) -> None:
    expected = sign_runtime(secret=secret, **values)
    if not hmac.compare_digest(signature.removeprefix("sha256="), expected):
        raise ValueError("invalid runtime signature")


def verify_fresh(timestamp: str, ttl_seconds: int = 300) -> None:
    try:
        parsed = int(timestamp)
    except ValueError as exc:
        raise ValueError("invalid runtime timestamp") from exc
    if abs(int(time.time()) - parsed) > ttl_seconds:
        raise ValueError("expired runtime timestamp")


def retry_delay(attempt: int, base: float = 1.0, cap: float = 60.0) -> float:
    if attempt < 1:
        raise ValueError("attempt must be positive")
    return secrets.SystemRandom().uniform(0, min(cap, base * (2 ** (attempt - 1))))


def retryable(status_code: int | None, network_error: bool = False) -> bool:
    return network_error or status_code in RETRYABLE_HTTP
