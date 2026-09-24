import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


SENSITIVE_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
)


def correlation_id(value: str | None = None) -> str:
    return value or str(uuid.uuid4())


def canonical_hash(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]"
            if any(part in str(key).lower() for part in SENSITIVE_PARTS)
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(
            r"(?i)\b(authorization|cookie|credential|password|secret|token)\s*[:=]\s*[^\s,;]+",
            r"\1=[REDACTED]",
            value,
        )
        value = re.sub(
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value
        )
    return value


def sanitize_for_storage(payload: Any) -> Any:
    """Return the only representation permitted in durable event payload fields."""
    return redact(payload)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_seconds: int = 5
    max_seconds: int = 300

    def delay(self, attempts: int) -> int:
        if attempts < 1:
            raise ValueError("attempts must be positive")
        return min(self.max_seconds, self.base_seconds * (2 ** (attempts - 1)))


@dataclass
class OutboxItem:
    event_id: str
    topic: str
    payload: dict[str, Any]
    correlation_id: str
    status: str = "pending"
    attempts: int = 0
    next_attempt_at: datetime | None = None
    last_error: str | None = None

    def fail(self, error: str, policy: RetryPolicy, now: datetime) -> None:
        self.attempts += 1
        self.last_error = str(redact({"error": error})["error"])
        if self.attempts >= policy.max_attempts:
            self.status = "dead_letter"
            self.next_attempt_at = None
        else:
            self.status = "retry"
            self.next_attempt_at = now + timedelta(seconds=policy.delay(self.attempts))

    def recover(self, now: datetime, lock_timeout_seconds: int = 60) -> None:
        if (
            self.status == "processing"
            and self.next_attempt_at
            and self.next_attempt_at <= now - timedelta(seconds=lock_timeout_seconds)
        ):
            self.status = "retry"
            self.next_attempt_at = now

    def replay(self) -> None:
        if self.status != "dead_letter":
            raise ValueError("only dead-letter items may be replayed")
        self.status = "pending"
        self.attempts = 0
        self.next_attempt_at = None
        self.last_error = None


@dataclass
class IdempotencyLedger:
    entries: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)

    def register(self, scope: str, raw_key: str, payload: Any, event_id: str) -> str:
        key_hash = hashlib.sha256(f"{scope}\0{raw_key}".encode()).hexdigest()
        digest = canonical_hash(redact(payload))
        existing = self.entries.get((scope, key_hash))
        if not existing:
            self.entries[(scope, key_hash)] = (digest, event_id)
            return "created"
        return "replay" if existing == (digest, event_id) else "conflict"


@dataclass
class Reconciler:
    checkpoint: str | None = None

    def reconcile(
        self, authoritative_ids: set[str], observed_ids: set[str], cursor: str
    ) -> dict[str, set[str]]:
        result = {
            "missing": authoritative_ids - observed_ids,
            "unexpected": observed_ids - authoritative_ids,
        }
        self.checkpoint = cursor
        return result


def enforce_dnc(contact: dict[str, Any]) -> None:
    if contact.get("do_not_call") or str(contact.get("consent", "")).lower() in {
        "revoked",
        "denied",
    }:
        raise PermissionError("do-not-call policy denies contact")


def authorize_transfer(
    *, dnc: bool, authenticated: bool, role: str, campaign_id: str, live_enabled: bool
) -> tuple[bool, str]:
    if dnc:
        return False, "do-not-call"
    if not authenticated:
        return False, "authentication-required"
    if role not in {"supervisor", "manager"}:
        return False, "role-denied"
    if campaign_id != "TEST_SYN":
        return False, "campaign-denied"
    if not live_enabled:
        return False, "live-transfer-disabled"
    return True, "authorized"
