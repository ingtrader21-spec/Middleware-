"""Deterministic command idempotency, retry classification, and dead-letter policy."""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

RetryClass = Literal["retryable","permanent"]

class IdempotencyConflict(RuntimeError): pass

def request_hash(command: dict[str, Any]) -> str:
    stable={k:v for k,v in command.items() if k not in {"command_id","created_at","updated_at"}}
    raw=json.dumps(stable,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()

@dataclass(frozen=True)
class Reservation:
    tenant_id: str
    idempotency_key: str
    request_sha256: str
    command_id: str

class IdempotencyRegistry:
    def __init__(self) -> None: self._items: dict[tuple[str,str],Reservation]={}
    def reserve(self, *, tenant_id: str, idempotency_key: str, command_id: str, request_sha256: str) -> tuple[Reservation,bool]:
        key=(tenant_id,idempotency_key); existing=self._items.get(key)
        if existing:
            if existing.request_sha256 != request_sha256:
                raise IdempotencyConflict("idempotency key reused with a different request")
            return existing, True
        value=Reservation(tenant_id,idempotency_key,request_sha256,command_id)
        self._items[key]=value
        return value, False

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int=5
    base_seconds: int=2
    max_seconds: int=300
    def delay(self, attempt: int) -> int:
        if attempt < 1: raise ValueError("attempt must be positive")
        return min(self.max_seconds,self.base_seconds*(2 ** (attempt-1)))

PERMANENT_CODES=frozenset({"invalid_request","unauthorized","forbidden","not_found","conflict","capability_disabled"})
RETRYABLE_CODES=frozenset({"timeout","rate_limited","provider_unavailable","connection_error","lease_expired"})

def classify_failure(code: str, *, http_status: int|None=None) -> RetryClass:
    if code in PERMANENT_CODES: return "permanent"
    if code in RETRYABLE_CODES: return "retryable"
    if http_status is not None:
        if http_status in {408,425,429} or 500 <= http_status <= 599: return "retryable"
        if 400 <= http_status <= 499: return "permanent"
    return "permanent"

@dataclass(frozen=True)
class RetryDecision:
    state: Literal["retry","dead_letter"]
    next_attempt_at: datetime|None
    classification: RetryClass
    reason: str

def decide_retry(*, attempt: int, error_code: str, now: datetime|None=None, http_status: int|None=None, policy: RetryPolicy=RetryPolicy()) -> RetryDecision:
    now=now or datetime.now(timezone.utc)
    classification=classify_failure(error_code,http_status=http_status)
    if classification=="permanent":
        return RetryDecision("dead_letter",None,classification,"non_retryable")
    if attempt >= policy.max_attempts:
        return RetryDecision("dead_letter",None,classification,"max_attempts_exhausted")
    return RetryDecision("retry",now+timedelta(seconds=policy.delay(attempt)),classification,"retry_scheduled")

def redrive_eligible(dead_letter: dict[str,Any]) -> bool:
    return bool(dead_letter.get("state")=="dead_lettered" and dead_letter.get("resolved_at") is None and dead_letter.get("redrive_blocked") is not True)
