"""Bounded provider-canary controller (PAS-57).

A provider canary is described by a :class:`ProviderCanaryPlan` and evaluated
by :func:`evaluate_plan` against the operator-owned Settings caps. Every
missing prerequisite is an automatic denial with a stable reason code:

* the controller is disabled by default and refused in production;
* the plan is bound to one allowlisted tenant, one allowlisted connector
  target, the provider and capability that target owns, and ``TEST_SYN``;
* attempt, rate, spend, destination and duration budgets must be declared and
  must fit inside the Settings caps;
* owner approval, change ticket, provider readiness and rollback evidence must
  each be referenced exactly once with a canonical digest;
* a fresh kill-switch read-back must show the switch armed, and provider
  read-back must be required from a source valid for the channel.

Only synthetic execution exists. :func:`execute_synthetic` never imports or
calls a provider transport: it produces deterministic simulated read-back
marked ``synthetic`` whose source (``synthetic_simulator``) the real provider
evidence validator in :mod:`app.provider_canary` rejects, so a synthetic run
can never be presented as live provider proof. A ``live`` plan is always
denied; no live execution path is implemented.
"""

from __future__ import annotations

import re
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .provider_canary import (
    SUCCESS_STATUSES,
    TARGET_CHANNELS,
    CanaryChannel,
    EvidenceSource,
    canonical_fingerprint,
)

SYNTHETIC_CAMPAIGN = "TEST_SYN"
SYNTHETIC_READBACK_SOURCE = "synthetic_simulator"
REQUIRED_EVIDENCE_KINDS: tuple[str, ...] = (
    "owner_approval",
    "change_ticket",
    "provider_readiness",
    "rollback_plan",
)
EvidenceKind = Literal[
    "owner_approval", "change_ticket", "provider_readiness", "rollback_plan"
]

# target -> (provider, capability): the only provider and capability a canary
# for that connector target may name.
TARGET_BINDINGS: dict[str, tuple[str, str]] = {
    "klyrow-email": ("postal", "email.send"),
    "telnexa-sms": ("jasmin", "sms.send"),
    "vicidial-restricted": ("vicidial", "voice.call"),
    "postly-social": ("postiz", "social.publish"),
}
READBACK_SOURCES: dict[CanaryChannel, frozenset[str]] = {
    "email": frozenset({"provider_api", "provider_webhook"}),
    "sms": frozenset({"provider_api", "provider_webhook"}),
    "voice": frozenset({"provider_cdr"}),
    "social": frozenset({"provider_api"}),
}

_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
_RATE_WINDOW = timedelta(seconds=60)
_RUN_NAMESPACE = uuid.UUID("6f0f8f55-1d2b-4b53-9a57-5a0e3c7d57a1")


def _aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return value


def _fingerprint(value: str, name: str) -> str:
    if _FINGERPRINT.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical sha256 fingerprint")
    return value


class CanaryEvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    reference: str = Field(min_length=1, max_length=256)
    digest: str

    @field_validator("reference")
    @classmethod
    def safe_reference(cls, value: str) -> str:
        if _SAFE_REFERENCE.fullmatch(value) is None:
            raise ValueError("evidence reference contains unsafe characters")
        return value

    @field_validator("digest")
    @classmethod
    def canonical_digest(cls, value: str) -> str:
        return _fingerprint(value, "evidence digest")


class CanaryBudget(BaseModel):
    """Declared budget; structural bounds here, operator caps in the policy."""

    model_config = ConfigDict(extra="forbid")

    max_attempts: int = Field(ge=1, le=100)
    max_rate_per_minute: int = Field(ge=1, le=60)
    max_spend_minor_units: int = Field(ge=0, le=1_000_000)
    spend_currency: Literal["USD"] = "USD"
    max_destinations: int = Field(ge=1, le=100)
    max_duration_seconds: int = Field(ge=1, le=86_400)


class KillSwitchReadback(BaseModel):
    """Operator read-back of the provider-side kill switch before a canary."""

    model_config = ConfigDict(extra="forbid")

    reference: str = Field(min_length=1, max_length=256)
    state: Literal["armed", "tripped", "unknown"]
    observed_at: datetime

    @field_validator("reference")
    @classmethod
    def safe_reference(cls, value: str) -> str:
        if _SAFE_REFERENCE.fullmatch(value) is None:
            raise ValueError("kill-switch reference contains unsafe characters")
        return value

    @field_validator("observed_at")
    @classmethod
    def aware_observed_at(cls, value: datetime) -> datetime:
        return _aware(value, "observed_at")


class ReadbackRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required: bool
    source: EvidenceSource
    timeout_seconds: int = Field(ge=1, le=3_600)


class ProviderCanaryPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    canary_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    campaign_id: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=64)
    provider: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    capability: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")
    mode: Literal["synthetic", "live"] = "synthetic"
    destination_fingerprints: list[str] = Field(min_length=1, max_length=100)
    payload_fingerprint: str
    budget: CanaryBudget
    not_before: datetime
    not_after: datetime
    # Prerequisites are optional in the schema on purpose: a missing
    # prerequisite is a policy denial with a reason code, not a 422.
    evidence: list[CanaryEvidenceRef] = Field(default_factory=list, max_length=16)
    kill_switch: KillSwitchReadback | None = None
    readback: ReadbackRequirement | None = None

    @field_validator("destination_fingerprints")
    @classmethod
    def canonical_destinations(cls, values: list[str]) -> list[str]:
        for value in values:
            _fingerprint(value, "destination fingerprint")
        if len(set(values)) != len(values):
            raise ValueError("destination fingerprints must be unique")
        return values

    @field_validator("payload_fingerprint")
    @classmethod
    def canonical_payload(cls, value: str) -> str:
        return _fingerprint(value, "payload fingerprint")

    @field_validator("not_before", "not_after")
    @classmethod
    def aware_window(cls, value: datetime) -> datetime:
        return _aware(value, "canary window")

    @model_validator(mode="after")
    def ordered_window(self) -> ProviderCanaryPlan:
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be later than not_before")
        return self

    def digest(self) -> str:
        return canonical_fingerprint(self.model_dump(mode="json"))


class CanaryPolicySettings(Protocol):
    app_env: str
    provider_canary_controller_enabled: bool
    provider_canary_kill_switch_engaged: bool
    provider_canary_allowed_tenant_ids: str
    provider_canary_allowed_targets: str
    provider_canary_max_attempts: int
    provider_canary_max_rate_per_minute: int
    provider_canary_max_destinations: int
    provider_canary_max_duration_seconds: int
    provider_canary_max_spend_minor_units: int
    provider_canary_kill_switch_readback_max_age_seconds: int


def _csv(value: str) -> frozenset[str]:
    return frozenset(item.strip() for item in value.split(",") if item.strip())


def policy_caps(settings: CanaryPolicySettings) -> dict[str, Any]:
    return {
        "allowed_tenant_ids": sorted(_csv(settings.provider_canary_allowed_tenant_ids)),
        "allowed_targets": sorted(_csv(settings.provider_canary_allowed_targets)),
        "max_attempts": settings.provider_canary_max_attempts,
        "max_rate_per_minute": settings.provider_canary_max_rate_per_minute,
        "max_destinations": settings.provider_canary_max_destinations,
        "max_duration_seconds": settings.provider_canary_max_duration_seconds,
        "max_spend_minor_units": settings.provider_canary_max_spend_minor_units,
        "kill_switch_readback_max_age_seconds": (
            settings.provider_canary_kill_switch_readback_max_age_seconds
        ),
    }


@dataclass(frozen=True)
class CanaryDecision:
    canary_id: str
    plan_digest: str
    reasons: tuple[str, ...]
    evaluated_at: datetime

    @property
    def allowed(self) -> bool:
        return not self.reasons

    def as_dict(self) -> dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "decision": "ALLOW_SYNTHETIC" if self.allowed else "DENY",
            "allowed": self.allowed,
            "execution_mode": "synthetic",
            "live_execution_available": False,
            "reasons": list(self.reasons),
            "plan_digest": self.plan_digest,
            "evaluated_at": self.evaluated_at.isoformat(),
            "provider_effects": 0,
        }


def evaluate_plan(
    plan: ProviderCanaryPlan,
    settings: CanaryPolicySettings,
    *,
    now: datetime,
    runtime_kill_switch_engaged: bool = False,
    recent_runs: int = 0,
) -> CanaryDecision:
    """Return every reason the plan is denied; no reasons means ALLOW_SYNTHETIC."""

    _aware(now, "now")
    reasons: list[str] = []
    deny = reasons.append

    if not settings.provider_canary_controller_enabled:
        deny("CONTROLLER_DISABLED")
    if settings.app_env == "production":
        deny("PRODUCTION_ENVIRONMENT_FORBIDDEN")
    if settings.provider_canary_kill_switch_engaged or runtime_kill_switch_engaged:
        deny("KILL_SWITCH_ENGAGED")
    if plan.mode != "synthetic":
        deny("LIVE_EXECUTION_NOT_AUTHORIZED")
    if plan.campaign_id != SYNTHETIC_CAMPAIGN:
        deny("CAMPAIGN_NOT_TEST_SYN")

    # Tenant / target / provider / capability bounds.
    if plan.tenant_id not in _csv(settings.provider_canary_allowed_tenant_ids):
        deny("TENANT_NOT_ALLOWED")
    binding = TARGET_BINDINGS.get(plan.target)
    if binding is None:
        deny("TARGET_UNKNOWN")
    else:
        if plan.target not in _csv(settings.provider_canary_allowed_targets):
            deny("TARGET_NOT_ALLOWED")
        provider, capability = binding
        if plan.provider != provider:
            deny("PROVIDER_MISMATCH")
        if plan.capability != capability:
            deny("CAPABILITY_MISMATCH")

    # Budgets against operator caps and against the plan's own declarations.
    budget = plan.budget
    if budget.max_attempts > settings.provider_canary_max_attempts:
        deny("BUDGET_ATTEMPTS_EXCEEDS_CAP")
    if budget.max_rate_per_minute > settings.provider_canary_max_rate_per_minute:
        deny("BUDGET_RATE_EXCEEDS_CAP")
    if budget.max_destinations > settings.provider_canary_max_destinations:
        deny("BUDGET_DESTINATIONS_EXCEEDS_CAP")
    if budget.max_duration_seconds > settings.provider_canary_max_duration_seconds:
        deny("BUDGET_DURATION_EXCEEDS_CAP")
    if budget.max_spend_minor_units > settings.provider_canary_max_spend_minor_units:
        deny("BUDGET_SPEND_EXCEEDS_CAP")
    if len(plan.destination_fingerprints) > budget.max_destinations:
        deny("DESTINATIONS_EXCEED_BUDGET")
    if len(plan.destination_fingerprints) > budget.max_attempts:
        deny("ATTEMPTS_EXCEED_BUDGET")
    window = (plan.not_after - plan.not_before).total_seconds()
    if window > budget.max_duration_seconds:
        deny("WINDOW_EXCEEDS_DURATION_BUDGET")
    if now < plan.not_before:
        deny("WINDOW_NOT_OPEN")
    if now >= plan.not_after:
        deny("WINDOW_EXPIRED")
    if recent_runs >= min(
        budget.max_rate_per_minute, settings.provider_canary_max_rate_per_minute
    ):
        deny("RATE_BUDGET_EXHAUSTED")

    # Evidence prerequisites: every kind exactly once.
    kinds = [item.kind for item in plan.evidence]
    for kind in REQUIRED_EVIDENCE_KINDS:
        count = kinds.count(kind)
        if count == 0:
            deny(f"EVIDENCE_MISSING:{kind}")
        elif count > 1:
            deny(f"EVIDENCE_DUPLICATE:{kind}")

    # Kill-switch read-back.
    kill_switch = plan.kill_switch
    if kill_switch is None:
        deny("KILL_SWITCH_READBACK_MISSING")
    else:
        if kill_switch.state != "armed":
            deny("KILL_SWITCH_NOT_ARMED")
        age = (now - kill_switch.observed_at).total_seconds()
        if age < 0:
            deny("KILL_SWITCH_READBACK_FROM_FUTURE")
        elif age > settings.provider_canary_kill_switch_readback_max_age_seconds:
            deny("KILL_SWITCH_READBACK_STALE")

    # Provider read-back requirement.
    readback = plan.readback
    if readback is None:
        deny("READBACK_REQUIREMENT_MISSING")
    else:
        if not readback.required:
            deny("READBACK_NOT_REQUIRED")
        channel = TARGET_CHANNELS.get(plan.target)
        if channel is not None and readback.source not in READBACK_SOURCES[channel]:
            deny("READBACK_SOURCE_INVALID_FOR_CHANNEL")

    return CanaryDecision(
        canary_id=plan.canary_id,
        plan_digest=plan.digest(),
        reasons=tuple(reasons),
        evaluated_at=now,
    )


@dataclass
class SyntheticCanaryRun:
    run_id: str
    canary_id: str
    tenant_id: str
    target: str
    provider: str
    capability: str
    plan_digest: str
    status: Literal["completed", "halted"]
    started_at: datetime
    completed_at: datetime
    attempts: list[dict[str, Any]] = field(default_factory=list)
    halt_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        verified = self.status == "completed" and all(
            attempt["readback"]["verified"] for attempt in self.attempts
        )
        return {
            "run_id": self.run_id,
            "canary_id": self.canary_id,
            "tenant_id": self.tenant_id,
            "target": self.target,
            "provider": self.provider,
            "capability": self.capability,
            "plan_digest": self.plan_digest,
            "execution_mode": "synthetic",
            "synthetic": True,
            "status": self.status,
            "halt_reason": self.halt_reason,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "attempt_count": len(self.attempts),
            "attempts": self.attempts,
            "readback_verified": verified,
            "spend_minor_units": 0,
            "provider_calls": 0,
            "provider_effects": 0,
            "evidence_digest": canonical_fingerprint(
                {
                    "run_id": self.run_id,
                    "plan_digest": self.plan_digest,
                    "status": self.status,
                    "attempts": self.attempts,
                }
            ),
        }


def execute_synthetic(
    plan: ProviderCanaryPlan,
    decision: CanaryDecision,
    *,
    now: datetime,
    kill_switch_engaged: Any = lambda: False,
) -> SyntheticCanaryRun:
    """Simulate the canary without any provider transport.

    ``kill_switch_engaged`` is polled before every attempt so an engaged
    switch halts the run between attempts.
    """

    if not decision.allowed or decision.plan_digest != plan.digest():
        raise PermissionError("synthetic execution requires an allowing decision")
    if plan.mode != "synthetic":
        raise PermissionError("only synthetic execution is implemented")
    channel = TARGET_CHANNELS[plan.target]
    terminal_status = sorted(SUCCESS_STATUSES[channel])[0]
    run = SyntheticCanaryRun(
        run_id=str(uuid.uuid5(_RUN_NAMESPACE, f"{plan.canary_id}:{decision.plan_digest}")),
        canary_id=plan.canary_id,
        tenant_id=plan.tenant_id,
        target=plan.target,
        provider=plan.provider,
        capability=plan.capability,
        plan_digest=decision.plan_digest,
        status="completed",
        started_at=now,
        completed_at=now,
    )
    for index, destination in enumerate(plan.destination_fingerprints, start=1):
        if kill_switch_engaged():
            run.status = "halted"
            run.halt_reason = "KILL_SWITCH_ENGAGED"
            break
        reference = "syn-" + canonical_fingerprint(
            [run.run_id, index, destination]
        ).removeprefix("sha256:")[:32]
        run.attempts.append(
            {
                "attempt": index,
                "destination_fingerprint": destination,
                "payload_fingerprint": plan.payload_fingerprint,
                "synthetic_reference": reference,
                "terminal_status": terminal_status,
                "readback": {
                    "source": SYNTHETIC_READBACK_SOURCE,
                    "synthetic": True,
                    "provider_reference": reference,
                    "destination_fingerprint": destination,
                    "payload_fingerprint": plan.payload_fingerprint,
                    "terminal_status": terminal_status,
                    "observed_at": now.isoformat(),
                    "verified": True,
                },
            }
        )
    return run


class IdempotencyConflict(RuntimeError):
    """The canary id was already executed with a different plan."""


class ProviderCanaryLedger:
    """Bounded, process-local record of synthetic runs and denials.

    Synthetic runs carry no provider effect, so process-local retention is
    sufficient: it provides idempotency by ``canary_id``, the per
    ``(tenant, target)`` rate window, the runtime kill switch and read-back of
    completed runs.
    """

    def __init__(self, *, max_runs: int = 256, max_denials: int = 256) -> None:
        self._lock = threading.Lock()
        self._max_runs = max_runs
        self._runs: dict[str, SyntheticCanaryRun] = {}
        self._by_canary: dict[str, str] = {}
        self._starts: dict[tuple[str, str], deque[datetime]] = {}
        self._denials: deque[dict[str, Any]] = deque(maxlen=max_denials)
        self._kill_switch: dict[str, Any] | None = None

    @property
    def kill_switch_engaged(self) -> bool:
        return self._kill_switch is not None

    def engage_kill_switch(self, *, actor: str, reason: str, now: datetime) -> dict[str, Any]:
        with self._lock:
            if self._kill_switch is None:
                self._kill_switch = {
                    "engaged": True,
                    "engaged_by": actor,
                    "reason": reason,
                    "engaged_at": now.isoformat(),
                }
            return dict(self._kill_switch)

    def kill_switch_state(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._kill_switch) if self._kill_switch else {"engaged": False}

    def recent_runs(self, tenant_id: str, target: str, now: datetime) -> int:
        with self._lock:
            starts = self._starts.get((tenant_id, target))
            if not starts:
                return 0
            while starts and now - starts[0] >= _RATE_WINDOW:
                starts.popleft()
            return len(starts)

    def existing(self, plan: ProviderCanaryPlan) -> SyntheticCanaryRun | None:
        with self._lock:
            run_id = self._by_canary.get(plan.canary_id)
            if run_id is None:
                return None
            run = self._runs[run_id]
            if run.plan_digest != plan.digest():
                raise IdempotencyConflict(plan.canary_id)
            return run

    def record_run(self, run: SyntheticCanaryRun) -> None:
        with self._lock:
            if len(self._runs) >= self._max_runs:
                oldest = next(iter(self._runs))
                evicted = self._runs.pop(oldest)
                self._by_canary.pop(evicted.canary_id, None)
            self._runs[run.run_id] = run
            self._by_canary[run.canary_id] = run.run_id
            self._starts.setdefault((run.tenant_id, run.target), deque()).append(
                run.started_at
            )

    def record_denial(self, decision: CanaryDecision) -> None:
        with self._lock:
            self._denials.append(decision.as_dict())

    def get(self, run_id: str) -> SyntheticCanaryRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {"runs": len(self._runs), "denials": len(self._denials)}
