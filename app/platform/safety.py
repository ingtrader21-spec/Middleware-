"""The one Safety authority of the command kernel.

The Safety Gate is evaluated after the Policy Engine and before a command is
persisted, and again by the worker before an adapter is invoked. It fails
closed. A configuration switch alone is never sufficient to activate an
effect: an external-effect capability is admitted only when *every* one of
these agrees —

* the capability registry (``config/capabilities.v2.json``) lists and enables
  it — a capability it does not list is denied ``capability_unknown`` whatever
  its classification,
* every Settings effect gate and umbrella control the switch table names is
  on (``Settings.external_effects`` / ``Settings.umbrella_controls``),
* the global and the provider kill switches are off,
* the deployment environment is one the capability may run in,
* an adapter owning the command is registered and reported ready,
* the tenant is within its rate budget and the backlog is below its bound,
* a campaign is named where the capability is campaign scoped,
* a synthetic capability names a synthetic tenant.

The switch table lives in ``config/platform-safety.v1.json``. Kill switches
may be tightened at runtime through :meth:`SafetyGate.trip`; nothing here can
loosen a switch.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from app.commands import CommandPolicyRegistry
from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]
SAFETY_PATH = ROOT / "config" / "platform-safety.v1.json"


class SafetyConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class CapabilityGate:
    capability: str
    classification: str
    effect_flags: tuple[str, ...]
    umbrella_controls: tuple[str, ...]
    environments: tuple[str, ...]
    campaign_scoped: bool
    synthetic_tenant_required: bool


@dataclass(frozen=True)
class SafetyLimits:
    tenant_commands_per_minute: int
    tenant_backlog_bound: int
    global_backlog_bound: int


@dataclass(frozen=True)
class SafetySwitches:
    safety_version: str
    global_kill_switch: bool
    provider_kill_switches: Mapping[str, bool]
    synthetic_tenants: frozenset[str]
    gates: Mapping[str, CapabilityGate]
    limits: SafetyLimits

    @classmethod
    def load(cls, path: Path = SAFETY_PATH) -> "SafetySwitches":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != "1.0":
            raise SafetyConfigurationError("unsupported safety switch table schema")
        version = raw.get("safety_version")
        if not isinstance(version, str) or not version:
            raise SafetyConfigurationError("safety_version is required")
        kill = raw.get("global_kill_switch")
        if not isinstance(kill, bool):
            raise SafetyConfigurationError("global_kill_switch must be a boolean")
        providers = raw.get("provider_kill_switches")
        if not isinstance(providers, dict) or not all(
            isinstance(k, str) and isinstance(v, bool) for k, v in providers.items()
        ):
            raise SafetyConfigurationError("provider_kill_switches must map provider -> bool")
        synthetic = raw.get("synthetic_tenants")
        if not isinstance(synthetic, list) or not all(isinstance(item, str) and item for item in synthetic):
            raise SafetyConfigurationError("synthetic_tenants must be a list of tenant ids")
        gates_raw = raw.get("capability_gates")
        if not isinstance(gates_raw, dict) or not gates_raw:
            raise SafetyConfigurationError("capability_gates must not be empty")
        gates: dict[str, CapabilityGate] = {}
        for capability, item in gates_raw.items():
            if not isinstance(item, dict):
                raise SafetyConfigurationError(f"{capability}: gate must be an object")
            classification = item.get("classification")
            if classification not in {"external_effect", "internal", "synthetic"}:
                raise SafetyConfigurationError(f"{capability}: unknown classification {classification!r}")
            environments = item.get("environments")
            if not isinstance(environments, list) or not environments:
                raise SafetyConfigurationError(f"{capability}: environments must not be empty")
            gates[capability] = CapabilityGate(
                capability=capability,
                classification=classification,
                effect_flags=tuple(item.get("effect_flags", ())),
                umbrella_controls=tuple(item.get("umbrella_controls", ())),
                environments=tuple(environments),
                campaign_scoped=item.get("campaign_scoped") is True,
                synthetic_tenant_required=item.get("synthetic_tenant_required") is True,
            )
        limits_raw = raw.get("limits") or {}
        limits = SafetyLimits(
            tenant_commands_per_minute=int(limits_raw.get("tenant_commands_per_minute", 600)),
            tenant_backlog_bound=int(limits_raw.get("tenant_backlog_bound", 1000)),
            global_backlog_bound=int(limits_raw.get("global_backlog_bound", 10000)),
        )
        if min(limits.tenant_commands_per_minute, limits.tenant_backlog_bound, limits.global_backlog_bound) < 1:
            raise SafetyConfigurationError("limits must be positive")
        return cls(
            safety_version=version,
            global_kill_switch=kill,
            provider_kill_switches=dict(providers),
            synthetic_tenants=frozenset(synthetic),
            gates=gates,
            limits=limits,
        )


@dataclass(frozen=True)
class SafetySubject:
    tenant_id: str
    command_type: str
    target: str
    capability: str
    campaign_id: str | None = None
    correlation_id: str = ""


@dataclass(frozen=True)
class SafetyContext:
    """Runtime facts the gate cannot know by itself."""

    adapter_registered: bool
    adapter_ready: bool | None
    tenant_backlog: int | None = None
    global_backlog: int | None = None


@dataclass(frozen=True)
class SafetyDecision:
    decision_id: str
    safety_version: str
    correlation_id: str
    allow: bool
    reason_code: str
    reason_codes: tuple[str, ...]
    classification: str
    saturated: bool = False
    safe_metadata: Mapping[str, str | bool | int] = field(default_factory=dict)

    def evidence(self) -> dict[str, Any]:
        return {
            "safety_decision_id": self.decision_id,
            "safety_version": self.safety_version,
            "safety_allow": self.allow,
            "safety_reason_code": self.reason_code,
        }


class _TokenBucket:
    """Per-tenant sliding budget; bounded memory (tenants seen recently)."""

    def __init__(self, per_minute: int, *, clock=time.monotonic, max_tenants: int = 10_000) -> None:
        self.per_minute = per_minute
        self.clock = clock
        self.max_tenants = max_tenants
        self._lock = threading.Lock()
        self._state: dict[str, tuple[float, float]] = {}

    def admit(self, tenant_id: str) -> bool:
        now = self.clock()
        with self._lock:
            tokens, updated = self._state.get(tenant_id, (float(self.per_minute), now))
            tokens = min(float(self.per_minute), tokens + (now - updated) * (self.per_minute / 60.0))
            if tokens < 1.0:
                self._state[tenant_id] = (tokens, now)
                return False
            self._state[tenant_id] = (tokens - 1.0, now)
            if len(self._state) > self.max_tenants:
                oldest = min(self._state, key=lambda key: self._state[key][1])
                self._state.pop(oldest, None)
            return True


class SafetyGate:
    def __init__(
        self,
        settings: Settings,
        policies: CommandPolicyRegistry,
        switches: SafetySwitches | None = None,
        *,
        clock=time.monotonic,
    ) -> None:
        self.settings = settings
        self.policies = policies
        self.switches = switches or SafetySwitches.load()
        self._tripped_global = False
        self._tripped_providers: set[str] = set()
        self._budget = _TokenBucket(self.switches.limits.tenant_commands_per_minute, clock=clock)

    # ------------------------------------------------------------------
    # Runtime tightening (never loosening)
    # ------------------------------------------------------------------
    def trip(self, provider: str | None = None) -> None:
        if provider is None:
            self._tripped_global = True
        else:
            self._tripped_providers.add(provider)

    @property
    def global_kill(self) -> bool:
        return self.switches.global_kill_switch or self._tripped_global

    def provider_kill(self, provider: str) -> bool:
        return self.switches.provider_kill_switches.get(provider, False) or provider in self._tripped_providers

    def gate(self, capability: str) -> CapabilityGate | None:
        return self.switches.gates.get(capability)

    def classification(self, capability: str) -> str:
        gate = self.gate(capability)
        # An unknown capability is the most dangerous class until listed.
        return gate.classification if gate is not None else "external_effect"

    def campaign_scoped(self, capability: str) -> bool:
        gate = self.gate(capability)
        return gate.campaign_scoped if gate is not None else False

    # ------------------------------------------------------------------
    # Decision
    # ------------------------------------------------------------------
    def evaluate(self, subject: SafetySubject, context: SafetyContext, *, consume_budget: bool = True) -> SafetyDecision:
        reasons: list[str] = []
        saturated = False
        gate = self.gate(subject.capability)
        classification = gate.classification if gate is not None else "external_effect"
        environment = self.settings.app_env

        if self.global_kill:
            reasons.append("global_kill_switch")
        if self.provider_kill(subject.target):
            reasons.append("provider_kill_switch")
        if gate is None:
            reasons.append("capability_without_safety_gate")
        if subject.capability not in self.policies.capabilities:
            # Unknown to the capability registry: denied whatever its class.
            reasons.append("capability_unknown")
        if gate is not None:
            if environment not in gate.environments:
                reasons.append("environment_not_authorized")
            if gate.campaign_scoped and not subject.campaign_id:
                reasons.append("campaign_scope_required")
            if gate.synthetic_tenant_required and subject.tenant_id not in self.switches.synthetic_tenants:
                reasons.append("synthetic_tenant_required")
            if classification == "external_effect":
                if self.policies.capabilities.get(subject.capability) is not True:
                    reasons.append("capability_disabled")
                effects = self.settings.external_effects
                for flag in gate.effect_flags:
                    if effects.get(flag) is not True:
                        reasons.append(f"effect_gate_off:{flag}")
                umbrella = self.settings.umbrella_controls
                for control in gate.umbrella_controls:
                    if umbrella.get(control) is not True:
                        reasons.append(f"umbrella_control_off:{control}")
            elif classification == "synthetic":
                if self.policies.capabilities.get(subject.capability) is not True:
                    reasons.append("capability_disabled")
        if not context.adapter_registered:
            reasons.append("adapter_not_registered")
        elif context.adapter_ready is False:
            reasons.append("adapter_not_ready")

        limits = self.switches.limits
        if context.global_backlog is not None and context.global_backlog >= limits.global_backlog_bound:
            reasons.append("global_backlog_saturated")
            saturated = True
        if context.tenant_backlog is not None and context.tenant_backlog >= limits.tenant_backlog_bound:
            reasons.append("tenant_backlog_saturated")
            saturated = True
        if consume_budget and not reasons and not self._budget.admit(subject.tenant_id):
            reasons.append("tenant_rate_limited")
            saturated = True

        return SafetyDecision(
            decision_id=str(uuid4()),
            safety_version=self.switches.safety_version,
            correlation_id=subject.correlation_id,
            allow=not reasons,
            reason_code=reasons[0] if reasons else "allowed",
            reason_codes=tuple(reasons) or ("allowed",),
            classification=classification,
            saturated=saturated,
            safe_metadata={
                "environment": environment,
                "capability": subject.capability,
                "target": subject.target,
                "classification": classification,
                "global_kill_switch": self.global_kill,
            },
        )

    def describe(self) -> dict[str, Any]:
        return {
            "safety_version": self.switches.safety_version,
            "global_kill_switch": self.global_kill,
            "provider_kill_switches": {
                provider: self.provider_kill(provider)
                for provider in sorted(set(self.switches.provider_kill_switches) | self._tripped_providers)
            },
            "synthetic_tenants": sorted(self.switches.synthetic_tenants),
            "limits": {
                "tenant_commands_per_minute": self.switches.limits.tenant_commands_per_minute,
                "tenant_backlog_bound": self.switches.limits.tenant_backlog_bound,
                "global_backlog_bound": self.switches.limits.global_backlog_bound,
            },
            "effect_defaults": {
                capability: {
                    "enabled": self.policies.capabilities.get(capability) is True,
                    "classification": gate.classification,
                }
                for capability, gate in sorted(self.switches.gates.items())
            },
        }
