"""The command kernel: one orchestrator over the existing command ledger.

``CommandKernel.submit`` runs steps 9–18 of the canonical submission sequence
(registry resolution, adapter ownership, Policy Engine, Safety Gate,
idempotency + persistence + audit + outbox intent in one transaction) on top
of :class:`app.commands.CommandService`. It never executes a provider effect;
that is the ExecutionBus's job after commit. Reads, cancellation and replay
delegate to the same ledger.

There is no second store, no second state machine and no second policy or
capability registry here.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import UUID, uuid4

from app.commands import (
    ADAPTER_COMMAND_DESTINATION,
    ALLOWED_COMMAND_TRANSITIONS,
    API_OPERATION_STATES,
    TEMPORAL_COMMAND_DESTINATION,
    CommandCapabilityDisabled,
    CommandConflict,
    CommandEnvelope,
    CommandError,
    CommandNotFound,
    CommandOperation,
    CommandService,
    OperationAttempt,
    OperationEvent,
    redact_metadata,
)
from app.core.config import Settings
from app.core.policy_engine import (
    COMMAND_POLICY_VERSION,
    PLATFORM_OPERATOR_ROLE,
    CommandPolicyDecision,
    CommandPolicyRequest,
    evaluate_command,
)
from app.platform.metrics import KernelMetrics
from app.platform.principal import KernelPrincipal
from app.platform.registry import AdapterRegistry
from app.platform.resilience import ReplayMode
from app.platform.safety import SafetyContext, SafetyDecision, SafetyGate, SafetySubject

logger = logging.getLogger("codestra.platform.kernel")

SCOPE_COMMAND = "platform.command"
SCOPE_COMMAND_READ = "platform.command.read"
SCOPE_COMMAND_REPLAY = "platform.command.replay"


class PolicyDenied(CommandError):
    status_code = 403
    code = "policy_denied"


class SafetyDenied(CommandError):
    status_code = 403
    code = "safety_denied"


class KernelSaturated(CommandError):
    status_code = 429
    code = "kernel_saturated"
    retryable = True


class ReplayNotAllowed(CommandError):
    status_code = 409
    code = "replay_not_allowed"


class CapabilityUnknown(CommandCapabilityDisabled):
    """The capability is not listed in the capability registry."""

    code = "capability_unknown"


class AdapterNotFound(CommandError):
    status_code = 404
    code = "adapter_not_found"


class CommandUnowned(CommandError):
    status_code = 403
    code = "command_unowned"


@dataclass(frozen=True)
class SubmitResult:
    operation: CommandOperation
    policy: CommandPolicyDecision
    safety: SafetyDecision
    destination: str

    @property
    def duplicate(self) -> bool:
        return self.operation.duplicate


@dataclass(frozen=True)
class DenialAudit:
    """What the kernel records for a denied submission (no command row exists)."""

    kind: str
    tenant_id: str
    command_id: UUID
    command_type: str
    target: str
    capability: str
    actor_id: str
    client_id: str
    correlation_id: str
    reason_code: str
    decision_id: str
    version: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DenialAuditSink:
    """Where policy/safety denials are recorded. The Postgres implementation
    writes ``middleware_control_audit`` (immutable); the memory one keeps a list."""

    async def record(self, audit: DenialAudit) -> None:  # pragma: no cover - protocol
        raise NotImplementedError


class MemoryDenialAuditSink(DenialAuditSink):
    def __init__(self) -> None:
        self.records: list[DenialAudit] = []

    async def record(self, audit: DenialAudit) -> None:
        self.records.append(audit)


class _BacklogCache:
    def __init__(self, ttl_seconds: float = 2.0, *, clock=time.monotonic) -> None:
        self.ttl = ttl_seconds
        self.clock = clock
        self._values: dict[str, tuple[float, tuple[int, int]]] = {}

    def get(self, tenant_id: str) -> tuple[int, int] | None:
        item = self._values.get(tenant_id)
        if item is None or self.clock() - item[0] > self.ttl:
            return None
        return item[1]

    def put(self, tenant_id: str, value: tuple[int, int]) -> None:
        if len(self._values) > 10_000:
            self._values.clear()
        self._values[tenant_id] = (self.clock(), value)


class CommandKernel:
    def __init__(
        self,
        *,
        settings: Settings,
        commands: CommandService,
        registry: AdapterRegistry,
        safety: SafetyGate,
        metrics: KernelMetrics,
        denials: DenialAuditSink,
        service_id: str,
    ) -> None:
        self.settings = settings
        self.commands = commands
        self.registry = registry
        self.safety = safety
        self.metrics = metrics
        self.denials = denials
        self.service_id = service_id
        self._backlog = _BacklogCache()

    # ------------------------------------------------------------------
    # Submission (steps 9–18)
    # ------------------------------------------------------------------
    def _policy_request(
        self,
        command: CommandEnvelope,
        principal: KernelPrincipal,
        *,
        required_scope: str,
        operator_required: bool = False,
    ) -> CommandPolicyRequest:
        return CommandPolicyRequest(
            correlation_id=command.correlation_id,
            principal=principal.subject,
            client_id=principal.client_id,
            tenant_id=command.tenant_id,
            authorized_tenants=principal.tenants,
            roles=principal.roles,
            scopes=principal.scopes,
            required_scope=required_scope,
            command_type=command.command_type,
            target=command.target,
            capability=command.capability,
            campaign_id=_campaign_id(command.payload),
            environment=self.settings.app_env,  # type: ignore[arg-type]
            effect_classification=self.safety.classification(command.capability),  # type: ignore[arg-type]
            caller_command_prefixes=principal.caller.allowed_command_prefixes,
            caller_targets=tuple(sorted(principal.caller.allowed_targets)),
            caller_connector_commands_allowed=principal.caller.connector_commands_allowed,
            campaign_scoped=self.safety.campaign_scoped(command.capability),
            operator_required=operator_required,
        )

    async def _backlog_for(self, tenant_id: str) -> tuple[int | None, int | None]:
        cached = self._backlog.get(tenant_id)
        if cached is not None:
            return cached
        try:
            value = await self.commands.backlog(tenant_id)
        except Exception:  # a backlog probe must not turn into a 500
            logger.warning("kernel_backlog_probe_failed", exc_info=True)
            return None, None
        self._backlog.put(tenant_id, value)
        return value

    async def _deny(self, kind: str, command: CommandEnvelope, principal: KernelPrincipal, *, reason_code: str, decision_id: str, version: str) -> None:
        await self.denials.record(
            DenialAudit(
                kind=kind,
                tenant_id=command.tenant_id,
                command_id=command.command_id,
                command_type=command.command_type,
                target=command.target,
                capability=command.capability,
                actor_id=principal.subject,
                client_id=principal.client_id,
                correlation_id=command.correlation_id,
                reason_code=reason_code,
                decision_id=decision_id,
                version=version,
            )
        )

    async def submit(
        self,
        command: CommandEnvelope,
        principal: KernelPrincipal,
        *,
        replay_mode: ReplayMode | None = None,
        replay_of: UUID | None = None,
        trace: Mapping[str, str] | None = None,
        required_scope: str | None = None,
    ) -> SubmitResult:
        from app.identity_missions import authorize_mission

        if not authorize_mission(command.command_type, principal.scopes):
            await self._deny("policy_deny", command, principal, reason_code="mission_scope_missing", decision_id=str(uuid4()), version="identity-missions.v1")
            raise PolicyDenied("policy denied: mission_scope_missing")
        started = time.perf_counter()
        family = _family(command.command_type)
        self.metrics.commands_received.labels(command_family=family).inc()

        # 9 — registry resolution: a known capability, exactly one owning policy,
        # matching target and capability.
        if command.capability not in self.commands.policies.capabilities:
            self.metrics.policy_denials.labels(reason="capability_unknown").inc()
            raise CapabilityUnknown("capability is not listed in the capability registry")
        policy = self.commands.policies.resolve(command.command_type)
        if policy is None or policy.target != command.target or policy.capability != command.capability:
            self.metrics.policy_denials.labels(reason="registry_mismatch").inc()
            raise CommandCapabilityDisabled("command type, target and capability do not name one registered policy")

        # 10 — adapter ownership. Temporal-executed families need no in-process adapter.
        ownership = self.registry.ownership(command.command_type)
        destination = ADAPTER_COMMAND_DESTINATION if ownership is not None else TEMPORAL_COMMAND_DESTINATION
        adapter_registered = ownership is not None or destination == TEMPORAL_COMMAND_DESTINATION

        # 11 — Policy Engine.
        decision = evaluate_command(
            self._policy_request(
                command,
                principal,
                required_scope=(
                    SCOPE_COMMAND_REPLAY
                    if replay_mode is ReplayMode.REEXECUTE
                    else required_scope or SCOPE_COMMAND
                ),
                operator_required=replay_mode is ReplayMode.REEXECUTE,
            )
        )
        if not decision.allow:
            self.metrics.policy_denials.labels(reason=decision.reason_code).inc()
            await self._deny("policy_deny", command, principal, reason_code=decision.reason_code, decision_id=decision.decision_id, version=decision.policy_version)
            raise PolicyDenied(f"policy denied: {decision.reason_code}")

        # 12 — Safety Gate.
        tenant_backlog, global_backlog = await self._backlog_for(command.tenant_id)
        safety = self.safety.evaluate(
            SafetySubject(
                tenant_id=command.tenant_id,
                command_type=command.command_type,
                target=command.target,
                capability=command.capability,
                campaign_id=_campaign_id(command.payload),
                correlation_id=command.correlation_id,
            ),
            SafetyContext(
                adapter_registered=adapter_registered,
                adapter_ready=None,
                tenant_backlog=tenant_backlog,
                global_backlog=global_backlog,
            ),
        )
        if not safety.allow:
            self.metrics.safety_denials.labels(reason=safety.reason_code).inc()
            await self._deny("safety_deny", command, principal, reason_code=safety.reason_code, decision_id=safety.decision_id, version=safety.safety_version)
            if safety.saturated:
                raise KernelSaturated(f"kernel saturated: {safety.reason_code}")
            raise SafetyDenied(f"safety denied: {safety.reason_code}")

        # 13–17 — idempotency reservation, command, audit, outbox intent, COMMIT.
        evidence: dict[str, Any] = {**decision.evidence(), **safety.evidence(), "destination": destination}
        if ownership is not None:
            evidence["adapter_id"] = ownership.adapter_id
        if replay_mode is not None:
            evidence["replay_mode"] = replay_mode.value
            evidence["replay_of"] = str(replay_of) if replay_of is not None else None
        operation = await self.commands.submit(
            command,
            authenticated_subject=principal.subject,
            authenticated_client_id=principal.client_id,
            destination=destination,
            decision_evidence=evidence,
            trace=trace,
        )
        if operation.duplicate:
            self.metrics.idempotency_duplicates.inc()
        self.metrics.command_duration.labels(stage="accept").observe(time.perf_counter() - started)
        return SubmitResult(operation=operation, policy=decision, safety=safety, destination=destination)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    async def get(self, tenant_id: str, operation_id: UUID) -> CommandOperation:
        return await self.commands.get(tenant_id, operation_id)

    async def timeline(self, tenant_id: str, operation_id: UUID, *, limit: int = 200) -> list[OperationEvent]:
        events = await self.commands.list_events(tenant_id, operation_id, limit=limit)
        # Append-only and monotonic by construction; verify rather than trust.
        ids = [event.event_id for event in events]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise CommandConflict("operation timeline is not monotonic")
        return events

    async def attempts(self, tenant_id: str, operation_id: UUID, *, limit: int = 100) -> list[OperationAttempt]:
        return await self.commands.list_attempts(tenant_id, operation_id, limit=limit)

    # ------------------------------------------------------------------
    # Cancellation (Phase 11) — the ledger's mutate_operation already encodes
    # the legal outcomes; the kernel adds the audit actor and metrics.
    # ------------------------------------------------------------------
    async def cancel(
        self,
        tenant_id: str,
        operation_id: UUID,
        *,
        principal: KernelPrincipal,
        idempotency_key: str,
        expected_version: int,
        reason: str,
    ) -> CommandOperation:
        operation = await self.commands.mutate_operation(
            tenant_id,
            operation_id,
            action="cancel",
            actor_id=principal.subject,
            idempotency_key=idempotency_key,
            expected_version=expected_version,
            reason=reason,
        )
        self.metrics.cancellations.labels(result=operation.state).inc()
        return operation

    # ------------------------------------------------------------------
    # Replay (Phase 12)
    # ------------------------------------------------------------------
    async def replay(
        self,
        tenant_id: str,
        operation_id: UUID,
        *,
        principal: KernelPrincipal,
        mode: ReplayMode,
        idempotency_key: str,
        expected_version: int,
        reason: str,
        new_idempotency_key: str | None = None,
    ) -> CommandOperation:
        if PLATFORM_OPERATOR_ROLE not in principal.roles:
            raise ReplayNotAllowed("replay requires the platform-operator role")
        original = await self.commands.get(tenant_id, operation_id)
        if mode is ReplayMode.REPROCESS:
            # Re-run Middleware processing from durable evidence: the ledger's
            # reconcile mutation requests a readback-only reconciliation. No
            # new provider effect can result from it.
            if original.state not in {"dispatching", "accepted", "readback_pending", "reconciliation_required"}:
                raise ReplayNotAllowed("REPROCESS is only meaningful for an operation with an unknown provider outcome")
            operation = await self.commands.mutate_operation(
                tenant_id,
                operation_id,
                action="reconcile",
                actor_id=principal.subject,
                idempotency_key=idempotency_key,
                expected_version=expected_version,
                reason=f"REPROCESS: {reason}",
            )
            self.metrics.replays.labels(mode="REPROCESS").inc()
            return operation

        # REEXECUTE: a deliberately new provider effect.
        if original.state not in {"failed", "dead_lettered", "cancelled"}:
            raise ReplayNotAllowed("REEXECUTE requires a terminal failed, dead-lettered or cancelled operation")
        if not new_idempotency_key or new_idempotency_key == original.idempotency_key:
            raise ReplayNotAllowed("REEXECUTE requires a new idempotency key")
        ownership = self.registry.ownership(original.command_type)
        if ownership is not None:
            advertised = self.registry.advertised(ownership.adapter_id)
            if not advertised.safe_reexecution:
                raise ReplayNotAllowed(f"adapter {ownership.adapter_id} does not support safe re-execution")
        envelope = await self.commands.load_envelope(tenant_id, operation_id)
        replayed = envelope.model_copy(
            update={
                "command_id": uuid4(),
                "idempotency_key": new_idempotency_key,
                "requested_by": principal.subject,
                "correlation_id": envelope.correlation_id,
            }
        )
        result = await self.submit(replayed, principal, replay_mode=ReplayMode.REEXECUTE, replay_of=operation_id)
        self.metrics.replays.labels(mode="REEXECUTE").inc()
        return result.operation

    # ------------------------------------------------------------------
    # Describe (Phase 13)
    # ------------------------------------------------------------------
    def describe(self, *, runtime_schema_version: int, contract_digest: str | None, command_contract_version: str) -> dict[str, Any]:
        capabilities = self.commands.policies.capabilities
        return {
            "kernel_version": "3.0.0",
            "service_id": self.service_id,
            "source_sha": self.settings.source_sha,
            "release_id": self.settings.release_id,
            "app_version": self.settings.app_version,
            "environment": self.settings.app_env,
            "runtime_schema_version": runtime_schema_version,
            "alembic_schema_head": self.settings.schema_head,
            "public_contract_digest": contract_digest,
            "command_contract_version": command_contract_version,
            "policy_version": COMMAND_POLICY_VERSION,
            "safety": self.safety.describe(),
            "command_prefixes": [
                {
                    "prefix": policy.prefix,
                    "target": policy.target,
                    "capability": policy.capability,
                    "readback_required": policy.readback_required,
                    "adapter_id": self.registry.owners().get(policy.prefix),
                }
                for policy in sorted(self.commands.policies.policies, key=lambda item: item.prefix)
            ],
            "adapters": self.registry.describe(),
            "capabilities": {name: value for name, value in sorted(capabilities.items())},
            "effect_defaults": {name: False for name in sorted(capabilities) if name != "TEST_SYN_EXECUTE"},
            "provider_effects_enabled": any(
                value is True and name != "TEST_SYN_EXECUTE" for name, value in capabilities.items()
            ),
            "canonical_port": 8095,
            "canonical_service": "middleware-integration-api",
            "state_vocabulary": {
                "persisted": dict(sorted(API_OPERATION_STATES.items())),
                "public": sorted(set(API_OPERATION_STATES.values())),
                "transitions": {state: sorted(targets) for state, targets in sorted(ALLOWED_COMMAND_TRANSITIONS.items())},
                "completed_requires": "provider read-back MATCHED",
            },
            "idempotency": {
                "authority": "middleware_commands UNIQUE(tenant_id, idempotency_key) + payload digest",
                "binding": ["tenant_id", "authenticated_client_id", "command_type", "target", "capability", "idempotency_key", "payload"],
                "exact_replay": "200 duplicate=true, no new intent",
                "same_key_different_payload": "409 command_conflict",
            },
            "cancel": {"scope": SCOPE_COMMAND, "optimistic_concurrency": "expected_version", "ambiguous_outcome": "RECONCILIATION_REQUIRED"},
            "replay": {"scope": SCOPE_COMMAND_REPLAY, "role": PLATFORM_OPERATOR_ROLE, "modes": [mode.value for mode in ReplayMode], "uncertain_outcome": "reconcile first"},
            "readiness": {
                "adapter_registry_valid": self.registry.validated,
                "registered_adapters": list(self.registry.ids()),
                "unowned_command_prefixes": list(self.registry.unowned_prefixes()),
            },
        }


def _campaign_id(payload: Mapping[str, Any]) -> str | None:
    value = payload.get("campaign_id")
    return value if isinstance(value, str) and value else None


def _family(command_type: str) -> str:
    return command_type.split(".", 1)[0]


__all__ = [
    "AdapterNotFound",
    "CapabilityUnknown",
    "CommandKernel",
    "CommandUnowned",
    "DenialAudit",
    "DenialAuditSink",
    "KernelSaturated",
    "MemoryDenialAuditSink",
    "PolicyDenied",
    "ReplayNotAllowed",
    "SafetyDenied",
    "SubmitResult",
    "SCOPE_COMMAND",
    "SCOPE_COMMAND_READ",
    "SCOPE_COMMAND_REPLAY",
    "redact_metadata",
    "CommandNotFound",
]
