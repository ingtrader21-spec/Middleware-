"""V3 command kernel certification: registry, policy, safety, submission,
idempotency concurrency, execution bus, reconciliation, cancellation, replay
and the crash/chaos matrix — all against the in-memory ledger, the same
kernel code the PostgreSQL processes run."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from app.commands import (
    ADAPTER_COMMAND_DESTINATION,
    CommandCapabilityDisabled,
    CommandConflict,
    CommandEnvelope,
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    MemoryCommandStore,
)
from app.control_plane_auth import ControlPlaneCaller
from app.core.config import Settings
from app.core.policy_engine import CommandPolicyRequest, evaluate_command
from app.platform.adapter import AdapterConfigurationError, ReadbackStatus
from app.platform.adapters.fixtures import FixtureAdapter, development_fixtures
from app.platform.adapters.fixtures import test_syn_adapter as synthetic_adapter
from app.platform.bus import AdapterDispatch, BusSettings
from app.platform.kernel import (
    KernelSaturated,
    MemoryDenialAuditSink,
    PolicyDenied,
    ReplayNotAllowed,
    SafetyDenied,
)
from app.platform.memory import MemoryExecutionBus
from app.platform.metrics import KernelMetrics
from app.platform.principal import KernelPrincipal
from app.platform.reconciler import Reconciler
from app.platform.registry import AdapterRegistry, AdapterRegistryError
from app.platform.resilience import ReplayMode
from app.platform.runtime import build_platform_runtime, command_policies
from app.platform.safety import SafetyContext, SafetyGate, SafetySubject, SafetySwitches

TENANT = "TEST_SYN"
OTHER_TENANT = "tenant-b"


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def caller(prefixes: tuple[str, ...] = ("test.syn.", "crm."), targets: tuple[str, ...] = ("test-syn", "odoo-19"), *, allowed: bool = True) -> ControlPlaneCaller:
    return ControlPlaneCaller(
        client_id="middleware-api",
        command_scope="platform.command",
        status_scope="platform.command.read",
        allowed_command_prefixes=prefixes,
        allowed_targets=frozenset(targets),
        connector_commands_allowed=allowed,
        compatibility_only=False,
    )


def principal(*, tenants: tuple[str, ...] = (TENANT,), roles: tuple[str, ...] = (), scopes: tuple[str, ...] = ("platform.command", "platform.command.read"), subject: str = "user-1", client: ControlPlaneCaller | None = None) -> KernelPrincipal:
    return KernelPrincipal(subject=subject, client_id="middleware-api", tenants=tenants, roles=roles, scopes=scopes, caller=client or caller())


def envelope(**updates: Any) -> CommandEnvelope:
    value: dict[str, Any] = {
        "command_id": str(uuid4()),
        "command_type": "test.syn.execute.v1",
        "command_version": "1.0",
        "target": "test-syn",
        "tenant_id": TENANT,
        "requested_by": "user-1",
        "correlation_id": "corr-" + uuid4().hex[:12],
        "idempotency_key": "idem-" + uuid4().hex,
        "capability": "TEST_SYN_EXECUTE",
        "payload": {"probe": True},
    }
    value.update(updates)
    return CommandEnvelope.model_validate(value)


class Harness:
    """One kernel + memory bus + reconciler wired exactly like the runtime."""

    def __init__(self, settings: Settings, *, adapters: tuple[object, ...] | None = None, bus_settings: BusSettings | None = None) -> None:
        self.settings = settings
        self.store = MemoryCommandStore()
        self.commands = CommandService(store=self.store, policies=command_policies(settings))
        self.adapters = adapters if adapters is not None else development_fixtures()
        self.platform = build_platform_runtime(
            settings,
            commands=self.commands,
            http=None,
            pool=None,
            service_id="middleware-integration-api",
            adapters=self.adapters,
            bus_settings=bus_settings,
        )
        assert self.platform.registry_error is None, self.platform.registry_error
        self.kernel = self.platform.kernel
        self.dispatch = self.platform.dispatch
        self.bus = MemoryExecutionBus(self.store, self.dispatch)
        self.reconciler: Reconciler = cast(Reconciler, self.platform.reconciler)

    @property
    def test_syn(self) -> FixtureAdapter:
        return self.platform.registry.adapter("test-syn")  # type: ignore[return-value]

    async def submit(self, command: CommandEnvelope, who: KernelPrincipal | None = None):
        return await self.kernel.submit(command, who or principal())

    def intents(self, command_id: UUID):
        return [item for item in self.store._outbox if item.command_id == str(command_id)]


@pytest.fixture
def harness(test_settings: Settings) -> Harness:
    return Harness(test_settings)


# ----------------------------------------------------------------------------
# adapter registry
# ----------------------------------------------------------------------------
def test_registry_refuses_duplicate_ids_and_unowned_adapters(test_settings: Settings) -> None:
    registry = AdapterRegistry(command_policies(test_settings))
    registry.register(synthetic_adapter())
    with pytest.raises(AdapterRegistryError, match="duplicate adapter id"):
        registry.register(synthetic_adapter())
    with pytest.raises(AdapterRegistryError, match="owns no command prefix"):
        registry.register(FixtureAdapter(adapter_id="stray", provider_family="x", connector_ids=("nobody",), served_capabilities=("NOTHING",)))
    with pytest.raises(AdapterConfigurationError):
        registry.register(object())


def test_registry_refuses_two_owners_for_one_prefix(test_settings: Settings) -> None:
    registry = AdapterRegistry(command_policies(test_settings))
    registry.register(FixtureAdapter(adapter_id="odoo-a", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("ODOO_WRITE",)))
    with pytest.raises(AdapterRegistryError, match="two owners"):
        registry.register(FixtureAdapter(adapter_id="odoo-b", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("ODOO_WRITE",)))


def test_registry_requires_capability_and_readback_support(test_settings: Settings) -> None:
    registry = AdapterRegistry(command_policies(test_settings))
    with pytest.raises(AdapterRegistryError, match="does not implement capability"):
        registry.register(FixtureAdapter(adapter_id="odoo-x", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("EMAIL_DELIVERY",)))

    class NoReadback(FixtureAdapter):
        supports_readback = False

    no_readback = NoReadback(adapter_id="odoo-y", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("ODOO_WRITE",))
    no_readback.supports_readback = False
    with pytest.raises(AdapterRegistryError, match="must support readback"):
        registry.register(no_readback)


def test_registry_validation_fails_when_an_enabled_capability_has_no_adapter(test_settings: Settings) -> None:
    registry = AdapterRegistry(command_policies(test_settings))  # TEST_SYN_EXECUTE is enabled in test
    with pytest.raises(AdapterRegistryError, match="enabled capability 'TEST_SYN_EXECUTE' has no adapter"):
        registry.validate()
    registry.register(synthetic_adapter())
    registry.validate()
    ownership = registry.ownership("test.syn.execute.v1")
    assert ownership is not None and ownership.adapter_id == "test-syn"
    assert registry.ownership("crm.contact.create.v1") is None
    assert "crm." in registry.unowned_prefixes()


def test_every_command_prefix_has_at_most_one_owner_and_disabled_prefixes_may_be_unowned(test_settings: Settings) -> None:
    registry = AdapterRegistry(command_policies(test_settings))
    registry.register_all(development_fixtures())
    registry.validate()
    owners = registry.owners()
    assert len(set(owners)) == len(owners)
    for policy in registry.policies.policies:
        if registry.policies.capabilities.get(policy.capability) is True:
            assert policy.prefix in owners


# ----------------------------------------------------------------------------
# policy engine (command authorization)
# ----------------------------------------------------------------------------
def _policy_request(**updates: Any) -> CommandPolicyRequest:
    value: dict[str, Any] = {
        "correlation_id": "c1",
        "principal": "user-1",
        "client_id": "middleware-api",
        "tenant_id": TENANT,
        "authorized_tenants": (TENANT,),
        "roles": (),
        "scopes": ("platform.command",),
        "required_scope": "platform.command",
        "command_type": "test.syn.execute.v1",
        "target": "test-syn",
        "capability": "TEST_SYN_EXECUTE",
        "environment": "test",
        "effect_classification": "synthetic",
        "caller_command_prefixes": ("test.syn.",),
        "caller_targets": ("test-syn",),
        "caller_connector_commands_allowed": True,
    }
    value.update(updates)
    return CommandPolicyRequest.model_validate(value)


@pytest.mark.parametrize(
    "updates, reason",
    [
        ({"scopes": ("platform.command.read",)}, "scope_missing"),
        ({"authorized_tenants": ("other",)}, "tenant_not_authorized"),
        ({"authorized_tenants": ("*",)}, "wildcard_tenant_prohibited"),
        ({"caller_connector_commands_allowed": False}, "client_without_command_authority"),
        ({"caller_targets": ("odoo-19",)}, "target_not_authorized_for_client"),
        ({"caller_command_prefixes": ("crm.",)}, "command_namespace_not_authorized"),
        ({"campaign_scoped": True}, "campaign_scope_required"),
        ({"operator_required": True}, "operator_role_required"),
        ({"environment": "production"}, "synthetic_command_in_production"),
    ],
)
def test_policy_engine_denies_by_reason(updates: dict[str, Any], reason: str) -> None:
    decision = evaluate_command(_policy_request(**updates))
    assert decision.allow is False
    assert reason in decision.reason_codes
    assert decision.reason_code == decision.reason_codes[0]
    assert decision.evidence()["policy_allow"] is False


def test_policy_engine_allows_and_reports_version() -> None:
    decision = evaluate_command(_policy_request(roles=("platform-operator",), operator_required=True, campaign_scoped=True, campaign_id="camp-1"))
    assert decision.allow is True
    assert decision.reason_codes == ["allowed"]
    assert decision.policy_version.startswith("2026-")
    assert decision.safe_metadata["operator"] is True


# ----------------------------------------------------------------------------
# safety gate
# ----------------------------------------------------------------------------
def _subject(**updates: Any) -> SafetySubject:
    value = {"tenant_id": TENANT, "command_type": "test.syn.execute.v1", "target": "test-syn", "capability": "TEST_SYN_EXECUTE", "correlation_id": "c1"}
    value.update(updates)
    return SafetySubject(**value)


def test_safety_gate_allows_synthetic_commands_and_denies_external_effects_by_default(test_settings: Settings) -> None:
    gate = SafetyGate(test_settings, command_policies(test_settings))
    ok = gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=True))
    assert ok.allow and ok.classification == "synthetic"
    denied = gate.evaluate(_subject(command_type="crm.contact.create.v1", target="odoo-19", capability="ODOO_WRITE"), SafetyContext(adapter_registered=True, adapter_ready=True))
    assert not denied.allow
    assert "capability_disabled" in denied.reason_codes
    assert "environment_not_authorized" in denied.reason_codes
    assert any(code.startswith("effect_gate_off:") for code in denied.reason_codes)
    assert any(code.startswith("umbrella_control_off:") for code in denied.reason_codes)


def test_safety_gate_kill_switches_only_tighten(test_settings: Settings) -> None:
    gate = SafetyGate(test_settings, command_policies(test_settings))
    gate.trip("test-syn")
    assert gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=True)).reason_code == "provider_kill_switch"
    gate.trip()
    assert gate.evaluate(_subject(target="odoo-19"), SafetyContext(adapter_registered=True, adapter_ready=True)).reason_code == "global_kill_switch"
    assert gate.describe()["global_kill_switch"] is True


def test_safety_gate_requires_synthetic_tenant_registered_and_ready_adapter(test_settings: Settings) -> None:
    gate = SafetyGate(test_settings, command_policies(test_settings))
    assert gate.evaluate(_subject(tenant_id="real-tenant"), SafetyContext(adapter_registered=True, adapter_ready=True)).reason_code == "synthetic_tenant_required"
    assert gate.evaluate(_subject(), SafetyContext(adapter_registered=False, adapter_ready=None)).reason_code == "adapter_not_registered"
    assert gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=False)).reason_code == "adapter_not_ready"
    assert gate.evaluate(_subject(capability="UNLISTED_THING"), SafetyContext(adapter_registered=True, adapter_ready=True)).reason_code == "capability_without_safety_gate"


def test_safety_gate_bounds_backlog_and_tenant_rate(test_settings: Settings) -> None:
    clock = [0.0]
    gate = SafetyGate(test_settings, command_policies(test_settings), clock=lambda: clock[0])
    limits = gate.switches.limits
    saturated = gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=True, global_backlog=limits.global_backlog_bound))
    assert saturated.reason_code == "global_backlog_saturated" and saturated.saturated
    tenant_full = gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=True, tenant_backlog=limits.tenant_backlog_bound))
    assert tenant_full.reason_code == "tenant_backlog_saturated"
    for _ in range(limits.tenant_commands_per_minute):
        assert gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=True)).allow
    limited = gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=True))
    assert limited.reason_code == "tenant_rate_limited" and limited.saturated
    clock[0] += 60.0
    assert gate.evaluate(_subject(), SafetyContext(adapter_registered=True, adapter_ready=True)).allow


def test_safety_switch_table_is_well_formed() -> None:
    switches = SafetySwitches.load()
    assert switches.global_kill_switch is False
    quarantined = {"face-id", "face-liveness", "camera-gateway", "postgresql"}
    assert all(value is (name in quarantined) for name, value in switches.provider_kill_switches.items())
    assert quarantined <= switches.provider_kill_switches.keys()
    for name, gate in switches.gates.items():
        if gate.classification == "external_effect":
            assert "production" in gate.environments or "staging" in gate.environments
            assert "development" not in gate.environments and "test" not in gate.environments, name


# ----------------------------------------------------------------------------
# submission (steps 9–18)
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_submit_persists_command_audit_and_one_adapter_intent(harness: Harness) -> None:
    command = envelope()
    result = await harness.submit(command)
    assert result.operation.state == "persisted"
    assert result.duplicate is False
    assert result.destination == ADAPTER_COMMAND_DESTINATION
    assert result.policy.allow and result.safety.allow
    intents = harness.intents(command.command_id)
    assert len(intents) == 1 and intents[0].destination == ADAPTER_COMMAND_DESTINATION
    events = await harness.commands.list_events(TENANT, command.command_id, limit=10)
    assert events[0].new_state == "persisted"
    metadata = events[0].safe_metadata
    assert metadata["policy_allow"] is True and metadata["safety_allow"] is True
    assert metadata["adapter_id"] == "test-syn"
    assert metadata["policy_decision_id"] == result.policy.decision_id
    assert harness.test_syn.provider_effects == 0  # nothing executes in the request


@pytest.mark.asyncio
async def test_submit_rejects_registry_mismatch_policy_and_safety_denials(harness: Harness) -> None:
    with pytest.raises(CommandCapabilityDisabled):
        await harness.submit(envelope(target="odoo-19"))
    with pytest.raises(PolicyDenied, match="command_namespace_not_authorized"):
        await harness.submit(envelope(), principal(client=caller(prefixes=("crm.",), targets=("test-syn",))))
    with pytest.raises(PolicyDenied, match="tenant_not_authorized"):
        await harness.submit(envelope(), principal(tenants=(OTHER_TENANT,)))
    with pytest.raises(SafetyDenied, match="synthetic_tenant_required"):
        await harness.submit(envelope(tenant_id=OTHER_TENANT), principal(tenants=(OTHER_TENANT,)))
    with pytest.raises(SafetyDenied, match="environment_not_authorized|capability_disabled"):
        await harness.submit(envelope(command_type="crm.contact.create.v1", target="odoo-19", capability="ODOO_WRITE"))
    denials = harness.platform.denials
    assert isinstance(denials, MemoryDenialAuditSink)
    kinds = [item.kind for item in denials.records]
    assert kinds.count("policy_deny") == 2 and kinds.count("safety_deny") == 2
    assert harness.store._outbox == []  # a denied command never creates an intent


@pytest.mark.asyncio
async def test_submit_reports_saturation_as_429(harness: Harness) -> None:
    harness.kernel.safety.switches = SafetySwitches.load().__class__(
        **{**harness.kernel.safety.switches.__dict__, "limits": harness.kernel.safety.switches.limits.__class__(tenant_commands_per_minute=600, tenant_backlog_bound=1, global_backlog_bound=1)}
    )
    await harness.submit(envelope())
    harness.kernel._backlog._values.clear()
    with pytest.raises(KernelSaturated):
        await harness.submit(envelope())


@pytest.mark.asyncio
async def test_exact_replay_returns_the_operation_without_a_second_intent(harness: Harness) -> None:
    command = envelope()
    first = await harness.submit(command)
    second = await harness.submit(command)
    assert second.operation.command_id == first.operation.command_id
    assert second.duplicate is True
    assert len(harness.intents(command.command_id)) == 1
    with pytest.raises(CommandConflict):
        await harness.submit(command.model_copy(update={"payload": {"probe": False}}))
    with pytest.raises(CommandConflict):
        await harness.submit(command.model_copy(update={"command_id": uuid4()}))


@pytest.mark.asyncio
async def test_hundred_concurrent_identical_submissions_create_one_operation(harness: Harness) -> None:
    command = envelope()
    results = await asyncio.gather(*(harness.submit(command) for _ in range(100)))
    ids = {item.operation.command_id for item in results}
    assert ids == {command.command_id}
    assert sum(1 for item in results if not item.duplicate) == 1
    assert sum(1 for item in results if item.duplicate) == 99
    assert len(harness.store._commands) == 1
    assert len(harness.intents(command.command_id)) == 1
    await harness.bus.drain()
    assert harness.test_syn.provider_effects == 1
    conflicting = await asyncio.gather(
        *(harness.submit(command.model_copy(update={"payload": {"probe": "changed"}})) for _ in range(10)),
        return_exceptions=True,
    )
    assert all(isinstance(item, CommandConflict) for item in conflicting)


# ----------------------------------------------------------------------------
# execution bus
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bus_completes_only_after_matched_readback(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    assert await harness.bus.run_once() is True
    operation = await harness.commands.get(TENANT, command.command_id)
    assert operation.state == "completed"
    assert operation.provider_operation_id is not None
    assert operation.provider_operation_id.startswith("test-syn:")
    assert operation.readback_evidence is not None
    assert operation.readback_evidence["status"] == "matched"
    assert operation.readback_evidence_sha256
    states = [event.new_state for event in await harness.commands.list_events(TENANT, command.command_id, limit=20)]
    assert states == ["persisted", "queued", "dispatching", "accepted", "readback_pending", "completed"]
    attempts = await harness.commands.list_attempts(TENANT, command.command_id, limit=10)
    assert [item.attempt_number for item in attempts] == [1]
    assert harness.bus.stats().completed == 1
    assert harness.test_syn.provider_effects == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "behaviour, state, effects, bus_outcome",
    [
        ("reject", "failed", 0, "completed"),
        ("unknown", "reconciliation_required", 1, "quarantined"),
        ("crash", "reconciliation_required", 1, "quarantined"),
        ("readback_mismatch", "failed", 1, "completed"),
        ("readback_unavailable", "reconciliation_required", 1, "quarantined"),
        ("readback_unsupported", "reconciliation_required", 1, "quarantined"),
    ],
)
async def test_bus_classifies_adapter_outcomes(harness: Harness, behaviour: str, state: str, effects: int, bus_outcome: str) -> None:
    command = envelope(payload={"fixture": behaviour})
    await harness.submit(command)
    await harness.bus.run_once()
    operation = await harness.commands.get(TENANT, command.command_id)
    assert operation.state == state
    assert harness.test_syn.effects.get(str(command.command_id), 0) == effects
    assert harness.bus.processed[-1][1] == bus_outcome


@pytest.mark.asyncio
async def test_bus_times_out_into_reconciliation_not_success(test_settings: Settings) -> None:
    harness = Harness(test_settings, bus_settings=BusSettings(default_timeout_seconds=0.05))
    command = envelope(payload={"fixture": "timeout"})
    await harness.submit(command)
    await harness.bus.run_once()
    operation = await harness.commands.get(TENANT, command.command_id)
    assert operation.state == "reconciliation_required"
    assert operation.last_error is not None
    assert operation.last_error.startswith("adapter_timeout")


@pytest.mark.asyncio
async def test_bus_retries_transient_failures_with_a_bound_and_dead_letters(test_settings: Settings) -> None:
    harness = Harness(test_settings, bus_settings=BusSettings(max_attempts=3))
    harness.bus.max_attempts = 3
    clock = [1_000.0]
    harness.bus.clock = lambda: clock[0]
    command = envelope()
    harness.test_syn.scripts[str(command.command_id)] = ["transient", "success"]
    await harness.submit(command)
    await harness.bus.run_once()
    assert (await harness.commands.get(TENANT, command.command_id)).state == "queued"
    assert harness.bus.processed[-1][1] == "retry"
    assert await harness.bus.run_once() is False  # exponential backoff not elapsed
    clock[0] += 10_000.0
    await harness.bus.run_once()
    assert (await harness.commands.get(TENANT, command.command_id)).state == "completed"
    attempts = await harness.commands.list_attempts(TENANT, command.command_id, limit=10)
    assert [item.attempt_number for item in attempts] == [1, 2]

    hopeless = envelope()
    harness.test_syn.scripts[str(hopeless.command_id)] = ["transient"] * 5
    await harness.submit(hopeless)
    for _ in range(3):
        clock[0] += 10_000.0
        await harness.bus.run_once()
    assert (await harness.commands.get(TENANT, hopeless.command_id)).state == "dead_lettered"
    assert harness.bus.stats().dead_lettered == 1


@pytest.mark.asyncio
async def test_bus_re_evaluates_safety_at_execution_time(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    harness.kernel.safety.trip("test-syn")
    await harness.bus.run_once()
    operation = await harness.commands.get(TENANT, command.command_id)
    assert operation.state == "dead_lettered"
    assert harness.test_syn.provider_effects == 0


@pytest.mark.asyncio
async def test_two_workers_one_command_one_effect(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    second = MemoryExecutionBus(harness.store, AdapterDispatch(settings=harness.settings, commands=harness.commands, registry=harness.platform.registry, safety=harness.kernel.safety, metrics=KernelMetrics(), worker_id="worker-2"), worker_id="worker-2")
    first_claimed, second_claimed = await asyncio.gather(harness.bus.run_once(), second.run_once())
    assert first_claimed != second_claimed  # exactly one of them claimed the row
    assert harness.test_syn.provider_effects == 1
    assert (await harness.commands.get(TENANT, command.command_id)).state == "completed"


@pytest.mark.asyncio
async def test_stale_attempt_fencing_rejects_finalization(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    await harness.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="w", reason="q")
    await harness.commands.transition(TENANT, command.command_id, new_state="dispatching", actor_id="w", reason="attempt 1")
    await harness.commands.transition(TENANT, command.command_id, new_state="failed", actor_id="w", reason="x", expected_attempt=1)
    await harness.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="w", reason="retry")
    await harness.commands.transition(TENANT, command.command_id, new_state="dispatching", actor_id="w", reason="attempt 2")
    with pytest.raises(CommandConflict, match="stale attempt fencing"):
        await harness.commands.transition(TENANT, command.command_id, new_state="accepted", actor_id="stale-worker", reason="late", expected_attempt=1)
    await harness.commands.transition(TENANT, command.command_id, new_state="accepted", actor_id="w", reason="ok", expected_attempt=2)


# ----------------------------------------------------------------------------
# crash / chaos matrix (C, D, E, F, G) and lease recovery
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_chaos_worker_crash_after_lease_before_adapter_call_reclaims_safely(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    intent = harness.intents(command.command_id)[0]
    # C: the worker claimed the row and died before calling the adapter.
    intent.lease_owner, intent.lease_until, intent.attempt_count = "dead-worker", harness.bus.clock() + 60, 1
    assert await harness.bus.run_once() is False  # lease still live: nobody else may touch it
    harness.bus.expire_leases()
    assert await harness.bus.run_once() is True
    assert (await harness.commands.get(TENANT, command.command_id)).state == "completed"
    assert harness.test_syn.provider_effects == 1


@pytest.mark.asyncio
async def test_chaos_worker_crash_during_adapter_request_reads_back_instead_of_resending(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    # D/E: the ledger says dispatching (attempt opened), the provider applied the
    # effect, the worker died before recording the acknowledgement.
    await harness.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="dead", reason="q")
    await harness.commands.transition(TENANT, command.command_id, new_state="dispatching", actor_id="dead", reason="attempt 1")
    harness.test_syn.effects[str(command.command_id)] = 1
    await harness.bus.run_once()
    operation = await harness.commands.get(TENANT, command.command_id)
    assert operation.state == "completed"
    assert harness.test_syn.executed == []  # readback discovered the effect; no resend
    assert harness.test_syn.effects[str(command.command_id)] == 1


@pytest.mark.asyncio
async def test_chaos_worker_crash_after_acknowledgement_before_state_update_is_repaired(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    await harness.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="dead", reason="q")
    await harness.commands.transition(TENANT, command.command_id, new_state="dispatching", actor_id="dead", reason="attempt 1")
    await harness.commands.transition(TENANT, command.command_id, new_state="accepted", actor_id="dead", reason="ack", provider_operation_id="test-syn:x:1")
    harness.test_syn.effects[str(command.command_id)] = 1
    await harness.bus.run_once()  # F: repaired by readback
    assert (await harness.commands.get(TENANT, command.command_id)).state == "completed"
    assert harness.test_syn.effects[str(command.command_id)] == 1


@pytest.mark.asyncio
async def test_chaos_worker_crash_after_commit_produces_no_duplicate_effect(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    await harness.bus.run_once()
    intent = harness.intents(command.command_id)[0]
    # G: the outbox row was not marked complete (crash after the ledger commit).
    intent.completed_at, intent.lease_owner, intent.lease_until = None, None, None
    await harness.bus.run_once()
    assert harness.test_syn.provider_effects == 1
    assert (await harness.commands.get(TENANT, command.command_id)).state == "completed"


# ----------------------------------------------------------------------------
# reconciliation
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reconciler_completes_matched_and_requeues_not_found(harness: Harness) -> None:
    unknown = envelope(payload={"fixture": "unknown"})
    await harness.submit(unknown)
    await harness.bus.run_once()
    assert (await harness.commands.get(TENANT, unknown.command_id)).state == "reconciliation_required"
    harness.bus.expire_leases()
    decision = await harness.reconciler.run_once()
    assert decision is not None and decision.action == "complete"
    operation = await harness.commands.get(TENANT, unknown.command_id)
    assert operation.readback_evidence is not None
    assert operation.state == "completed" and operation.readback_evidence["reconciled"] is True
    assert harness.test_syn.provider_effects == 1  # never re-sent

    lost = envelope()
    harness.test_syn.scripts[str(lost.command_id)] = ["crash", "success"]
    await harness.submit(lost)
    await harness.bus.run_once()
    harness.test_syn.effects.pop(str(lost.command_id), None)  # the provider has no trace of it
    harness.bus.expire_leases()
    decision = await harness.reconciler.run_once()
    assert decision is not None
    assert decision.action == "retry" and decision.final_state == "queued"
    await harness.bus.run_once()
    assert (await harness.commands.get(TENANT, lost.command_id)).state == "completed"


@pytest.mark.asyncio
async def test_reconciler_dead_letters_after_bounded_mismatches(harness: Harness) -> None:
    command = envelope(payload={"fixture": "unknown"})
    await harness.submit(command)
    await harness.bus.run_once()
    harness.test_syn.reconcile_as[str(command.command_id)] = ReadbackStatus.MISMATCH
    harness.reconciler.budget = 2
    harness.bus.expire_leases()
    first = await harness.reconciler.run_once()
    assert first is not None
    assert first.action == "release" and first.final_state == "reconciliation_required"
    harness.bus.expire_leases()
    second = await harness.reconciler.run_once()
    assert second is not None
    assert second.action == "dead_letter"
    assert (await harness.commands.get(TENANT, command.command_id)).state == "dead_lettered"
    assert harness.test_syn.provider_effects == 1
    assert await harness.reconciler.source.backlog() == 0


@pytest.mark.asyncio
async def test_reconciler_dead_letters_an_unsupported_readback_at_once(harness: Harness) -> None:
    """An adapter with no read surface for a command answers UNSUPPORTED
    deterministically: the reconciler records the reason and dead-letters in
    one cycle instead of burning the budget; the effect is never re-sent."""
    command = envelope(payload={"fixture": "unknown"})
    await harness.submit(command)
    await harness.bus.run_once()
    harness.test_syn.reconcile_as[str(command.command_id)] = ReadbackStatus.UNSUPPORTED
    harness.reconciler.budget = 6
    harness.bus.expire_leases()
    decision = await harness.reconciler.run_once()
    assert decision is not None
    assert decision.action == "dead_letter" and decision.final_state == "dead_lettered"
    operation = await harness.commands.get(TENANT, command.command_id)
    assert operation.state == "dead_lettered"
    events = await harness.commands.list_events(TENANT, command.command_id, limit=50)
    assert any("read-back unsupported" in (event.reason or "") for event in events)
    assert harness.test_syn.provider_effects == 1
    assert await harness.reconciler.source.backlog() == 0


# ----------------------------------------------------------------------------
# cancellation and replay
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cancel_semantics_follow_the_ledger(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    cancelled = await harness.kernel.cancel(TENANT, command.command_id, principal=principal(), idempotency_key="cancel-0001", expected_version=1, reason="operator")
    assert cancelled.state == "cancelled" and cancelled.resource_version == 2
    assert harness.intents(command.command_id)[0].cancelled_at is not None
    assert await harness.bus.run_once() is False
    replay = await harness.kernel.cancel(TENANT, command.command_id, principal=principal(), idempotency_key="cancel-0001", expected_version=1, reason="operator")
    assert replay.duplicate is True
    with pytest.raises(CommandConflict):
        await harness.kernel.cancel(TENANT, command.command_id, principal=principal(), idempotency_key="cancel-0002", expected_version=2, reason="again")

    running = envelope()
    await harness.submit(running)
    await harness.commands.transition(TENANT, running.command_id, new_state="queued", actor_id="w", reason="q")
    await harness.commands.transition(TENANT, running.command_id, new_state="dispatching", actor_id="w", reason="d")
    ambiguous = await harness.kernel.cancel(TENANT, running.command_id, principal=principal(), idempotency_key="cancel-0003", expected_version=1, reason="operator")
    assert ambiguous.state == "reconciliation_required"


@pytest.mark.asyncio
async def test_replay_requires_operator_and_never_re_executes_on_reprocess(harness: Harness) -> None:
    command = envelope(payload={"fixture": "unknown"})
    await harness.submit(command)
    await harness.bus.run_once()
    with pytest.raises(ReplayNotAllowed):
        await harness.kernel.replay(TENANT, command.command_id, principal=principal(), mode=ReplayMode.REPROCESS, idempotency_key="replay-0001", expected_version=1, reason="r")
    operator = principal(roles=("platform-operator",), scopes=("platform.command", "platform.command.read", "platform.command.replay"))
    reprocessed = await harness.kernel.replay(TENANT, command.command_id, principal=operator, mode=ReplayMode.REPROCESS, idempotency_key="replay-0001", expected_version=1, reason="r")
    assert reprocessed.state == "reconciliation_required"
    assert harness.test_syn.provider_effects == 1
    with pytest.raises(ReplayNotAllowed, match="terminal"):
        await harness.kernel.replay(TENANT, command.command_id, principal=operator, mode=ReplayMode.REEXECUTE, idempotency_key="replay-0002", expected_version=2, reason="r", new_idempotency_key="idem-new-00000001")


@pytest.mark.asyncio
async def test_reexecute_creates_a_new_governed_operation(harness: Harness) -> None:
    command = envelope(payload={"fixture": "reject"})
    await harness.submit(command)
    await harness.bus.run_once()
    assert (await harness.commands.get(TENANT, command.command_id)).state == "failed"
    operator = principal(roles=("platform-operator",), scopes=("platform.command", "platform.command.read", "platform.command.replay"))
    with pytest.raises(ReplayNotAllowed, match="new idempotency key"):
        await harness.kernel.replay(TENANT, command.command_id, principal=operator, mode=ReplayMode.REEXECUTE, idempotency_key="replay-0003", expected_version=1, reason="r")
    replayed = await harness.kernel.replay(TENANT, command.command_id, principal=operator, mode=ReplayMode.REEXECUTE, idempotency_key="replay-0003", expected_version=1, reason="r", new_idempotency_key="idem-new-00000002")
    assert replayed.command_id != command.command_id
    events = await harness.commands.list_events(TENANT, replayed.command_id, limit=5)
    assert events[0].safe_metadata["replay_mode"] == "REEXECUTE"
    assert events[0].safe_metadata["replay_of"] == str(command.command_id)
    assert len(harness.store._outbox) == 2


# ----------------------------------------------------------------------------
# tenant isolation and describe
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_tenant_isolation(harness: Harness) -> None:
    command = envelope()
    await harness.submit(command)
    from app.commands import CommandNotFound

    with pytest.raises(CommandNotFound):
        await harness.kernel.get(OTHER_TENANT, command.command_id)
    with pytest.raises(CommandNotFound):
        await harness.kernel.cancel(OTHER_TENANT, command.command_id, principal=principal(tenants=(OTHER_TENANT,)), idempotency_key="cancel-x001", expected_version=1, reason="r")
    with pytest.raises(PolicyDenied, match="tenant_not_authorized"):
        await harness.submit(envelope(tenant_id=OTHER_TENANT))


def test_describe_exposes_registries_and_no_secrets(harness: Harness) -> None:
    description = harness.kernel.describe(runtime_schema_version=11, contract_digest="abc", command_contract_version="command-envelope.v1")
    assert description["canonical_port"] == 8095
    assert description["provider_effects_enabled"] is False
    assert all(value is False for value in description["effect_defaults"].values())
    assert "test-syn" in [row["adapter_id"] for row in description["adapters"]]
    assert {row["prefix"] for row in description["command_prefixes"]} >= {"crm.", "test.syn."}
    flat = str(description).lower()
    for forbidden in ("password", "secret", "token", "authorization", "private_key"):
        assert forbidden not in flat or forbidden in {"token"} and "kill_switch" in flat


def test_test_syn_policy_is_never_registered_in_production(test_settings: Settings) -> None:
    production = test_settings.replace(app_env="production")
    registry = command_policies(production, CommandPolicyRegistry((CommandPolicy("crm.", "odoo-19", "ODOO_WRITE", True),), {"ODOO_WRITE": False}))
    assert registry.resolve("test.syn.execute.v1") is None
    assert "TEST_SYN_EXECUTE" not in registry.capabilities


@pytest.mark.asyncio
async def test_bus_fails_closed_when_target_connector_is_not_served(harness: Harness) -> None:
    command = envelope()
    submitted = await harness.submit(command)
    adapter = harness.test_syn
    adapter.connector_ids = ("different-connector",)

    await harness.bus.drain()

    current = await harness.commands.get(TENANT, submitted.operation.command_id)
    assert current.state == "dead_lettered"
    assert adapter.provider_effects == 0


@pytest.mark.asyncio
async def test_bus_uses_provider_status_before_readback_for_async_completion(harness: Harness) -> None:
    command = envelope(payload={"probe": True, "fixture": "success"})
    submitted = await harness.submit(command)

    await harness.bus.drain()

    current = await harness.commands.get(TENANT, submitted.operation.command_id)
    assert current.state == "completed"
    assert current.provider_operation_id is not None
    assert str(command.command_id) in harness.test_syn.readbacks


@pytest.mark.asyncio
async def test_reconciler_dead_letters_when_connector_mapping_disappears(harness: Harness) -> None:
    command = envelope(payload={"probe": True, "fixture": "unknown"})
    submitted = await harness.submit(command)
    await harness.bus.drain()
    current = await harness.commands.get(TENANT, submitted.operation.command_id)
    assert current.state == "reconciliation_required"

    harness.test_syn.connector_ids = ("different-connector",)
    harness.bus.expire_leases()
    decision = await harness.reconciler.run_once()

    assert decision is not None
    assert decision.action == "dead_letter"
    current = await harness.commands.get(TENANT, submitted.operation.command_id)
    assert current.state == "dead_lettered"
    assert harness.test_syn.provider_effects == 1
