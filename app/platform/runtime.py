"""Process-scoped wiring of the command kernel, owned by the RuntimeContainer.

``build_platform_runtime`` composes — exactly once per process — the kernel
metrics, the Safety Gate, the adapter registry (with the adapters this
environment may serve), the command kernel, the ``adapter-command`` outbox
handler and the reconciler over the container's existing
:class:`~app.commands.CommandService`, shared ``asyncpg`` pool and shared
``httpx.AsyncClient``. Nothing here opens a resource of its own.

Adapter set per environment (fail closed):

* ``development``/``test``: the TEST_SYN fixture plus the no-effect channel
  fixtures, so every kernel path is exercised without a provider;
* ``staging``/``preproduction``: the TEST_SYN fixture plus every provider
  adapter whose configuration validates (an unconfigured provider leaves its
  capability unavailable);
* ``production``: no adapter until a separate production mission registers
  them — every external-effect capability is ``false`` anyway.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable

import asyncpg
import httpx

from app.commands import CommandPolicy, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.core.config import Settings
from app.platform.adapter import AdapterContext
from app.platform.bus import AdapterDispatch, BusSettings
from app.platform.kernel import CommandKernel, DenialAuditSink, MemoryDenialAuditSink
from app.platform.metrics import KernelMetrics
from app.platform.reconciler import Reconciler, ReconciliationSource
from app.platform.rehearsal import RehearsalLedger
from app.platform.registry import AdapterRegistry, AdapterRegistryError
from app.platform.safety import SafetyGate

logger = logging.getLogger("codestra.platform.runtime")

SYNTHETIC_ENVIRONMENTS = frozenset({"development", "test", "staging", "preproduction"})
TEST_SYN_CAPABILITY = "TEST_SYN_EXECUTE"
TEST_SYN_TARGET = "test-syn"
TEST_SYN_PREFIX = "test.syn."


def synthetic_policy() -> CommandPolicy:
    return CommandPolicy(prefix=TEST_SYN_PREFIX, target=TEST_SYN_TARGET, capability=TEST_SYN_CAPABILITY, readback_required=True)


def command_policies(settings: Settings, base: CommandPolicyRegistry | None = None) -> CommandPolicyRegistry:
    """The one capability registry of the process: the file-backed registry,
    the N8N executor family (capability off, no connector manifest), plus the
    synthetic TEST_SYN family outside production."""
    from app.platform.adapters.n8n import N8N_CAPABILITY, n8n_policy

    registry = base or CommandPolicyRegistry.load()
    registry = registry.extended((n8n_policy(),), {N8N_CAPABILITY: False})
    if settings.app_env in SYNTHETIC_ENVIRONMENTS:
        return registry.extended((synthetic_policy(),), {TEST_SYN_CAPABILITY: True})
    return registry


@dataclass
class PlatformRuntime:
    settings: Settings
    metrics: KernelMetrics
    safety: SafetyGate
    registry: AdapterRegistry
    kernel: CommandKernel
    dispatch: AdapterDispatch
    reconciler: Reconciler | None
    denials: DenialAuditSink
    registry_error: str | None = None
    # Process-local read-back of the no-effect rehearsals run by this process.
    rehearsals: RehearsalLedger = field(default_factory=RehearsalLedger)

    async def registry_ready(self) -> bool:
        return self.registry_error is None and self.registry.validated

    async def adapters_ready(self) -> bool | None:
        """Every adapter that owns an *enabled* capability must be ready.
        ``None`` (not configured) when no enabled capability is owned."""
        enabled = self.registry.enabled_adapter_ids()
        if not enabled:
            return None
        context = AdapterContext(
            tenant_id="readiness",
            command_id="readiness",
            correlation_id="readiness",
            attempt=0,
            timeout_seconds=self.settings.readiness_timeout_seconds,
            environment=self.settings.app_env,
            deployment_sha=self.settings.source_sha,
            http=self.dispatch.http,
        )
        report = await self.registry.readiness(context)
        return all(report[adapter_id].ready for adapter_id in enabled if adapter_id in report)


def default_adapters(settings: Settings, *, http: httpx.AsyncClient | None) -> tuple[object, ...]:
    from app.platform.adapters.fixtures import development_fixtures, test_syn_adapter

    if settings.app_env in {"development", "test"}:
        return development_fixtures()
    if settings.app_env in {"staging", "preproduction"}:
        from app.platform.adapters.n8n import n8n_adapter
        from app.platform.adapters.providers import provider_adapters

        adapters: list[object] = [test_syn_adapter(), *provider_adapters(settings, http=http)]
        # The N8N executor wraps the reservation transport, which is written
        # against the ORM session factory of app.db.session.
        from app.db.session import SessionFactory

        n8n = n8n_adapter(settings, SessionFactory)
        if n8n is not None:
            adapters.append(n8n)
        return tuple(adapters)
    return ()


def build_platform_runtime(
    settings: Settings,
    *,
    commands: CommandService,
    http: httpx.AsyncClient | None,
    pool: asyncpg.Pool | None,
    service_id: str,
    adapters: Iterable[object] | None = None,
    denials: DenialAuditSink | None = None,
    reconciliation_source: ReconciliationSource | None = None,
    metrics: KernelMetrics | None = None,
    safety: SafetyGate | None = None,
    bus_settings: BusSettings | None = None,
) -> PlatformRuntime:
    metrics = metrics or KernelMetrics(service=service_id)
    safety = safety or SafetyGate(settings, commands.policies)
    registry = AdapterRegistry(commands.policies)
    registry_error: str | None = None
    try:
        registry.register_all(default_adapters(settings, http=http) if adapters is None else adapters)
        registry.validate()
    except AdapterRegistryError as exc:
        # Readiness reports it; the kernel refuses commands for unowned prefixes.
        registry_error = str(exc)
        logger.error("adapter_registry_invalid", extra={"error": registry_error})

    if denials is None:
        if pool is not None:
            from app.platform.persistence import PostgresDenialAuditSink

            denials = PostgresDenialAuditSink(pool)
        else:
            denials = MemoryDenialAuditSink()

    kernel = CommandKernel(
        settings=settings,
        commands=commands,
        registry=registry,
        safety=safety,
        metrics=metrics,
        denials=denials,
        service_id=service_id,
    )
    dispatch = AdapterDispatch(
        settings=settings,
        commands=commands,
        registry=registry,
        safety=safety,
        metrics=metrics,
        http=http,
        bus_settings=bus_settings,
    )
    if reconciliation_source is None:
        if pool is not None:
            from app.platform.persistence import PostgresReconciliationSource

            reconciliation_source = PostgresReconciliationSource(pool)
        elif isinstance(commands.store, MemoryCommandStore):
            from app.platform.memory import MemoryReconciliationSource

            reconciliation_source = MemoryReconciliationSource(commands.store)
    reconciler = (
        Reconciler(settings=settings, commands=commands, registry=registry, source=reconciliation_source, metrics=metrics, http=http)
        if reconciliation_source is not None
        else None
    )
    return PlatformRuntime(
        settings=settings,
        metrics=metrics,
        safety=safety,
        registry=registry,
        kernel=kernel,
        dispatch=dispatch,
        reconciler=reconciler,
        denials=denials,
        registry_error=registry_error,
    )


def describe_runtime(runtime: PlatformRuntime) -> dict[str, Any]:
    return {
        "adapters": runtime.registry.ids(),
        "owners": runtime.registry.owners(),
        "registry_error": runtime.registry_error,
    }
