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
* ``production``: the adapters of ``config/production-adapters.v1.json``
  whose configuration validates, and only while every capability they serve
  is known, gated and ``false`` (:mod:`app.platform.production`). Any
  violation registers no adapter at all and fails readiness. Registration
  never activates an effect.

``PlatformRuntime.adapter_readback`` is the read-only evidence behind
``GET /platform/v1/adapters``: registration outcome per adapter, the state of
every capability, and readiness — probing only adapters that own an enabled
capability, so with every capability off no provider is contacted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

import asyncpg
import httpx

from app.commands import CommandPolicy, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.core.config import Settings
from app.platform.adapter import AdapterContext
from app.platform.bus import AdapterDispatch, BusSettings
from app.platform.kernel import CommandKernel, DenialAuditSink, MemoryDenialAuditSink
from app.platform.metrics import KernelMetrics
from app.platform.production import RegistrationReport, production_candidates, register_production_adapters
from app.platform.reconciler import Reconciler, ReconciliationSource
from app.platform.registry import AdapterRegistry, AdapterRegistryError
from app.platform.safety import SafetyGate

logger = logging.getLogger("codestra.platform.runtime")

SYNTHETIC_ENVIRONMENTS = frozenset({"development", "test", "staging", "preproduction"})
TEST_SYN_CAPABILITY = "TEST_SYN_EXECUTE"
TEST_SYN_TARGET = "test-syn"
TEST_SYN_PREFIX = "test.syn."

# How the adapter set was chosen (reported by the readback).
MODE_PRODUCTION_MANIFEST = "production_manifest"
MODE_ENVIRONMENT_DEFAULTS = "environment_defaults"
MODE_EXPLICIT = "explicit"


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
    registration_mode: str = MODE_EXPLICIT
    registration: RegistrationReport | None = None

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

    async def adapter_readback(self) -> dict[str, Any]:
        """Registration, capability and readiness evidence; never an effect."""
        policies = self.registry.policies
        capability_owners = self.registry.capability_owners()
        registered = set(self.registry.ids())
        described = self.registry.describe()
        # Every capability a policy, a registered adapter or the manifest names.
        referenced = {policy.capability for policy in policies.policies}
        referenced.update(name for row in described for name in row["capabilities"])
        if self.registration is not None:
            referenced.update(name for row in self.registration.rows for name in row.capabilities)
        rows: list[dict[str, Any]] = []
        for row in described:
            manifest_row = self.registration.row(row["adapter_id"]) if self.registration else None
            rows.append(
                {
                    **row,
                    "registered": True,
                    "reason": manifest_row.reason if manifest_row else "registered",
                    "capability_states": {name: policies.capabilities.get(name) is True for name in row["capabilities"]},
                }
            )
        if self.registration is not None:
            for manifest_row in self.registration.rows:
                if manifest_row.adapter_id in registered:
                    continue
                rows.append(
                    {
                        **manifest_row.describe(),
                        "registered": False,
                        "command_prefixes": [],
                        "capability_states": {name: policies.capabilities.get(name) is True for name in manifest_row.capabilities},
                    }
                )
        rows.sort(key=lambda item: item["adapter_id"])
        capabilities = {
            name: {
                "known": True,
                "enabled": value is True,
                "classification": self.safety.classification(name),
                "adapter_ids": list(capability_owners.get(name, ())),
            }
            for name, value in sorted(policies.capabilities.items())
        }
        effectful_enabled = sorted(
            name for name, state in capabilities.items() if state["enabled"] and state["classification"] != "synthetic"
        )
        probed = list(self.registry.enabled_adapter_ids())
        registry_valid = await self.registry_ready()
        return {
            "environment": self.settings.app_env,
            "source_sha": self.settings.source_sha,
            "registration_mode": self.registration_mode,
            "registration": self.registration.describe() if self.registration else None,
            "registry_valid": registry_valid,
            "registry_error": self.registry_error,
            "adapters": rows,
            "capabilities": capabilities,
            "unknown_capabilities": sorted(name for name in referenced if name not in policies.capabilities),
            "effectful_capabilities_enabled": effectful_enabled,
            "provider_effects_enabled": bool(effectful_enabled),
            "readiness": {
                "adapter_registry": registry_valid,
                "platform_adapters": await self.adapters_ready(),
                "probed_adapter_ids": probed,
            },
        }


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
    # Production registers through the manifest (build_platform_runtime).
    return ()


def build_platform_runtime(
    settings: Settings,
    *,
    commands: CommandService,
    http: httpx.AsyncClient | None,
    pool: asyncpg.Pool | None,
    service_id: str,
    adapters: Iterable[object] | None = None,
    candidates: Iterable[object] | None = None,
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
    registration: RegistrationReport | None = None
    production = settings.app_env == "production" and adapters is None
    if production:
        mode = MODE_PRODUCTION_MANIFEST
    else:
        mode = MODE_ENVIRONMENT_DEFAULTS if adapters is None else MODE_EXPLICIT
    try:
        if production:
            registration = register_production_adapters(
                commands.policies,
                safety.switches,
                candidates=production_candidates(settings, http=http) if candidates is None else candidates,
            )
            if registration.refused:
                raise AdapterRegistryError("production adapter registration refused: " + "; ".join(registration.violations))
            chosen: Iterable[object] = registration.adapters
        else:
            chosen = default_adapters(settings, http=http) if adapters is None else adapters
        registry.register_all(chosen)
        registry.validate()
    except AdapterRegistryError as exc:
        # Readiness reports it; the kernel refuses commands for unowned prefixes.
        registry_error = str(exc)
        logger.error("adapter_registry_invalid", extra={"error": registry_error})
        if production:
            # Fail closed: a partially registered production set routes nothing.
            registry = AdapterRegistry(commands.policies)

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
        registration_mode=mode,
        registration=registration,
    )


def describe_runtime(runtime: PlatformRuntime) -> dict[str, Any]:
    return {
        "adapters": runtime.registry.ids(),
        "owners": runtime.registry.owners(),
        "registry_error": runtime.registry_error,
        "registration_mode": runtime.registration_mode,
    }
