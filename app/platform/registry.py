"""The one adapter registry.

Adapters register once at process start. The registry refuses duplicate ids,
requires every adapter to own at least one command prefix of the command
registry (``connectors/generated/command-registry.v1.json`` through
:class:`app.commands.CommandPolicyRegistry`), requires exactly one owner per
prefix, requires readback support wherever the command registry demands it,
and reports as not ready when an *enabled* capability has no ready adapter.
The kernel routes only through :meth:`AdapterRegistry.owner_for`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

from app.commands import CommandPolicy, CommandPolicyRegistry
from app.platform.adapter import (
    Adapter,
    AdapterCapabilities,
    AdapterConfigurationError,
    AdapterContext,
    AdapterReadiness,
    assert_adapter,
)

logger = logging.getLogger("codestra.platform.registry")


class AdapterRegistryError(RuntimeError):
    """The adapter set cannot serve the command registry safely."""


@dataclass(frozen=True)
class Ownership:
    prefix: str
    target: str
    capability: str
    readback_required: bool
    adapter_id: str


class AdapterRegistry:
    def __init__(self, policies: CommandPolicyRegistry) -> None:
        self.policies = policies
        self._adapters: dict[str, Adapter] = {}
        self._advertised: dict[str, AdapterCapabilities] = {}
        # command prefix -> adapter id
        self._owners: dict[str, str] = {}
        self._validated = False

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register(self, candidate: object) -> Adapter:
        adapter = assert_adapter(candidate)
        adapter.validate_config()
        advertised = adapter.capabilities()
        if advertised.adapter_id != adapter.adapter_id:
            raise AdapterRegistryError(
                f"adapter {adapter.adapter_id!r} advertises a different id {advertised.adapter_id!r}"
            )
        if adapter.adapter_id in self._adapters:
            raise AdapterRegistryError(f"duplicate adapter id {adapter.adapter_id!r}")
        if not advertised.connector_ids:
            raise AdapterRegistryError(f"adapter {adapter.adapter_id!r} owns no connector id")
        # Resolve ownership before capability diagnostics. An adapter with no
        # target in the command registry is unowned regardless of advertised
        # capabilities; this keeps registration failures deterministic.
        matching_targets = [
            policy
            for policy in self.policies.policies
            if policy.target in advertised.connector_ids
        ]
        if not matching_targets:
            raise AdapterRegistryError(
                f"adapter {adapter.adapter_id!r} owns no command prefix of the command registry"
            )
        unknown = sorted(
            name
            for name in advertised.capabilities
            if name not in self.policies.capabilities
        )
        if unknown:
            raise AdapterRegistryError(
                f"adapter {adapter.adapter_id!r} advertises unknown capabilities {unknown}"
            )
        owned: list[CommandPolicy] = []
        for policy in self.policies.policies:
            if policy.target not in advertised.connector_ids:
                continue
            if policy.capability not in advertised.capabilities:
                raise AdapterRegistryError(
                    f"adapter {adapter.adapter_id!r} owns target {policy.target!r} but does not "
                    f"implement capability {policy.capability!r} required by prefix {policy.prefix!r}"
                )
            if policy.readback_required and not advertised.supports_readback:
                raise AdapterRegistryError(
                    f"adapter {adapter.adapter_id!r} must support readback for prefix {policy.prefix!r}"
                )
            existing = self._owners.get(policy.prefix)
            if existing is not None and existing != adapter.adapter_id:
                raise AdapterRegistryError(
                    f"command prefix {policy.prefix!r} would have two owners: {existing!r} and {adapter.adapter_id!r}"
                )
            owned.append(policy)
        if not owned:
            raise AdapterRegistryError(
                f"adapter {adapter.adapter_id!r} owns no command prefix of the command registry"
            )
        for policy in owned:
            self._owners[policy.prefix] = adapter.adapter_id
        self._adapters[adapter.adapter_id] = adapter
        self._advertised[adapter.adapter_id] = advertised
        self._validated = False
        return adapter

    def register_all(self, adapters: Iterable[object]) -> None:
        for adapter in adapters:
            self.register(adapter)

    def validate(self) -> None:
        """Every enabled capability must have exactly one owning adapter for
        each of its command prefixes. Disabled capabilities may be unowned
        (they cannot be activated by configuration alone)."""
        problems: list[str] = []
        for policy in self.policies.policies:
            enabled = self.policies.capabilities.get(policy.capability) is True
            owner = self._owners.get(policy.prefix)
            if enabled and owner is None:
                problems.append(
                    f"enabled capability {policy.capability!r} has no adapter for prefix {policy.prefix!r}"
                )
        if problems:
            raise AdapterRegistryError("; ".join(problems))
        self._validated = True

    @property
    def validated(self) -> bool:
        return self._validated

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

    def adapter(self, adapter_id: str) -> Adapter:
        try:
            return self._adapters[adapter_id]
        except KeyError:
            raise AdapterRegistryError(f"adapter {adapter_id!r} is not registered") from None

    def advertised(self, adapter_id: str) -> AdapterCapabilities:
        return self._advertised[adapter_id]

    def ownership(self, command_type: str) -> Ownership | None:
        policy = self.policies.resolve(command_type)
        if policy is None:
            return None
        adapter_id = self._owners.get(policy.prefix)
        if adapter_id is None:
            return None
        return Ownership(
            prefix=policy.prefix,
            target=policy.target,
            capability=policy.capability,
            readback_required=policy.readback_required,
            adapter_id=adapter_id,
        )

    def owner_for(self, command_type: str) -> Adapter | None:
        ownership = self.ownership(command_type)
        if ownership is None:
            return None
        return self._adapters[ownership.adapter_id]

    def owners(self) -> dict[str, str]:
        return dict(sorted(self._owners.items()))

    def unowned_prefixes(self) -> tuple[str, ...]:
        return tuple(
            sorted(policy.prefix for policy in self.policies.policies if policy.prefix not in self._owners)
        )

    # ------------------------------------------------------------------
    # Readiness / description
    # ------------------------------------------------------------------
    async def readiness(self, context: AdapterContext) -> dict[str, AdapterReadiness]:
        report: dict[str, AdapterReadiness] = {}
        for adapter_id, adapter in sorted(self._adapters.items()):
            try:
                report[adapter_id] = await adapter.readiness(context)
            except Exception as exc:  # readiness must never raise into the probe
                logger.warning("adapter_readiness_failed", extra={"adapter": adapter_id, "error": type(exc).__name__})
                report[adapter_id] = AdapterReadiness(ready=False, detail=type(exc).__name__)
        return report

    def enabled_adapter_ids(self) -> tuple[str, ...]:
        """Adapters that own at least one prefix whose capability is enabled."""
        enabled: set[str] = set()
        for policy in self.policies.policies:
            if self.policies.capabilities.get(policy.capability) is True:
                owner = self._owners.get(policy.prefix)
                if owner is not None:
                    enabled.add(owner)
        return tuple(sorted(enabled))

    def describe(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for adapter_id in self.ids():
            advertised = self._advertised[adapter_id]
            rows.append(
                {
                    "adapter_id": adapter_id,
                    "version": advertised.version,
                    "provider_family": advertised.provider_family,
                    "connector_ids": list(advertised.connector_ids),
                    "capabilities": list(advertised.capabilities),
                    "command_prefixes": sorted(prefix for prefix, owner in self._owners.items() if owner == adapter_id),
                    "supports_readback": advertised.supports_readback,
                    "supports_cancel": advertised.supports_cancel,
                    "supports_status": advertised.supports_status,
                    "safe_reexecution": advertised.safe_reexecution,
                    "external_effect": advertised.external_effect,
                }
            )
        return rows


__all__ = [
    "AdapterConfigurationError",
    "AdapterRegistry",
    "AdapterRegistryError",
    "Ownership",
]
