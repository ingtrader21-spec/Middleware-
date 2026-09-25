"""Production adapter registration: every capability OFF, fail closed.

``config/production-adapters.v1.json`` is the only list of adapters the
production kernel may register. :func:`register_production_adapters` joins
that manifest with the adapters that could be built from this process's
configuration and refuses the whole set — no adapter at all — when any of
these fails:

* ``activation_authorized`` is the literal ``false`` (activation belongs to a
  separate mission that meets the capability registry's
  ``activation_requirements``);
* every capability a manifest adapter serves is known to the capability
  registry, has an ``external_effect`` Safety Gate and is ``false``;
* no effectful capability of the capability registry is ``true``;
* every built adapter is listed in the manifest and advertises exactly the
  manifest's provider family, connector ids and capabilities.

A manifest adapter whose configuration does not validate is simply not
registered (``not_configured``); its capability stays unavailable, which the
Safety Gate reports as ``adapter_not_registered``. Registering an adapter
never activates an effect: the Safety Gate still denies ``capability_disabled``
for every command it owns.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.commands import CommandPolicyRegistry
from app.platform.adapter import Adapter, AdapterConfigurationError, assert_adapter
from app.platform.safety import SafetySwitches

logger = logging.getLogger("codestra.platform.production")

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "config" / "production-adapters.v1.json"

# Row reasons, stable for the readback API.
REGISTERED = "registered"
NOT_CONFIGURED = "not_configured"
MANIFEST_MISMATCH = "manifest_mismatch"
REGISTRATION_REFUSED = "registration_refused"


class ProductionManifestError(ValueError):
    """The production adapter manifest is malformed."""


@dataclass(frozen=True)
class ManifestAdapter:
    adapter_id: str
    provider_family: str
    connector_ids: tuple[str, ...]
    capabilities: tuple[str, ...]


def _names(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ProductionManifestError(f"{label} must be a non-empty list of names")
    if len(set(value)) != len(value):
        raise ProductionManifestError(f"{label} must not repeat a name")
    return tuple(value)


@dataclass(frozen=True)
class ProductionManifest:
    manifest_version: str
    activation_authorized: bool
    adapters: tuple[ManifestAdapter, ...]

    @classmethod
    def load(cls, path: Path = MANIFEST_PATH) -> "ProductionManifest":
        return cls.parse(json.loads(path.read_text(encoding="utf-8")))

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "ProductionManifest":
        if raw.get("schema_version") != "1.0":
            raise ProductionManifestError("unsupported production adapter manifest schema")
        if raw.get("environment") != "production":
            raise ProductionManifestError("the production adapter manifest must name the production environment")
        version = raw.get("manifest_version")
        if not isinstance(version, str) or not version:
            raise ProductionManifestError("manifest_version is required")
        activation = raw.get("activation_authorized")
        if not isinstance(activation, bool):
            raise ProductionManifestError("activation_authorized must be a boolean")
        items = raw.get("adapters")
        if not isinstance(items, list) or not items:
            raise ProductionManifestError("adapters must not be empty")
        adapters: list[ManifestAdapter] = []
        claimed: dict[str, str] = {}
        for item in items:
            if not isinstance(item, dict):
                raise ProductionManifestError("each adapter must be an object")
            adapter_id = item.get("adapter_id")
            family = item.get("provider_family")
            if not isinstance(adapter_id, str) or not adapter_id or not isinstance(family, str) or not family:
                raise ProductionManifestError("each adapter needs an adapter_id and a provider_family")
            entry = ManifestAdapter(
                adapter_id=adapter_id,
                provider_family=family,
                connector_ids=_names(item.get("connector_ids"), f"{adapter_id}.connector_ids"),
                capabilities=_names(item.get("capabilities"), f"{adapter_id}.capabilities"),
            )
            if any(existing.adapter_id == adapter_id for existing in adapters):
                raise ProductionManifestError(f"duplicate adapter id {adapter_id!r}")
            for capability in entry.capabilities:
                owner = claimed.setdefault(capability, adapter_id)
                if owner != adapter_id:
                    raise ProductionManifestError(f"capability {capability!r} is served by {owner!r} and {adapter_id!r}")
            adapters.append(entry)
        return cls(manifest_version=version, activation_authorized=activation, adapters=tuple(adapters))

    def entry(self, adapter_id: str) -> ManifestAdapter | None:
        return next((item for item in self.adapters if item.adapter_id == adapter_id), None)

    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted({capability for item in self.adapters for capability in item.capabilities}))


@dataclass(frozen=True)
class RegistrationRow:
    adapter_id: str
    provider_family: str
    connector_ids: tuple[str, ...]
    capabilities: tuple[str, ...]
    registered: bool
    reason: str

    def describe(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "provider_family": self.provider_family,
            "connector_ids": list(self.connector_ids),
            "capabilities": list(self.capabilities),
            "registered": self.registered,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RegistrationReport:
    manifest_version: str
    activation_authorized: bool
    rows: tuple[RegistrationRow, ...]
    violations: tuple[str, ...]
    adapters: tuple[Adapter, ...] = field(default=(), compare=False, repr=False)

    @property
    def refused(self) -> bool:
        return bool(self.violations)

    def row(self, adapter_id: str) -> RegistrationRow | None:
        return next((row for row in self.rows if row.adapter_id == adapter_id), None)

    def describe(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "activation_authorized": self.activation_authorized,
            "refused": self.refused,
            "violations": list(self.violations),
            "adapters": [row.describe() for row in self.rows],
        }


def effect_violations(
    manifest: ProductionManifest,
    policies: CommandPolicyRegistry,
    switches: SafetySwitches,
) -> list[str]:
    """Everything that would let a production registration carry an effect."""
    violations: set[str] = set()
    if manifest.activation_authorized is not False:
        violations.add("activation_authorized_must_be_false")
    for capability in manifest.capabilities():
        if capability not in policies.capabilities:
            violations.add(f"capability_unknown:{capability}")
        gate = switches.gates.get(capability)
        if gate is None:
            violations.add(f"capability_without_safety_gate:{capability}")
        elif gate.classification != "external_effect":
            violations.add(f"capability_not_external_effect:{capability}")
    for capability, enabled in policies.capabilities.items():
        gate = switches.gates.get(capability)
        # An ungated capability is treated as effectful (the Safety Gate does the same).
        if enabled is not False and (gate is None or gate.classification != "synthetic"):
            violations.add(f"capability_enabled:{capability}")
    for policy in policies.policies:
        if policy.capability not in policies.capabilities:
            violations.add(f"capability_unknown:{policy.capability}")
    return sorted(violations)


def register_production_adapters(
    policies: CommandPolicyRegistry,
    switches: SafetySwitches,
    *,
    candidates: Iterable[object],
    manifest: ProductionManifest | None = None,
) -> RegistrationReport:
    """Join the manifest with the adapters this process could build."""
    manifest = manifest or ProductionManifest.load()
    violations = effect_violations(manifest, policies, switches)
    built: dict[str, Adapter] = {}
    for candidate in candidates:
        try:
            adapter = assert_adapter(candidate)
        except AdapterConfigurationError:
            violations.append(f"adapter_contract_invalid:{type(candidate).__name__}")
            continue
        if adapter.adapter_id in built:
            violations.append(f"adapter_duplicate:{adapter.adapter_id}")
            continue
        built[adapter.adapter_id] = adapter
        if manifest.entry(adapter.adapter_id) is None:
            violations.append(f"adapter_not_in_manifest:{adapter.adapter_id}")

    rows: list[RegistrationRow] = []
    accepted: list[Adapter] = []
    for entry in manifest.adapters:
        chosen = built.get(entry.adapter_id)
        reason = NOT_CONFIGURED
        if chosen is not None:
            advertised = chosen.capabilities()
            if (
                advertised.adapter_id != entry.adapter_id
                or advertised.provider_family != entry.provider_family
                or set(advertised.connector_ids) != set(entry.connector_ids)
                or set(advertised.capabilities) != set(entry.capabilities)
            ):
                violations.append(f"adapter_manifest_mismatch:{entry.adapter_id}")
                reason = MANIFEST_MISMATCH
            else:
                reason = REGISTERED
                accepted.append(chosen)
        rows.append(
            RegistrationRow(
                adapter_id=entry.adapter_id,
                provider_family=entry.provider_family,
                connector_ids=entry.connector_ids,
                capabilities=entry.capabilities,
                registered=reason == REGISTERED,
                reason=reason,
            )
        )

    unique = tuple(sorted(set(violations)))
    if unique:
        # Fail closed: nothing registers when any rule is broken.
        logger.error("production_adapter_registration_refused", extra={"violations": list(unique)})
        rows = [
            RegistrationRow(
                adapter_id=row.adapter_id,
                provider_family=row.provider_family,
                connector_ids=row.connector_ids,
                capabilities=row.capabilities,
                registered=False,
                reason=REGISTRATION_REFUSED if row.reason == REGISTERED else row.reason,
            )
            for row in rows
        ]
        accepted = []
    return RegistrationReport(
        manifest_version=manifest.manifest_version,
        activation_authorized=manifest.activation_authorized,
        rows=tuple(rows),
        violations=unique,
        adapters=tuple(accepted),
    )


def production_candidates(settings: Any, *, http: Any) -> tuple[object, ...]:
    """Every production adapter whose configuration validates."""
    from app.platform.adapters.providers import provider_adapters

    adapters: list[object] = list(provider_adapters(settings, http=http))
    try:
        from app.db.session import SessionFactory
        from app.platform.adapters.n8n import n8n_adapter

        n8n = n8n_adapter(settings, SessionFactory)
    except Exception as exc:  # noqa: BLE001 - fail closed: the executor is simply unavailable
        logger.info("n8n adapter not registered: %s", type(exc).__name__)
        n8n = None
    if n8n is not None:
        adapters.append(n8n)
    return tuple(adapters)


__all__ = [
    "MANIFEST_PATH",
    "ManifestAdapter",
    "ProductionManifest",
    "ProductionManifestError",
    "RegistrationReport",
    "RegistrationRow",
    "effect_violations",
    "production_candidates",
    "register_production_adapters",
]
