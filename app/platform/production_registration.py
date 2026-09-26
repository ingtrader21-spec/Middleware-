from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ProductionRegistrationError(ValueError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_production_registration(
    registration: dict[str, Any],
    adapter_registry: dict[str, Any],
    capability_registry: dict[str, Any],
) -> None:
    if registration.get("environment") != "production":
        raise ProductionRegistrationError("environment must be production")

    for key in ("provider_effects", "production_effects", "production_go"):
        if registration.get(key) is not False:
            raise ProductionRegistrationError(f"{key} must be false")

    if registration.get("unknown_capability_policy") != "DENY":
        raise ProductionRegistrationError("unknown capability policy must be DENY")

    if capability_registry.get("default_policy") != "DENY":
        raise ProductionRegistrationError("canonical capability default policy must be DENY")

    registry_items = adapter_registry.get("adapters")
    if not isinstance(registry_items, list) or not registry_items:
        raise ProductionRegistrationError("canonical adapter registry must be a non-empty list")
    known_adapters: set[str] = set()
    for item in registry_items:
        if not isinstance(item, dict) or not str(item.get("id") or "").strip():
            raise ProductionRegistrationError("canonical adapter registry entries require ids")
        adapter_id = str(item["id"])
        if adapter_id in known_adapters:
            raise ProductionRegistrationError(f"duplicate canonical adapter: {adapter_id}")
        known_adapters.add(adapter_id)

    capabilities = capability_registry.get("capabilities")
    if not isinstance(capabilities, dict) or not capabilities:
        raise ProductionRegistrationError("canonical capabilities must be a non-empty object")
    if any(not isinstance(name, str) or not isinstance(value, bool) for name, value in capabilities.items()):
        raise ProductionRegistrationError("canonical capabilities must map names to booleans")

    registration_items = registration.get("adapters")
    if not isinstance(registration_items, list) or not registration_items:
        raise ProductionRegistrationError("production adapters must be a non-empty list")
    seen: set[str] = set()

    for item in registration_items:
        if not isinstance(item, dict):
            raise ProductionRegistrationError("adapter registration entries must be objects")

        adapter_id = str(item.get("id") or "")
        if not adapter_id:
            raise ProductionRegistrationError("adapter id is required")
        if adapter_id in seen:
            raise ProductionRegistrationError(f"duplicate adapter registration: {adapter_id}")
        seen.add(adapter_id)

        if adapter_id not in known_adapters:
            raise ProductionRegistrationError(f"unreviewed adapter: {adapter_id}")
        if item.get("registered") is not True:
            raise ProductionRegistrationError(f"adapter must be registered explicitly: {adapter_id}")

        effect_capabilities = item.get("effect_capabilities")
        if not isinstance(effect_capabilities, list) or not effect_capabilities:
            raise ProductionRegistrationError(
                f"adapter must declare effect capabilities: {adapter_id}"
            )

        if any(not isinstance(capability, str) or not capability for capability in effect_capabilities):
            raise ProductionRegistrationError(
                f"effect capabilities must be non-empty strings: {adapter_id}"
            )
        if len(effect_capabilities) != len(set(effect_capabilities)):
            raise ProductionRegistrationError(
                f"duplicate effect capability declaration: {adapter_id}"
            )

        for capability in effect_capabilities:
            if capability not in capabilities:
                raise ProductionRegistrationError(
                    f"unknown effect capability {capability!r} for {adapter_id}"
                )
            if capabilities[capability] is not False:
                raise ProductionRegistrationError(
                    f"effect capability must remain false: {capability}"
                )

    if seen != known_adapters:
        missing = sorted(known_adapters - seen)
        extra = sorted(seen - known_adapters)
        raise ProductionRegistrationError(
            f"production registration must exactly cover canonical adapters; missing={missing}, extra={extra}"
        )


def validate_repository_registration(repo_root: str | Path) -> None:
    root = Path(repo_root)
    validate_production_registration(
        _load_json(root / "config" / "production-adapter-registration.v1.json"),
        _load_json(root / "config" / "adapter-registry.v2.json"),
        _load_json(root / "config" / "capabilities.v2.json"),
    )
