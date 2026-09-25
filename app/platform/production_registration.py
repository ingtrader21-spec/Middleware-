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

    known_adapters = {
        str(item["id"])
        for item in adapter_registry.get("adapters", [])
        if isinstance(item, dict) and item.get("id")
    }
    capabilities = capability_registry.get("capabilities") or {}
    seen: set[str] = set()

    for item in registration.get("adapters", []):
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

        for capability in effect_capabilities:
            if capability not in capabilities:
                raise ProductionRegistrationError(
                    f"unknown effect capability {capability!r} for {adapter_id}"
                )
            if capabilities[capability] is not False:
                raise ProductionRegistrationError(
                    f"effect capability must remain false: {capability}"
                )


def validate_repository_registration(repo_root: str | Path) -> None:
    root = Path(repo_root)
    validate_production_registration(
        _load_json(root / "config" / "production-adapter-registration.v1.json"),
        _load_json(root / "config" / "adapter-registry.v2.json"),
        _load_json(root / "config" / "capabilities.v2.json"),
    )
