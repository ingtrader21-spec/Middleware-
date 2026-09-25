from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from app.platform.production_registration import (
    ProductionRegistrationError,
    validate_production_registration,
    validate_repository_registration,
)


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> dict:
    return json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))


def test_repository_production_adapter_registration_is_fail_closed() -> None:
    validate_repository_registration(ROOT)


def test_unreviewed_adapter_is_rejected() -> None:
    registration = _load("production-adapter-registration.v1.json")
    adapters = _load("adapter-registry.v2.json")
    capabilities = _load("capabilities.v2.json")
    registration = copy.deepcopy(registration)
    registration["adapters"].append(
        {
            "id": "unknown-provider",
            "registered": True,
            "effect_capabilities": ["EMAIL_DELIVERY"],
        }
    )

    with pytest.raises(ProductionRegistrationError, match="unreviewed adapter"):
        validate_production_registration(registration, adapters, capabilities)


def test_enabled_effect_capability_is_rejected() -> None:
    registration = _load("production-adapter-registration.v1.json")
    adapters = _load("adapter-registry.v2.json")
    capabilities = copy.deepcopy(_load("capabilities.v2.json"))
    capabilities["capabilities"]["SMS_DELIVERY"] = True

    with pytest.raises(ProductionRegistrationError, match="must remain false"):
        validate_production_registration(registration, adapters, capabilities)


def test_global_effect_or_go_flag_is_rejected() -> None:
    adapters = _load("adapter-registry.v2.json")
    capabilities = _load("capabilities.v2.json")

    for key in ("provider_effects", "production_effects", "production_go"):
        registration = copy.deepcopy(_load("production-adapter-registration.v1.json"))
        registration[key] = True
        with pytest.raises(ProductionRegistrationError, match=f"{key} must be false"):
            validate_production_registration(registration, adapters, capabilities)


def test_unknown_capability_policy_must_deny() -> None:
    registration = copy.deepcopy(_load("production-adapter-registration.v1.json"))
    adapters = _load("adapter-registry.v2.json")
    capabilities = _load("capabilities.v2.json")
    registration["unknown_capability_policy"] = "ALLOW"

    with pytest.raises(ProductionRegistrationError, match="must be DENY"):
        validate_production_registration(registration, adapters, capabilities)
