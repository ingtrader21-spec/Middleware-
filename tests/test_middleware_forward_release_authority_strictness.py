from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = (
    ROOT / "config" / "middleware-forward-release-authority.v1.json"
)
VALIDATOR_PATH = (
    ROOT / "scripts" / "validate_middleware_authority_convergence.py"
)

SPEC = importlib.util.spec_from_file_location(
    "strict_middleware_authority_validator",
    VALIDATOR_PATH,
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def _authority() -> dict[str, Any]:
    value = json.loads(AUTHORITY_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_source_resolution_mode_is_mandatory_and_exact() -> None:
    value = copy.deepcopy(_authority())
    value["repositoryAuthority"]["sourceResolution"] = "use any branch HEAD"

    errors = validator.validate_forward_authority(value)

    assert any("sourceResolution" in error for error in errors)


def test_every_named_runtime_evidence_gate_is_mandatory() -> None:
    value = copy.deepcopy(_authority())
    value["runtimeAuthority"]["requiredEvidence"] = [
        "schema head 0058_campaign_design"
    ] * 7

    errors = validator.validate_forward_authority(value)

    assert any("exact named" in error for error in errors)


def test_every_safety_boundary_field_is_mandatory() -> None:
    value = copy.deepcopy(_authority())
    del value["safetyBoundary"]["externalEffectsAuthorizedByThisFile"]

    errors = validator.validate_forward_authority(value)

    assert any("exact required key set" in error for error in errors)
