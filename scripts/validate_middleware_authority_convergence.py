#!/usr/bin/env python3
"""Strict forward-authority checks layered over the historical inventory validator.

The base module is retained verbatim so this focused correction cannot silently
alter the already-reviewed Server A inventory and backup validation behavior.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_BASE_PATH = Path(__file__).with_name(
    "validate_middleware_authority_convergence_base.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "middleware_authority_convergence_base",
    _BASE_PATH,
)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - import invariant
    raise RuntimeError(f"cannot load base authority validator: {_BASE_PATH}")
_BASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BASE)

ROOT = _BASE.ROOT
# Forward schema requirement; preserve the reviewed historical base verbatim.
setattr(_BASE, "CURRENT_SCHEMA_HEAD", "0069_campaign_recycling_delivery_events")
SOURCE_RESOLUTION = (
    "resolve the exact protected-main GitHub event SHA at workflow execution"
)
REQUIRED_RUNTIME_EVIDENCE = (
    "signed release manifest bound to exact protected-main source",
    "immutable image digest and verified provenance",
    "schema head 0069_campaign_recycling_delivery_events",
    "effective source, digest, schema, profile, and capability read-back",
    "backup and isolated restore evidence",
    "rollback rehearsal and data-integrity evidence",
    "zero live-effect counters",
)
REQUIRED_SAFETY_BOUNDARY = {
    "deploymentAuthorizedByThisFile": False,
    "productionTrafficAuthorizedByThisFile": False,
    "externalEffectsAuthorizedByThisFile": False,
    "liveWritesRequired": False,
    "odooWritesRequired": False,
    "n8nDeliveryRequired": False,
    "emailDeliveryRequired": False,
    "smsDeliveryRequired": False,
    "socialPublishingRequired": False,
    "pstnDialingRequired": False,
    "callsPlacedExpected": 0,
}

_BASE_VALIDATE_FORWARD_AUTHORITY = _BASE.validate_forward_authority


def validate_forward_authority(authority: dict[str, Any]) -> list[str]:
    """Validate every field that keeps the forward release authority fail closed."""

    errors = list(_BASE_VALIDATE_FORWARD_AUTHORITY(authority))

    repository = authority.get("repositoryAuthority")
    if (
        isinstance(repository, dict)
        and repository.get("sourceResolution") != SOURCE_RESOLUTION
    ):
        errors.append(
            "forward authority sourceResolution must resolve the exact "
            "protected-main GitHub event SHA at workflow execution"
        )

    runtime = authority.get("runtimeAuthority")
    if isinstance(runtime, dict):
        required_evidence = runtime.get("requiredEvidence")
        if (
            not isinstance(required_evidence, list)
            or tuple(required_evidence) != REQUIRED_RUNTIME_EVIDENCE
        ):
            errors.append(
                "runtimeAuthority.requiredEvidence must contain the exact named "
                "backup, isolated-restore, rollback, schema, provenance, read-back, "
                "and zero-live-effect gates"
            )

    safety = authority.get("safetyBoundary")
    if not isinstance(safety, dict) or set(safety) != set(REQUIRED_SAFETY_BOUNDARY):
        errors.append("forward safetyBoundary must contain the exact required key set")
    elif safety != REQUIRED_SAFETY_BOUNDARY:
        errors.append(
            "forward safetyBoundary values must preserve every fail-closed denial"
        )

    return errors


# The base document validator resolves this symbol from its own module globals.
# Replace it before delegating so both direct checks and full-document checks use
# the strict current-authority contract.
setattr(_BASE, "validate_forward_authority", validate_forward_authority)


def validate_document(
    document: dict[str, Any],
    root: Path = ROOT,
) -> list[str]:
    return _BASE.validate_document(document, root=root)


def main(argv: list[str] | None = None) -> int:
    return _BASE.main(argv)


def __getattr__(name: str) -> Any:
    """Preserve the existing module surface for current tests and callers."""

    return getattr(_BASE, name)


if __name__ == "__main__":
    raise SystemExit(main())
