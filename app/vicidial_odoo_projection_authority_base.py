from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Mapping

from .vicidial_odoo_projection_errors import ProjectionConfigurationError

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_AUTHORITY = (
    _ROOT
    / "config"
    / "vicidial-odoo-projection-source-authority.v1.json"
)
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_EXPECTED_DEPENDENCIES = frozenset({"keycloak", "odoo", "vicidial"})


def load_projection_source_locks(
    path: Path = _SOURCE_AUTHORITY,
) -> dict[str, str]:
    """Load the exact cross-repository source tuple for this projection.

    Repository metadata cannot prove a runtime deployment, but an enabled worker
    must still be bound to the exact reviewed dependency sources rather than to
    floating PR heads or branch names. Any malformed or incomplete authority is
    therefore a startup-blocking configuration error.
    """

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProjectionConfigurationError(
            "projection source authority cannot be loaded"
        ) from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "1.0"
        or document.get("kind")
        != "vicidial-odoo-projection-source-authority"
    ):
        raise ProjectionConfigurationError(
            "projection source authority identity is invalid"
        )

    dependencies = document.get("dependencies")
    if not isinstance(dependencies, dict) or set(dependencies) != set(
        _EXPECTED_DEPENDENCIES
    ):
        raise ProjectionConfigurationError(
            "projection source authority dependency coverage is invalid"
        )

    locks: dict[str, str] = {}
    for name in sorted(_EXPECTED_DEPENDENCIES):
        row = dependencies.get(name)
        if not isinstance(row, dict):
            raise ProjectionConfigurationError(
                f"{name} source authority record is invalid"
            )
        source_sha = row.get("source_sha")
        runtime_env = row.get("runtime_env")
        repository = row.get("repository")
        pull_request = row.get("pull_request")
        if (
            not isinstance(source_sha, str)
            or _SHA40.fullmatch(source_sha) is None
            or not isinstance(runtime_env, str)
            or not runtime_env
            or not isinstance(repository, str)
            or "/" not in repository
            or type(pull_request) is not int
            or pull_request <= 0
            or row.get("merge_required_before_activation") is not True
        ):
            raise ProjectionConfigurationError(
                f"{name} source authority fields are invalid"
            )
        if runtime_env in locks:
            raise ProjectionConfigurationError(
                "projection source authority reuses a runtime variable"
            )
        locks[runtime_env] = source_sha

    boundary = document.get("activation_boundary")
    if not isinstance(boundary, dict):
        raise ProjectionConfigurationError(
            "projection activation boundary is missing"
        )
    expected_false = (
        "source_merge_authorized_by_this_file",
        "runtime_activation_authorized_by_this_file",
        "production_dialing_authorized_by_this_file",
        "external_effects_authorized_by_this_file",
    )
    if any(boundary.get(field) is not False for field in expected_false):
        raise ProjectionConfigurationError(
            "projection source authority grants an effect"
        )
    if (
        boundary.get("requires_exact_runtime_source_readback") is not True
        or boundary.get("requires_protected_dependency_merges") is not True
        or boundary.get("calls_placed_expected") != 0
    ):
        raise ProjectionConfigurationError(
            "projection activation boundary is not fail closed"
        )
    return locks


def validate_projection_source_locks(
    source: Mapping[str, str],
    *,
    path: Path = _SOURCE_AUTHORITY,
) -> dict[str, str]:
    """Require runtime read-back variables to equal the reviewed source tuple."""

    locks = load_projection_source_locks(path)
    for runtime_env, expected_sha in sorted(locks.items()):
        observed = source.get(runtime_env, "").strip().lower()
        if observed != expected_sha:
            raise ProjectionConfigurationError(
                f"{runtime_env} must equal locked source {expected_sha}"
            )
    return locks
