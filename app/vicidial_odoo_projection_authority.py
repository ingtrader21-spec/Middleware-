from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from . import vicidial_odoo_projection_authority_base as _BASE
from .vicidial_odoo_projection_errors import ProjectionConfigurationError

_SOURCE_AUTHORITY = _BASE._SOURCE_AUTHORITY
_SHA40 = _BASE._SHA40


def _load_authority_document(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProjectionConfigurationError(
            "projection source authority cannot be loaded"
        ) from exc
    if not isinstance(document, dict):
        raise ProjectionConfigurationError(
            "projection source authority identity is invalid"
        )
    return document


def load_projection_source_locks(
    path: Path = _SOURCE_AUTHORITY,
) -> dict[str, str]:
    """Return locks only when every dependency is a protected-main merge.

    Candidate heads are useful review evidence, but they are never runtime
    authority. An enabled worker must stop before NATS, state, or Odoo access
    until every prerequisite row records an immutable protected-main merge SHA.
    """

    locks = _BASE.load_projection_source_locks(path)
    document = _load_authority_document(path)
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ProjectionConfigurationError(
            "projection source authority dependency coverage is invalid"
        )

    for name in sorted(dependencies):
        row = dependencies.get(name)
        if not isinstance(row, dict):
            raise ProjectionConfigurationError(
                f"{name} source authority record is invalid"
            )
        if row.get("state_at_lock") != "merged":
            raise ProjectionConfigurationError(
                f"{name} dependency must be a protected-main merge before activation"
            )
        if row.get("base_ref") != "refs/heads/main" or "base_sha" in row:
            raise ProjectionConfigurationError(
                f"{name} dependency must identify protected refs/heads/main"
            )
        merge_sha = row.get("merge_sha")
        source_sha = row.get("source_sha")
        if (
            not isinstance(merge_sha, str)
            or _SHA40.fullmatch(merge_sha) is None
            or source_sha != merge_sha
        ):
            raise ProjectionConfigurationError(
                f"{name} dependency must pin one immutable merge SHA"
            )
        runtime_env = row.get("runtime_env")
        if not isinstance(runtime_env, str) or locks.get(runtime_env) != merge_sha:
            raise ProjectionConfigurationError(
                f"{name} runtime lock does not match its protected merge"
            )

    return locks


def validate_projection_source_locks(
    source: Mapping[str, str],
    *,
    path: Path = _SOURCE_AUTHORITY,
) -> dict[str, str]:
    """Require runtime read-back variables to equal protected merge SHAs."""

    locks = load_projection_source_locks(path)
    for runtime_env, expected_sha in sorted(locks.items()):
        observed = source.get(runtime_env, "").strip().lower()
        if observed != expected_sha:
            raise ProjectionConfigurationError(
                f"{runtime_env} must equal locked source {expected_sha}"
            )
    return locks
