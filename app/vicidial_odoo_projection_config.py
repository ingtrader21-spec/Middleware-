from __future__ import annotations

import json
import posixpath
from pathlib import Path
from typing import Any, Mapping

from . import vicidial_odoo_projection_config_base as _BASE
from .vicidial_odoo_projection_errors import ProjectionConfigurationError

parse_bool = _BASE.parse_bool
_ROOT = Path(__file__).resolve().parents[1]
_PROJECTION_RUNTIME_AUTHORITY = (
    _ROOT
    / "config"
    / "vicidial-odoo-projection-runtime-authority.v1.json"
)
_EXPECTED_PROFILE_IDS = frozenset(
    {
        "codestra-middleware-staging-v1",
        "codestra-middleware-production-v1",
        "codestra-middleware-production-compose-v1",
    }
)
_EXPECTED_SAFETY_BOUNDARY = {
    "runtime_activation_authorized_by_this_file": False,
    "production_dialing_authorized_by_this_file": False,
    "external_effects_authorized_by_this_file": False,
    "calls_placed_expected": 0,
}


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _load_projection_profile(profile_id: str) -> Mapping[str, Any]:
    try:
        document = json.loads(
            _PROJECTION_RUNTIME_AUTHORITY.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ProjectionConfigurationError(
            "projection runtime authority cannot be loaded"
        ) from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "1.0"
        or document.get("kind")
        != "vicidial-odoo-projection-runtime-authority"
    ):
        raise ProjectionConfigurationError(
            "projection runtime authority identity is invalid"
        )
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(
        _EXPECTED_PROFILE_IDS
    ):
        raise ProjectionConfigurationError(
            "projection runtime authority profile coverage is invalid"
        )
    safety = document.get("safety_boundary")
    if safety != _EXPECTED_SAFETY_BOUNDARY:
        raise ProjectionConfigurationError(
            "projection runtime authority safety boundary is invalid"
        )
    profile = profiles.get(profile_id)
    if not isinstance(profile, dict):
        raise ProjectionConfigurationError(
            "selected runtime profile has no projection authority"
        )
    expected_fields = {
        "environment",
        "mode",
        "odoo_origin",
        "hmac_secret_path_prefix",
    }
    if set(profile) != expected_fields:
        raise ProjectionConfigurationError(
            "selected projection profile authority is malformed"
        )
    return profile


def _validate_hmac_path(raw: str, *, prefix: str, name: str) -> None:
    path = Path(raw)
    normalized = posixpath.normpath(raw.replace("\\", "/"))
    if (
        not _BASE._absolute_like(path)
        or not prefix.startswith("/run/secrets/")
        or not prefix.endswith("-")
        or not normalized.startswith(prefix)
    ):
        raise ProjectionConfigurationError(
            f"{name} does not match the selected runtime profile"
        )


def _validate_projection_runtime_authority(
    settings: Any,
    source: Mapping[str, str],
) -> None:
    profile_id = settings.runtime_profile_id
    if not isinstance(profile_id, str) or not profile_id:
        raise ProjectionConfigurationError(
            "enabled projection requires RUNTIME_PROFILE_ID"
        )
    authority = _load_projection_profile(profile_id)
    if authority.get("environment") != settings.app_env:
        raise ProjectionConfigurationError(
            "projection authority environment does not match APP_ENV"
        )

    mode = authority.get("mode")
    if mode == "blocked-pending-protected-authority":
        raise ProjectionConfigurationError(
            "selected runtime profile has no approved Odoo endpoint authority"
        )
    if mode != "synthetic-only":
        raise ProjectionConfigurationError(
            "selected projection profile mode is invalid"
        )
    if not settings.synthetic_only or settings.activation_id is not None:
        raise ProjectionConfigurationError(
            "selected projection profile permits synthetic-only operation"
        )

    expected_origin = authority.get("odoo_origin")
    prefix = authority.get("hmac_secret_path_prefix")
    if not isinstance(expected_origin, str) or not isinstance(prefix, str):
        raise ProjectionConfigurationError(
            "selected runtime profile has incomplete Odoo authority"
        )
    observed_origin = _BASE._https_origin(settings.odoo_base_url or "")
    if observed_origin != _BASE._https_origin(expected_origin):
        raise ProjectionConfigurationError(
            "Odoo origin does not match the selected runtime profile"
        )

    paths = {
        "VICIDIAL_ODOO_HMAC_SECRET_FILE": source.get(
            "VICIDIAL_ODOO_HMAC_SECRET_FILE",
            "",
        ).strip(),
        "VICIDIAL_ODOO_TENANT_HMAC_SECRETS_FILE": source.get(
            "VICIDIAL_ODOO_TENANT_HMAC_SECRETS_FILE",
            "",
        ).strip(),
    }
    if not any(paths.values()):
        raise ProjectionConfigurationError(
            "enabled projection requires an Odoo HMAC secret file"
        )
    for name, raw in paths.items():
        if raw:
            _validate_hmac_path(raw, prefix=prefix, name=name)


class ProjectionSettings(_BASE.ProjectionSettings):
    """Projection settings with immutable runtime-authority validation."""

    def validate(self, source: Mapping[str, str]) -> None:
        super().validate(source)
        if self.enabled:
            _validate_projection_runtime_authority(self, source)


def __getattr__(name: str) -> Any:
    return getattr(_BASE, name)
