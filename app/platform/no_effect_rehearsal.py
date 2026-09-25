from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class NoEffectRehearsalError(ValueError):
    pass


@dataclass(frozen=True)
class NoEffectRehearsalResult:
    profile_id: str
    provider_effects: int
    production_effects: int
    production_go: str
    checked_flags: tuple[str, ...]


_REQUIRED_VALUES = {
    "APP_ENV": "production",
    "RUNTIME_PROFILE_ID": "codestra-middleware-production-v1",
    "NATS_DISPATCH_MODE": "disabled",
    "TEMPORAL_WORKER_MODE": "disabled",
    "PRODUCTION_DIALING": "DISABLED",
}

_FALSE_FLAGS = (
    "LIVE_ADVERTISING_ENABLED",
    "EXTERNAL_DELIVERY_ENABLED",
    "SOCIAL_PUBLISHING_ENABLED",
    "EXTERNAL_MODEL_CALLS_ENABLED",
    "N8N_EXTERNAL_PROVIDER_WRITES",
    "OUTBOX_DISPATCH_ENABLED",
    "SEND_EVENTS",
    "ENABLE_EXTERNAL_DELIVERY",
    "LIVE_WRITE",
    "LIVE_WRITES",
    "ODOO_WRITE",
    "CALLBACK_DISPATCH",
    "N8N_DELIVERY_ENABLED",
    "VICIDIAL_WRITES_ENABLED",
    "EXTERNAL_DIAL_ENABLED",
    "PRODUCTION_CALLBACKS_ENABLED",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED",
    "SMS_DELIVERY_ENABLED",
    "EMAIL_DELIVERY_ENABLED",
    "SOCIAL_DELIVERY_ENABLED",
    "CRAWLER_EXECUTION_ENABLED",
    "SCRAPPER_EXECUTION_ENABLED",
)


def parse_env_file(path: str | Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            raise NoEffectRehearsalError(f"invalid env line: {raw!r}")
        values[key.strip()] = value.strip()
    return values


def validate_no_effect_runtime(values: dict[str, str]) -> NoEffectRehearsalResult:
    for key, expected in _REQUIRED_VALUES.items():
        actual = values.get(key)
        if actual != expected:
            raise NoEffectRehearsalError(f"{key} must be {expected!r}, got {actual!r}")

    if values.get("PRODUCTION_ACTIVATION_ID", ""):
        raise NoEffectRehearsalError("PRODUCTION_ACTIVATION_ID must be empty")

    checked: list[str] = []
    for key in _FALSE_FLAGS:
        actual = values.get(key)
        if actual is None:
            raise NoEffectRehearsalError(f"required deny flag missing: {key}")
        if actual.lower() != "false":
            raise NoEffectRehearsalError(f"{key} must remain false")
        checked.append(key)

    return NoEffectRehearsalResult(
        profile_id=values["RUNTIME_PROFILE_ID"],
        provider_effects=0,
        production_effects=0,
        production_go="NO",
        checked_flags=tuple(checked),
    )


def validate_repository_no_effect_runtime(repo_root: str | Path) -> NoEffectRehearsalResult:
    root = Path(repo_root)
    return validate_no_effect_runtime(
        parse_env_file(root / "config" / "environments" / "production.runtime.env.example")
    )
