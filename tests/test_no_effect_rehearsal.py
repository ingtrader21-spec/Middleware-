from __future__ import annotations

from pathlib import Path

import pytest

from app.platform.no_effect_rehearsal import (
    NoEffectRehearsalError,
    parse_env_file,
    validate_no_effect_runtime,
    validate_repository_no_effect_runtime,
)


ROOT = Path(__file__).resolve().parents[1]


def test_repository_production_runtime_is_no_effect() -> None:
    result = validate_repository_no_effect_runtime(ROOT)
    assert result.profile_id == "codestra-middleware-production-v1"
    assert result.provider_effects == 0
    assert result.production_effects == 0
    assert result.production_go == "NO"
    assert len(result.checked_flags) >= 20


def test_activation_id_must_be_empty() -> None:
    values = parse_env_file(ROOT / "config" / "environments" / "production.runtime.env.example")
    values["PRODUCTION_ACTIVATION_ID"] = "should-not-exist"
    with pytest.raises(NoEffectRehearsalError, match="must be empty"):
        validate_no_effect_runtime(values)


def test_effect_flag_must_remain_false() -> None:
    values = parse_env_file(ROOT / "config" / "environments" / "production.runtime.env.example")
    values["SMS_DELIVERY_ENABLED"] = "true"
    with pytest.raises(NoEffectRehearsalError, match="SMS_DELIVERY_ENABLED must remain false"):
        validate_no_effect_runtime(values)


def test_worker_and_dispatch_modes_must_remain_disabled() -> None:
    values = parse_env_file(ROOT / "config" / "environments" / "production.runtime.env.example")
    values["NATS_DISPATCH_MODE"] = "enabled"
    with pytest.raises(NoEffectRehearsalError, match="NATS_DISPATCH_MODE"):
        validate_no_effect_runtime(values)


def test_missing_deny_flag_fails_closed() -> None:
    values = parse_env_file(ROOT / "config" / "environments" / "production.runtime.env.example")
    del values["EMAIL_DELIVERY_ENABLED"]
    with pytest.raises(NoEffectRehearsalError, match="required deny flag missing"):
        validate_no_effect_runtime(values)


def test_every_required_runtime_identity_value_fails_closed_when_changed() -> None:
    baseline = parse_env_file(ROOT / "config" / "environments" / "production.runtime.env.example")
    expected = {
        "APP_ENV": "production",
        "RUNTIME_PROFILE_ID": "codestra-middleware-production-v1",
        "NATS_DISPATCH_MODE": "disabled",
        "TEMPORAL_WORKER_MODE": "disabled",
        "PRODUCTION_DIALING": "DISABLED",
    }
    for key, required in expected.items():
        values = dict(baseline)
        values[key] = required + "-drift"
        with pytest.raises(NoEffectRehearsalError, match=key):
            validate_no_effect_runtime(values)


@pytest.mark.parametrize("enabled", ["true", "TRUE", "1", "yes", "enabled"])
def test_each_truthy_spelling_is_rejected_for_effect_flags(enabled: str) -> None:
    baseline = parse_env_file(ROOT / "config" / "environments" / "production.runtime.env.example")
    for flag in (
        "SMS_DELIVERY_ENABLED",
        "EMAIL_DELIVERY_ENABLED",
        "SOCIAL_DELIVERY_ENABLED",
        "OUTBOX_DISPATCH_ENABLED",
    ):
        values = dict(baseline)
        values[flag] = enabled
        with pytest.raises(NoEffectRehearsalError, match=flag):
            validate_no_effect_runtime(values)


def test_duplicate_env_keys_are_rejected(tmp_path: Path) -> None:
    env_file = tmp_path / "runtime.env"
    env_file.write_text("APP_ENV=production\nAPP_ENV=staging\n", encoding="utf-8")
    with pytest.raises(NoEffectRehearsalError, match="duplicate env key: APP_ENV"):
        parse_env_file(env_file)


def test_malformed_env_line_is_rejected(tmp_path: Path) -> None:
    env_file = tmp_path / "runtime.env"
    env_file.write_text("APP_ENV=production\nBROKEN_LINE\n", encoding="utf-8")
    with pytest.raises(NoEffectRehearsalError, match="invalid env line"):
        parse_env_file(env_file)
