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
