from __future__ import annotations

from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.ai_provider import AIProviderError
from app.core.config import Settings
from app.workers import openai_jobs


def test_models_reasoning_and_cost_are_explicit_configuration(monkeypatch) -> None:
    monkeypatch.setattr(openai_jobs.settings, "openai_chat_model", "gpt-5.6-terra")
    monkeypatch.setattr(openai_jobs.settings, "openai_coding_model", "gpt-5.6-sol")
    monkeypatch.setattr(openai_jobs.settings, "openai_chat_reasoning_effort", "low")
    monkeypatch.setattr(
        openai_jobs.settings, "openai_coding_reasoning_effort", "medium"
    )

    class Command:
        class Type:
            value = "ai.chat.v1"

        command_type = Type()

    command = cast(Any, Command())
    assert openai_jobs._routing(command) == ("gpt-5.6-terra", "low")
    Command.Type.value = "ai.coding.v1"
    assert openai_jobs._routing(command) == ("gpt-5.6-sol", "medium")
    assert openai_jobs._estimated_cost("gpt-5.6-terra", 100, 10) == 320
    assert openai_jobs._estimated_cost("gpt-5.6-sol", 100, 10) == 800
    with pytest.raises(AIProviderError, match="provider_price_policy_missing"):
        openai_jobs._estimated_cost("unpriced", 1, 1)


def test_openai_secrets_require_root_style_permissions(tmp_path: Path) -> None:
    key = tmp_path / "openai-key"
    salt = tmp_path / "safety-salt"
    key.write_text("test-only-key")
    salt.write_text("a" * 32)
    key.chmod(0o600)
    salt.chmod(0o600)
    configured = Settings(
        openai_api_key_file=str(key), openai_safety_salt_file=str(salt)
    )
    assert configured.openai_api_key == "test-only-key"
    assert configured.openai_safety_salt == b"a" * 32
    key.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe"):
        _ = configured.openai_api_key


def test_openai_safety_salt_accepts_binary_entropy_without_text_decoding(
    tmp_path: Path,
) -> None:
    salt = tmp_path / "binary-safety-salt"
    binary_entropy = bytes(range(32))
    salt.write_bytes(binary_entropy)
    salt.chmod(0o400)
    configured = Settings(openai_safety_salt_file=str(salt))
    assert configured.openai_safety_salt == binary_entropy


def test_provider_worker_is_disabled_by_default_and_has_no_tools() -> None:
    settings = Settings()
    assert settings.ai_submissions_enabled is False
    assert settings.ai_worker_claims_enabled is False
    assert settings.openai_provider_enabled is False
    source = Path("app/providers/openai_responses.py").read_text()
    assert '"store": False' in source
    assert '"tools"' not in source
    assert "api.openai.com/v1/responses" in source


@pytest.mark.parametrize("value", [0, -1, 2, "invalid", None])
def test_openai_concurrency_rejects_missing_or_invalid_values(value: object) -> None:
    with pytest.raises(ValueError, match="concurrency"):
        Settings(openai_worker_max_concurrency=value)  # type: ignore[arg-type]


def test_openai_concurrency_is_explicitly_one() -> None:
    configured = Settings(openai_worker_max_concurrency=1)
    assert configured.openai_worker_max_concurrency == 1


@pytest.mark.asyncio
async def test_registration_must_match_configured_concurrency(monkeypatch) -> None:
    monkeypatch.setattr(openai_jobs.settings, "openai_worker_max_concurrency", 1)
    result = MagicMock()
    result.mappings.return_value.first.return_value = {
        "max_concurrency": 1,
        "enabled": True,
    }
    db = AsyncMock()
    db.execute.return_value = result
    await openai_jobs.validate_worker_registration(db)

    result.mappings.return_value.first.return_value = {
        "max_concurrency": 2,
        "enabled": True,
    }
    with pytest.raises(RuntimeError, match="registration_invalid"):
        await openai_jobs.validate_worker_registration(db)


@pytest.mark.asyncio
async def test_capacity_wait_does_not_crash_worker(monkeypatch) -> None:
    calls = 0

    async def occupied(*_args: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OverflowError("worker_concurrency_limit")
        raise RuntimeError("stop-test-loop")

    async def no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr(openai_jobs.settings, "openai_worker_max_concurrency", 1)
    monkeypatch.setattr(openai_jobs, "cycle", occupied)
    monkeypatch.setattr(openai_jobs.asyncio, "sleep", no_wait)
    with pytest.raises(RuntimeError, match="stop-test-loop"):
        await openai_jobs.run_forever(cast(Any, object()), cast(Any, object()))
    assert calls == 2
