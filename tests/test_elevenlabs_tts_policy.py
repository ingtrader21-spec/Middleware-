from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def protected_key(tmp_path: Path, value: bytes) -> Path:
    path = tmp_path / "api-key"
    path.write_bytes(value)
    path.chmod(0o400)
    return path


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r", b"\r\n"])
def test_text_secret_reader_removes_at_most_one_terminal_newline(
    tmp_path: Path, ending: bytes
) -> None:
    key = protected_key(tmp_path, b"synthetic-key" + ending)
    assert Settings._protected_text_secret(str(key), "synthetic key") == "synthetic-key"


@pytest.mark.parametrize(
    "value",
    [b"", b"two words", b"line\nbreak", b"nul\x00byte", b"\xffbinary", b"x\n\n"],
)
def test_text_secret_reader_rejects_malformed_values(
    tmp_path: Path, value: bytes
) -> None:
    key = protected_key(tmp_path, value)
    with pytest.raises(ValueError, match="malformed"):
        Settings._protected_text_secret(str(key), "synthetic key")


def test_text_secret_reader_rejects_unsafe_metadata(tmp_path: Path) -> None:
    key = protected_key(tmp_path, b"synthetic-key")
    key.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe"):
        Settings._protected_text_secret(str(key), "synthetic key")


def test_runtime_secret_path_cannot_be_redirected(tmp_path: Path) -> None:
    key = protected_key(tmp_path, b"synthetic-key")
    configured = Settings(elevenlabs_api_key_file=str(key))
    with pytest.raises(ValueError, match="path is not approved"):
        _ = configured.elevenlabs_api_key


def test_provider_is_disabled_and_governance_is_fixed_by_default() -> None:
    configured = Settings()
    assert configured.elevenlabs_provider_enabled is False
    assert configured.elevenlabs_base_url == "https://api.elevenlabs.io"
    assert configured.elevenlabs_model_id == "eleven_flash_v2_5"
    assert configured.elevenlabs_browser_output_format == "mp3_44100_128"
    assert configured.elevenlabs_telephony_output_format == "ulaw_8000"
    assert configured.elevenlabs_max_text_characters == 1000
    assert configured.elevenlabs_max_concurrency == 1
    assert configured.elevenlabs_request_logging_mode == "standard"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("elevenlabs_base_url", "http://api.elevenlabs.io"),
        ("elevenlabs_base_url", "https://attacker.invalid"),
        ("elevenlabs_model_id", "unapproved-model"),
        ("elevenlabs_canary_voice_id", "../voice"),
        ("elevenlabs_canary_voice_id", "voice?output_format=ulaw_8000"),
        ("elevenlabs_browser_output_format", "ulaw_8000"),
        ("elevenlabs_telephony_output_format", "mp3_44100_128"),
        ("elevenlabs_max_text_characters", 1001),
        ("elevenlabs_max_concurrency", 2),
        ("elevenlabs_connect_timeout_seconds", 0),
        ("elevenlabs_read_timeout_seconds", 121),
        ("elevenlabs_total_timeout_seconds", -1),
        ("elevenlabs_max_retries", 3),
        ("elevenlabs_request_logging_mode", "assume-zero-retention"),
    ],
)
def test_invalid_governance_configuration_fails_startup(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        Settings(**cast(Any, {field: value}))
