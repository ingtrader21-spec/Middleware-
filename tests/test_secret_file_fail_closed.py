"""OpenBao-rendered secret files: Middleware fails closed and never falls back to a plaintext default."""

from __future__ import annotations

import os

import pytest

from app.core.config import Settings


def make(**overrides):
    settings = Settings()
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


def test_rendered_files_replace_defaults_and_never_enter_the_environment(tmp_path):
    database = tmp_path / "database"
    redis = tmp_path / "redis"
    database.write_text(
        "postgresql+asyncpg://runtime:rendered@db.internal/codestra\n", encoding="utf-8"
    )
    redis.write_text("redis://:rendered@redis.internal:6379/2\n", encoding="utf-8")
    settings = make(database_url_file=str(database), redis_url_file=str(redis))
    settings.load_secret_files()
    assert (
        settings.database_url
        == "postgresql+asyncpg://runtime:rendered@db.internal/codestra"
    )
    assert settings.redis_url == "redis://:rendered@redis.internal:6379/2"
    assert "rendered" not in os.environ.get("DATABASE_URL", "")
    assert "rendered" not in os.environ.get("REDIS_URL", "")


@pytest.mark.parametrize(
    "prepare",
    [
        lambda p: None,  # missing: OpenBao agent has not rendered the file
        lambda p: p.write_text(
            "", encoding="utf-8"
        ),  # empty: rendering failed or lease expired and was scrubbed
        lambda p: p.write_text("   \n", encoding="utf-8"),
    ],
)
def test_unavailable_or_empty_rendering_fails_closed_without_plaintext_fallback(
    tmp_path, prepare
):
    path = tmp_path / "database"
    prepare(path)
    settings = make(
        database_url_file=str(path),
        database_url="postgresql+asyncpg://fallback@localhost/plaintext",
    )
    with pytest.raises(ValueError, match="database_url secret file"):
        settings.load_secret_files()
    # The plaintext default is never promoted into use once a rendered file is required.
    assert settings.database_url == "postgresql+asyncpg://fallback@localhost/plaintext"


def test_relative_secret_paths_are_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "database").write_text("postgresql+asyncpg://x@y/z", encoding="utf-8")
    settings = make(database_url_file="database")
    with pytest.raises(ValueError, match="unavailable"):
        settings.load_secret_files()
