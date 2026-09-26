from app.core.config import _load_process_settings
from types import SimpleNamespace

from app.db import session


def _settings():
    return SimpleNamespace(
        database_url="postgresql+asyncpg://local/default",
        database_pool_size=8,
        database_max_overflow=4,
        database_pool_timeout_seconds=5,
        database_pool_recycle_seconds=1800,
        database_command_timeout_seconds=30,
    )


def test_runtime_engine_preserves_verify_full_dsn(monkeypatch):
    captured = {}

    def fake_create_async_engine(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(session, "create_async_engine", fake_create_async_engine)
    dsn = (
        "postgresql+asyncpg://middleware_staging:PLACEHOLDER@postgres:5432/"
        "middleware_staging?sslmode=verify-full"
        "&sslrootcert=/run/secrets/database-ca.crt"
    )
    session._build_engine(_settings(), dsn)

    assert captured["url"] == "postgresql+asyncpg://"
    assert captured["kwargs"]["connect_args"]["dsn"] == (
        "postgresql://middleware_staging:PLACEHOLDER@postgres:5432/"
        "middleware_staging?sslmode=verify-full"
        "&sslrootcert=/run/secrets/database-ca.crt"
    )
    assert captured["kwargs"]["connect_args"]["command_timeout"] == 30


def test_process_settings_preserve_native_postgresql_dsn(monkeypatch):
    native = "postgresql://u:p@db.internal/testdb?sslmode=require"
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", native)
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.delenv("REDIS_URL_FILE", raising=False)

    process_settings = _load_process_settings()

    assert process_settings.database_url == native
