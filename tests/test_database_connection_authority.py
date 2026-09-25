"""DB-02/DB-03 canonical PostgreSQL connection authority tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.core.config import ConfigurationError, Settings, WEBHOOK_PRODUCERS
from app.db.connection import (
    DatabaseConnectionError,
    asyncpg_connection_kwargs,
    build_database_connection_authority,
)
from app.db import session as db_session


def _url(*, mode: str = "verify-full", extra: str = "") -> str:
    return (
        "postgresql://middleware_api:secret@postgres:5432/middleware_staging"
        f"?sslmode={mode}{extra}"
    )


def test_runtime_and_direct_asyncpg_share_exact_native_dsn() -> None:
    value = _url(
        extra=(
            "&sslrootcert=%2Frun%2Fsecrets%2Fca.crt"
            "&sslcert=%2Frun%2Fsecrets%2Fclient.crt"
            "&sslkey=%2Frun%2Fsecrets%2Fclient.key"
        )
    )
    authority = build_database_connection_authority(
        value,
        command_timeout_seconds=30,
        application_name="codestra-middleware/test",
        secure_environment=True,
        validate_tls_files=False,
    )
    dsn, kwargs = asyncpg_connection_kwargs(authority)
    assert dsn == value
    assert authority.sqlalchemy_url == "postgresql+asyncpg://"
    assert authority.connect_args["dsn"] == value
    assert kwargs == {
        "command_timeout": 30,
        "server_settings": {
            "search_path": "public",
            "application_name": "codestra-middleware/test",
        },
    }
    assert authority.sslmode == "verify-full"
    assert set(authority.tls_paths) == {"sslrootcert", "sslcert", "sslkey"}


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer", "require", "verify-ca"])
def test_staging_and_production_refuse_tls_downgrade(mode: str) -> None:
    with pytest.raises(DatabaseConnectionError, match="verify-full"):
        build_database_connection_authority(
            _url(mode=mode),
            command_timeout_seconds=30,
            application_name="codestra-middleware/staging",
            secure_environment=True,
            validate_tls_files=False,
        )


def test_database_query_cannot_override_target_identity() -> None:
    with pytest.raises(DatabaseConnectionError, match="override"):
        build_database_connection_authority(
            _url(extra="&host=other"),
            command_timeout_seconds=30,
            application_name="codestra-middleware/test",
            validate_tls_files=False,
        )


def test_client_certificate_and_key_are_atomic() -> None:
    with pytest.raises(DatabaseConnectionError, match="together"):
        build_database_connection_authority(
            _url(extra="&sslcert=%2Frun%2Fsecrets%2Fclient.crt"),
            command_timeout_seconds=30,
            application_name="codestra-middleware/staging",
            secure_environment=True,
            validate_tls_files=False,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX private-key mode contract")
def test_tls_files_are_readable_and_private(tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    for path in (ca, cert, key):
        path.write_text("test", encoding="utf-8")
    key.chmod(0o600)
    value = _url(
        extra=(
            f"&sslrootcert={ca}&sslcert={cert}&sslkey={key}"
        )
    )
    authority = build_database_connection_authority(
        value,
        command_timeout_seconds=30,
        application_name="codestra-middleware/staging",
        secure_environment=True,
    )
    assert authority.tls_paths["sslkey"] == key
    key.chmod(0o644)
    with pytest.raises(DatabaseConnectionError, match="permissions"):
        build_database_connection_authority(
            value,
            command_timeout_seconds=30,
            application_name="codestra-middleware/staging",
            secure_environment=True,
        )


def test_process_engine_uses_credential_free_sqlalchemy_url(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_create_async_engine(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(db_session, "create_async_engine", fake_create_async_engine)
    config = Settings.from_env(
        {
            "APP_ENV": "test",
            "DATABASE_URL": "postgresql://u:p@db.internal/testdb?sslmode=require",
            "REDIS_URL": "redis://127.0.0.1:6379/0",
        }
    )
    result = db_session._build_engine(config)
    assert result is not None
    assert captured["url"] == "postgresql+asyncpg://"
    connect_args = captured["connect_args"]
    assert isinstance(connect_args, dict)
    assert connect_args["dsn"].startswith("postgresql://u:p@db.internal/testdb")
    assert connect_args["server_settings"]["application_name"] == "codestra-middleware/test"


def test_compose_staging_profile_locks_tls_and_topology() -> None:
    env = {
        "APP_ENV": "staging",
        "ENVIRONMENT": "staging",
        "RUNTIME_PROFILE_ID": "codestra-middleware-staging-v1",
        "DATABASE_URL": (
            "postgresql://middleware_api:secret@postgres:5432/middleware_staging"
            "?sslmode=verify-full"
            "&sslrootcert=/run/secrets/middleware-staging-db-ca.crt"
            "&sslcert=/run/secrets/middleware-staging-db-client.crt"
            "&sslkey=/run/secrets/middleware-staging-db-client.key"
        ),
        "REDIS_URL": "redis://:secret@redis:6379/0",
        "NATS_STREAM": "CODESTRA_STAGING_EVENTS",
        "NATS_SUBJECT_PREFIX": "codestra.staging.events",
        "TEMPORAL_NAMESPACE": "codestra-staging",
        "TEMPORAL_TASK_QUEUE": "codestra-staging-critical",
        "KEYCLOAK_ISSUER": "https://auth-staging.codestra.co/realms/codestra",
        "KEYCLOAK_JWKS_URL": (
            "https://auth-staging.codestra.co/realms/codestra/"
            "protocol/openid-connect/certs"
        ),
        "KEYCLOAK_AUDIENCE": "middleware-api",
        "APP_SOURCE_SHA": "a" * 40,
        "IMAGE_DIGEST": "sha256:" + "b" * 64,
        "BUILD_TIME": "2026-09-21T11:16:00Z",
    }
    for producer in WEBHOOK_PRODUCERS:
        name = "WEBHOOK_SECRET_" + producer.upper().replace("-", "_").replace(".", "_")
        env[name] = "x" * 32
    settings = Settings.from_env(env)
    assert settings.runtime_profile_id == "codestra-middleware-staging-v1"
    for role in ("middleware_worker", "middleware_reconciler", "middleware_scheduler"):
        role_env = dict(env)
        role_env["DATABASE_URL"] = role_env["DATABASE_URL"].replace(
            "middleware_api:secret@", f"{role}:secret@"
        )
        role_settings = Settings.from_env(role_env)
        assert role_settings.runtime_profile_id == "codestra-middleware-staging-v1"
    bad = dict(env)
    bad["DATABASE_URL"] = bad["DATABASE_URL"].replace("sslmode=verify-full", "sslmode=require")
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        Settings.from_env(bad)
