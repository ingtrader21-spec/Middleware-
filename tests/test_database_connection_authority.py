from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote

import pytest

from app.db.connection import (
    DatabaseConnectionError,
    database_connection_authority,
    native_postgres_dsn,
)


def _cert_url(tmp_path: Path, *, mode: str = "verify-full") -> str:
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"
    ca.write_text("ca", encoding="utf-8")
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    if os.name == "posix":
        key.chmod(0o600)
    return (
        "postgresql+asyncpg://middleware_api:secret@db.internal:5432/middleware"
        f"?sslmode={mode}&sslrootcert={quote(str(ca))}"
        f"&sslcert={quote(str(cert))}&sslkey={quote(str(key))}"
    )


def test_one_authority_supplies_sqlalchemy_and_asyncpg_options(tmp_path):
    url = _cert_url(tmp_path)
    authority = database_connection_authority(
        url,
        environment="production",
        application_name="middleware-api",
        command_timeout=17,
    )
    assert authority.native_dsn == native_postgres_dsn(url)
    assert authority.sqlalchemy_url == "postgresql+asyncpg://"
    assert authority.hostname == "db.internal"
    assert authority.database == "middleware"
    assert authority.sslmode == "verify-full"
    assert authority.connect_args == {
        "dsn": authority.native_dsn,
        "command_timeout": 17.0,
        "server_settings": {
            "search_path": "public",
            "application_name": "middleware-api",
        },
    }
    assert authority.asyncpg_connect_kwargs == authority.connect_args
    assert authority.asyncpg_pool_kwargs(min_size=1, max_size=8) == {
        **authority.connect_args,
        "min_size": 1,
        "max_size": 8,
    }


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer", "require", "verify-ca"])
def test_production_rejects_non_verify_full_tls(tmp_path, mode):
    with pytest.raises(DatabaseConnectionError, match="verify-full"):
        database_connection_authority(
            _cert_url(tmp_path, mode=mode),
            environment="production",
            application_name="middleware-api",
        )


def test_production_requires_complete_client_certificate_material(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("ca", encoding="utf-8")
    with pytest.raises(DatabaseConnectionError, match="CA, client certificate and private key"):
        database_connection_authority(
            "postgresql://middleware_api@db.internal/middleware"
            f"?sslmode=verify-full&sslrootcert={quote(str(ca))}",
            environment="production",
            application_name="middleware-api",
        )


def test_configured_certificate_paths_must_exist():
    with pytest.raises(DatabaseConnectionError, match="unavailable or unreadable"):
        database_connection_authority(
            "postgresql://u@db.internal/middleware?sslmode=verify-full"
            "&sslrootcert=/definitely/missing/ca.pem"
            "&sslcert=/definitely/missing/client.pem"
            "&sslkey=/definitely/missing/client.key",
            application_name="middleware-test",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-key mode check")
def test_private_key_permissions_fail_closed(tmp_path):
    url = _cert_url(tmp_path)
    (tmp_path / "client.key").chmod(0o644)
    with pytest.raises(DatabaseConnectionError, match="permissions"):
        database_connection_authority(
            url,
            environment="production",
            application_name="middleware-api",
        )


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_staging_and_production_require_explicit_database_user(environment):
    with pytest.raises(DatabaseConnectionError, match="explicit PostgreSQL user"):
        database_connection_authority(
            "postgresql://db.internal/middleware",
            environment=environment,
            application_name="middleware-api",
        )


def test_development_keeps_local_user_fallback_compatibility():
    authority = database_connection_authority(
        "postgresql+asyncpg://localhost/codestra_middleware",
        environment="development",
        application_name="middleware-dev",
    )
    assert authority.database == "codestra_middleware"


def test_query_cannot_override_connection_identity():
    with pytest.raises(DatabaseConnectionError, match="override"):
        database_connection_authority(
            "postgresql://u@db.internal/middleware?host=other",
            application_name="middleware-test",
        )


def test_pool_bounds_fail_closed():
    authority = database_connection_authority(
        "postgresql://u@localhost/middleware",
        application_name="middleware-test",
    )
    with pytest.raises(DatabaseConnectionError, match="pool bounds"):
        authority.asyncpg_pool_kwargs(min_size=4, max_size=2)


def test_application_name_and_search_path_are_restricted():
    with pytest.raises(DatabaseConnectionError, match="application_name"):
        database_connection_authority(
            "postgresql://u@localhost/middleware",
            application_name="middleware api",
        )
    with pytest.raises(DatabaseConnectionError, match="search_path"):
        database_connection_authority(
            "postgresql://u@localhost/middleware",
            application_name="middleware-test",
            search_path="public,extensions",
        )
