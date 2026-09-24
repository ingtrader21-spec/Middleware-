"""Prove both migration connections preserve native DSN TLS policy."""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
from sqlalchemy.engine import make_url

from scripts import migrate_runtime as runner


@pytest.mark.parametrize("mode", ["disable", "require", "verify-ca", "verify-full"])
def test_tls_parameters_are_dsn_values_not_unsupported_driver_keywords(mode):
    native = (
        "postgresql://migration:p%25%40word@db.internal:5544/canonical"
        f"?sslmode={mode}&sslrootcert=%2Frun%2Fsecrets%2Fca.pem"
        "&sslcert=%2Frun%2Fsecrets%2Fclient.pem&sslkey=%2Frun%2Fsecrets%2Fclient.key"
    )
    native_dsn, sqlalchemy_url = runner.database_urls(native)
    engine_url, connect_args = runner.alembic_engine_options(sqlalchemy_url)
    # Exercise the real SQLAlchemy dialect without a database, network, or
    # asyncpg shim. The actual driver parses the same native DSN in each path.
    positional, keywords = PGDialect_asyncpg().create_connect_args(make_url(engine_url))
    keywords.update(connect_args)
    assert positional == []
    assert keywords == {
        "dsn": native_dsn,
        "command_timeout": 30,
        "server_settings": {"search_path": "public"},
    }
    assert native_dsn == native
    assert "sslmode" not in keywords and "ssl" not in keywords
    assert "migration" not in engine_url and "word" not in engine_url


def test_checked_production_tls_configuration_is_preserved():
    root = Path(__file__).resolve().parents[1]
    source = (root / "config/environments/production.runtime.env.example").read_text()
    assert "sslmode=verify-full" in source
    url = "postgresql://migration@db.internal/middleware?sslmode=verify-full"
    assert runner.alembic_engine_options(url)[1]["dsn"] == url


def test_tls_forwarding_cannot_override_the_accepted_database():
    with pytest.raises(runner.MigrationError, match="override"):
        runner.alembic_engine_options(
            "postgresql://migration@db.internal/accepted?sslmode=verify-full&host=other"
        )
