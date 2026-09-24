from __future__ import annotations

import os
import re
from urllib.parse import unquote, urlparse

import pytest


SAFE_DB_NAME = re.compile(r"^middleware_test_[A-Za-z0-9_]+$")


def _reject_url_overrides(parsed, label: str) -> None:
    if parsed.params or parsed.query or parsed.fragment:
        pytest.fail(f"{label} must not contain params, query overrides, or fragments")


@pytest.fixture(scope="session", autouse=True)
def require_disposable_integration_targets() -> None:
    """Fail before any destructive fixture if integration mode is unsafe.

    The shell wrapper performs the same checks, but the pytest suite must remain
    safe when invoked directly by a developer or alternate CI runner.
    """

    if os.getenv("RUNTIME_INTEGRATION_TESTS") != "1":
        return

    if os.getenv("RUNTIME_INTEGRATION_ALLOW_DISPOSABLE") != "YES":
        pytest.fail("RUNTIME_INTEGRATION_ALLOW_DISPOSABLE=YES is required")

    database_url = os.getenv("DATABASE_URL", "")
    redis_url = os.getenv("REDIS_URL", "")
    pg = urlparse(database_url)
    redis = urlparse(redis_url)

    if pg.scheme not in {"postgres", "postgresql"}:
        pytest.fail("DATABASE_URL must use postgres/postgresql")
    _reject_url_overrides(pg, "DATABASE_URL")
    if pg.hostname not in {"127.0.0.1", "localhost"}:
        pytest.fail("DATABASE_URL must target localhost disposable PostgreSQL")
    database_name = unquote(pg.path.lstrip("/"))
    if not SAFE_DB_NAME.fullmatch(database_name):
        pytest.fail("database name must match middleware_test_[A-Za-z0-9_]+")

    if redis.scheme not in {"redis", "rediss"}:
        pytest.fail("REDIS_URL must use redis/rediss")
    _reject_url_overrides(redis, "REDIS_URL")
    if redis.hostname not in {"127.0.0.1", "localhost"}:
        pytest.fail("REDIS_URL must target localhost disposable Redis")
    try:
        redis_db = int(unquote(redis.path.lstrip("/") or "0"))
    except ValueError:
        pytest.fail("REDIS_URL must select an explicit numeric disposable DB")
    if redis_db <= 0:
        pytest.fail("REDIS_URL must not target Redis DB 0 for destructive integration tests")
