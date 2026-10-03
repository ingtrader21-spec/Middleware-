"""PAS-78: the PostgreSQL access-path map must match the source it describes.

``docs/evidence/pas78-db-path-evidence-map-20260924/db-access-paths.v1.json``
lists every call that opens a database connection, pool or engine. These tests
read the repository (AST, not regex) so a new connection path cannot appear
without being mapped, and a mapped path cannot disappear without the map being
updated. Behavioural findings the map records are pinned here as well.
"""

from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app.core.config import ConfigurationError

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "docs" / "evidence" / "pas78-db-path-evidence-map-20260924"
MAP = json.loads((EVIDENCE_DIR / "db-access-paths.v1.json").read_text(encoding="utf-8"))

# Calls that open a connection, pool or engine. Attribute calls are recorded as
# ``module.attr``; bare-name calls by their name.
ATTRIBUTE_CALLS = {
    ("asyncpg", "create_pool"),
    ("asyncpg", "connect"),
    ("sqlite3", "connect"),
    ("psycopg", "connect"),
    ("psycopg2", "connect"),
    ("sqlalchemy", "create_engine"),
}
NAME_CALLS = {
    "create_async_engine",
    "async_engine_from_config",
    "engine_from_config",
    "create_engine",
}


def _source_files() -> list[Path]:
    files: list[Path] = []
    for root in MAP["scanned_roots"]:
        files.extend(
            path
            for path in sorted((ROOT / root).rglob("*.py"))
            if "tests" not in path.relative_to(ROOT).parts
        )
    return files


def _connection_calls(path: Path) -> list[str]:
    calls: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and (func.value.id, func.attr) in ATTRIBUTE_CALLS
        ):
            calls.append(f"{func.value.id}.{func.attr}")
        elif isinstance(func, ast.Name) and func.id in NAME_CALLS:
            calls.append(func.id)
    return calls


def test_every_connection_site_is_mapped() -> None:
    actual = Counter(
        (path.relative_to(ROOT).as_posix(), call)
        for path in _source_files()
        for call in _connection_calls(path)
    )
    mapped = Counter((site["file"], site["call"]) for site in MAP["connection_sites"])
    assert actual - mapped == Counter(), "unmapped connection sites; add them to the PAS-78 map"
    assert mapped - actual == Counter(), "stale connection sites in the PAS-78 map"


def test_connection_site_ids_are_unique_and_complete() -> None:
    ids = [site["id"] for site in MAP["connection_sites"]]
    assert len(ids) == len(set(ids))
    for site in MAP["connection_sites"]:
        for key in ("file", "call", "components", "dsn_source", "dsn_transform", "tls", "status"):
            assert site.get(key), f"{site['id']} is missing {key}"


def test_shell_paths_still_use_their_tool() -> None:
    for entry in MAP["shell_paths"]:
        path = ROOT / entry["file"]
        assert path.is_file(), entry["id"]
        token = "postgres-exporter" if entry["tool"] == "postgres-exporter" else entry["tool"]
        assert token in path.read_text(encoding="utf-8"), entry["id"]


def test_application_name_is_set_only_where_mapped() -> None:
    actual = {
        path.relative_to(ROOT).as_posix()
        for path in _source_files()
        if "application_name" in path.read_text(encoding="utf-8")
    }
    assert actual == set(MAP["application_name_files"])


def test_duplicate_dsn_normalizers_agree() -> None:
    from app.core.runtime import _asyncpg_dsn
    from app.db.session import _native_asyncpg_dsn

    samples = (
        "postgresql+asyncpg://u:p@db:5432/n?sslmode=verify-full",
        "postgresql://u:p@db:5432/n?sslmode=verify-full",
        "postgresql+asyncpg://u:p%25x@db/n",
        "",
    )
    for dsn in samples:
        assert _asyncpg_dsn(dsn) == _native_asyncpg_dsn(dsn)
        assert not _asyncpg_dsn(dsn).startswith("postgresql+asyncpg://")


def _locked_profile(profile_id: str) -> dict[str, object]:
    registry = json.loads((ROOT / "config" / "runtime-profiles.v1.json").read_text(encoding="utf-8"))
    return next(p for p in registry["profiles"] if p["profile_id"] == profile_id)["database"]


def _profile_dsn(database: dict[str, object], *, scheme: str | None = None, extra: str = "") -> str:
    query = f"?sslmode={database['sslmode']}" if database.get("sslmode") else ""
    if extra:
        query = f"{query}&{extra}" if query else f"?{extra}"
    return (
        f"{scheme or database['scheme']}://{database['username']}:placeholder@"
        f"{database['host']}:{database['port']}/{database['name']}{query}"
    )


def _validate(dsn: str, database: dict[str, object]) -> None:
    from app.core.config import settings

    candidate = settings.model_copy()
    candidate.database_url = dsn
    candidate._validate_database_profile(database)


def test_locked_profiles_admit_only_sslmode_in_the_dsn_query() -> None:
    """F-02: a CA/client-cert path cannot be carried in DATABASE_URL."""
    database = _locked_profile("codestra-middleware-staging-v1")
    _validate(_profile_dsn(database), database)
    for extra in (
        "sslrootcert=/run/secrets/database-ca.crt",
        "sslcert=/run/secrets/client.crt",
        "application_name=middleware-api",
    ):
        with pytest.raises(ConfigurationError):
            _validate(_profile_dsn(database, extra=extra), database)


def test_profile_tls_policy_is_as_mapped() -> None:
    """F-03: the production-compose profile locks the DSN to no sslmode."""
    assert _locked_profile("codestra-middleware-staging-v1")["sslmode"] == "verify-full"
    assert _locked_profile("codestra-middleware-production-v1")["sslmode"] == "verify-full"
    compose = _locked_profile("codestra-middleware-production-compose-v1")
    assert compose["sslmode"] is None
    assert parse_qs(urlsplit(_profile_dsn(compose)).query) == {}


def test_process_settings_rewrite_is_present() -> None:
    """F-01 precondition: the module-level scheme rewrite still exists."""
    source = (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    assert 'settings.database_url.replace(\n        "postgresql://", "postgresql+asyncpg://", 1\n    )' in source


@pytest.mark.xfail(
    strict=True,
    raises=ConfigurationError,
    reason=(
        "PAS-78 F-01: app/core/config.py rewrites the process settings DSN to "
        "postgresql+asyncpg:// after loading, and validate_domain() on those "
        "settings compares the scheme with the locked profile's 'postgresql'."
    ),
)
def test_process_normalized_dsn_passes_its_locked_profile() -> None:
    database = _locked_profile("codestra-middleware-staging-v1")
    raw = _profile_dsn(database)
    # Mirrors the module-level rewrite at the end of app/core/config.py.
    process_dsn = raw.replace("postgresql://", "postgresql+asyncpg://", 1)
    _validate(process_dsn, database)


def test_every_finding_is_documented() -> None:
    findings = (EVIDENCE_DIR / "07-findings.md").read_text(encoding="utf-8")
    for finding in MAP["findings"]:
        assert f"## {finding} " in findings, finding
