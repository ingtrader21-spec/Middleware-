#!/usr/bin/env python3
"""Apply and read back all canonical runtime migration authorities.

Execution is a database mutation and requires the existing protected deployment
and backup gates. --verify-only performs read-back without upgrades or SQL DDL.
The connector-only config/migration-lineage.v1.json is not production authority.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]

ALEMBIC_VERSION_TABLE = "public.alembic_version"
MIGRATION_LOCK = 742603070118
PLATFORM_TABLES = (
    "platform_services", "platform_service_environments",
    "platform_provisioning_requests", "platform_provisioning_audit",
)
RECEIPT_TABLES = {
    "core": "public.middleware_schema_migrations",
    "automation-v2": "public.middleware_automation_schema_migrations",
}


class MigrationError(RuntimeError):
    """Safe, credential-free migration failure."""


def database_urls(value: str) -> tuple[str, str]:
    """Keep exactly one explicit target; do not use app settings/secret fallbacks."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise MigrationError("DATABASE_URL must use PostgreSQL")
    if not parsed.hostname or not parsed.path.strip("/") or parsed.fragment:
        raise MigrationError("DATABASE_URL requires an explicit host and database")
    overrides = {"host", "port", "database", "dbname", "user", "password", "dsn", "server_settings"}
    if any(key.lower() in overrides for key, _ in parse_qsl(parsed.query)):
        raise MigrationError("DATABASE_URL query must not override its target or schema")
    suffix = value.split(":", 1)[1]
    return "postgresql:" + suffix, "postgresql+asyncpg:" + suffix


def migration_sets() -> tuple[tuple[str, tuple[Path, ...]], ...]:
    core = tuple(sorted((ROOT / "migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")))
    automation = tuple(sorted((ROOT / "migrations/automation").glob("[0-9][0-9][0-9][0-9]_*.sql")))
    for authority, paths in (("core", core), ("automation-v2", automation)):
        versions = tuple(int(path.name[:4]) for path in paths)
        if not versions or versions != tuple(range(1, len(versions) + 1)):
            raise MigrationError(f"{authority} migration bundle is missing or non-contiguous")
    return (("core", core), ("automation-v2", automation))


async def verify_database_lineage(conn, graph: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    table = await conn.fetchval("SELECT to_regclass('public.alembic_version')::text")
    if table is None:
        return ()
    rows = await conn.fetch(f"SELECT version_num FROM {ALEMBIC_VERSION_TABLE} ORDER BY version_num")
    observed = tuple(row["version_num"] for row in rows)
    if not observed or any(not isinstance(item, str) or item not in graph for item in observed):
        raise MigrationError("database Alembic lineage is empty or unknown; no stamp or upgrade allowed")
    if len(set(observed)) != len(observed):
        raise MigrationError("database Alembic lineage contains duplicate revisions")
    # Multiple independent branch heads are legitimate, but a head plus its
    # own ancestor is not a valid Alembic version-table state.
    def ancestors(revision: str) -> set[str]:
        result: set[str] = set()
        pending = list(graph[revision])
        while pending:
            parent = pending.pop()
            if parent not in result:
                result.add(parent)
                pending.extend(graph[parent])
        return result
    if any(ancestors(revision).intersection(observed) for revision in observed):
        raise MigrationError("database Alembic lineage contains redundant ancestor revisions")
    return observed


def alembic_engine_options(url: str) -> tuple[str, dict[str, object]]:
    """Pass the validated native DSN to asyncpg, including its TLS semantics.

    The SQLAlchemy asyncpg dialect forwards URL query keys as driver keyword
    arguments. sslmode/sslrootcert/sslcert/sslkey are DSN parameters, not asyncpg
    connect() keywords. A credential-free dialect URL plus the complete native
    DSN preserves verify-full, client certificates, and escaped credentials on
    both connections without translating or dropping any TLS policy.
    """
    native_url, _ = database_urls(url)
    return "postgresql+asyncpg://", {
        "dsn": native_url,
        "command_timeout": 30,
        "server_settings": {"search_path": "public"},
    }


async def upgrade_alembic(url: str, expected: str) -> None:
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    def upgrade(connection) -> None:
        config = Config()
        config.set_main_option("script_location", str(ROOT / "migrations"))
        config.attributes["connection"] = connection
        command.upgrade(config, expected)

    engine_url, connect_args = alembic_engine_options(url)
    engine = create_async_engine(engine_url, poolclass=NullPool, connect_args=connect_args)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(upgrade)
    finally:
        await engine.dispose()


async def verify_complete_schema(conn, expected: str, graph, bundles) -> None:
    from scripts.runtime_sql_schema import verify_sql_schema

    observed = await verify_database_lineage(conn, graph)
    if observed != (expected,):
        raise MigrationError("actual Alembic head does not match the accepted release")
    for authority, paths in bundles:
        table = RECEIPT_TABLES[authority]
        if await conn.fetchval("SELECT to_regclass($1)::text", table) is None:
            raise MigrationError(f"{authority} migration receipt table is missing")
        rows = await conn.fetch(f"SELECT version FROM {table} ORDER BY version")
        actual = tuple(row["version"] for row in rows)
        required = tuple(int(path.name[:4]) for path in paths)
        if actual != required:
            raise MigrationError(f"{authority} migration receipts do not match packaged SQL")
    for table in PLATFORM_TABLES:
        if await conn.fetchval("SELECT to_regclass($1)::text", "public." + table) is None:
            raise MigrationError("required platform service catalog table is missing")
    await verify_sql_schema(conn, ROOT)


async def run_migrations(conn, sqlalchemy_url: str, expected: str, graph, bundles, *, verify_only: bool) -> None:
    # A non-blocking session lock prevents concurrent instances of this runner
    # from applying the same DDL. It is released by closing the connection.
    if not await conn.fetchval("SELECT pg_try_advisory_lock($1)", MIGRATION_LOCK):
        raise MigrationError("another runtime migration or verification is in progress")
    await verify_database_lineage(conn, graph)
    if not verify_only:
        await upgrade_alembic(sqlalchemy_url, expected)
        for authority, migrations in bundles:
            for migration in migrations:
                await conn.execute(migration.read_text(encoding="utf-8"))
                print(f"RUNTIME_MIGRATION_APPLIED={authority}/{migration.name}")
    await verify_complete_schema(conn, expected, graph, bundles)
    print("RUNTIME_ALEMBIC_HEAD=" + expected)
    print("AUTOMATION_V2_SCHEMA_MIGRATION=PASS")
    print("RUNTIME_SCHEMA_VERIFIED=PASS")
    if not verify_only:
        print("RUNTIME_MIGRATION=PASS")


async def main(*, verify_only: bool = False) -> None:
    # Script entrypoints start with scripts/ on sys.path; resolve the packaged
    # repository import here without an out-of-order module-level import.
    sys.path.insert(0, str(ROOT))
    from scripts.production_migration_authority import validate_authority

    from scripts.runtime_sql_schema import load_contract

    expected, graph, history_digest = validate_authority(ROOT)
    load_contract(ROOT, history_digest)  # Reject missing/stale baseline before any DB access.
    if os.environ.get("SCHEMA_HEAD", expected) != expected:
        raise MigrationError("SCHEMA_HEAD differs from the protected release authority")
    bundles = migration_sets()  # Detect missing image assets before connecting.
    native_url, sqlalchemy_url = database_urls(os.environ.get("DATABASE_URL", ""))
    import asyncpg
    conn = await asyncpg.connect(
        native_url, command_timeout=30, server_settings={"search_path": "public"},
    )
    try:
        await run_migrations(conn, sqlalchemy_url, expected, graph, bundles, verify_only=verify_only)
    finally:
        await conn.close()
    print("RUNTIME_MIGRATION_HISTORY=" + history_digest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(main(verify_only=args.verify_only))
    except Exception as exc:
        # Driver and SQLAlchemy exceptions may include DSNs, SQL or credentials.
        # Keep raw exceptions out of protected execution logs.
        print("RUNTIME_MIGRATION=FAIL ERROR_TYPE=" + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1) from None
