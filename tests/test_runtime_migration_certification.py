from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from scripts import migrate_runtime as runner
from scripts.production_migration_authority import validate_authority

ROOT = Path(__file__).resolve().parents[1]
HEAD, GRAPH, _ = validate_authority(ROOT)
BUNDLES = runner.migration_sets()


class Database:
    def __init__(self, revisions=None, *, lock=True):
        self.revisions = revisions
        self.lock = lock
        self.tables = {"public." + name for name in runner.PLATFORM_TABLES}
        self.tables.update(runner.RECEIPT_TABLES.values())
        self.receipts = {"core": list(range(1, 12)), "automation-v2": [1]}
        self.executed = []
        self.structural_checks = 0
        self.structural_error = False

    async def fetchval(self, query, *args):
        if "pg_try_advisory_lock" in query:
            return self.lock
        if "public.alembic_version" in query:
            return None if self.revisions is None else "alembic_version"
        assert query == "SELECT to_regclass($1)::text"
        return args[0] if args[0] in self.tables else None

    async def fetch(self, query):
        if "SELECT version_num" in query:
            return [{"version_num": value} for value in self.revisions]
        for authority, table in runner.RECEIPT_TABLES.items():
            if f"FROM {table} " in query:
                return [{"version": value} for value in self.receipts[authority]]
        raise AssertionError(query)

    async def execute(self, sql):
        self.executed.append(sql)


@pytest.fixture(autouse=True)
def structural_verifier_for_ordering_unit_tests(monkeypatch):
    # These tests use an in-memory connection to test runner sequencing only.
    # The catalog verifier has independent unit and real-PostgreSQL tests.
    from scripts import runtime_sql_schema

    async def verify(conn, root):
        assert isinstance(conn, Database)
        assert root == ROOT
        conn.structural_checks += 1
        if conn.structural_error:
            raise runtime_sql_schema.SchemaDriftError("damaged SQL-managed table")

    monkeypatch.setattr(runtime_sql_schema, "verify_sql_schema", verify)


def run(database, *, verify_only=False):
    return asyncio.run(
        runner.run_migrations(
            database,
            "postgresql+asyncpg://ci@localhost/middleware_test_migrations",
            HEAD,
            GRAPH,
            BUNDLES,
            verify_only=verify_only,
        )
    )


@pytest.mark.parametrize("scheme", ["postgres", "postgresql", "postgresql+asyncpg"])
def test_exact_database_target_is_shared(scheme):
    suffix = "//u:p%25%40word@db.internal:5544/canonical?ssl=require"
    assert runner.database_urls(scheme + ":" + suffix) == (
        "postgresql:" + suffix,
        "postgresql+asyncpg:" + suffix,
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "sqlite:///db",
        "postgresql:///db",
        "postgresql://host/",
        "postgresql://host/db#other",
    ],
)
def test_database_target_cannot_fall_back(url):
    with pytest.raises(runner.MigrationError):
        runner.database_urls(url)


def test_all_sql_bundles_are_packaged():
    assert [(name, len(files)) for name, files in BUNDLES] == [
        ("core", 11),
        ("automation-v2", 1),
    ]


def test_missing_sql_fails_before_connect(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    with pytest.raises(runner.MigrationError, match="bundle"):
        runner.migration_sets()


def test_unknown_database_never_reaches_upgrade_or_sql(monkeypatch, capsys):
    database = Database(["20260828_0004"])

    async def forbidden(*args):
        pytest.fail("unknown lineage must not invoke Alembic")

    monkeypatch.setattr(runner, "upgrade_alembic", forbidden)
    with pytest.raises(runner.MigrationError, match="unknown"):
        run(database)
    assert database.executed == []
    assert "RUNTIME_MIGRATION=PASS" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "revisions",
    [[], [HEAD, HEAD], [HEAD, "0056_klyrow_delivery_events"], [None], [" " + HEAD]],
)
def test_corrupt_revision_state_fails_closed(revisions):
    with pytest.raises(runner.MigrationError):
        asyncio.run(runner.verify_database_lineage(Database(revisions), GRAPH))


def test_migration_applies_alembic_then_sql_then_actual_readback(monkeypatch, capsys):
    database = Database()
    upgraded = []

    async def upgrade(url, expected):
        assert database.executed == []
        upgraded.append(expected)
        database.revisions = [expected]

    monkeypatch.setattr(runner, "upgrade_alembic", upgrade)
    run(database)
    assert upgraded == [HEAD]
    assert database.structural_checks == 1
    assert len(database.executed) == 12
    assert "RUNTIME_SCHEMA_VERIFIED=PASS" in capsys.readouterr().out


def test_failed_alembic_never_applies_sql_or_claims_success(monkeypatch, capsys):
    database = Database()

    async def upgrade(*args):
        raise RuntimeError("upgrade failed")

    monkeypatch.setattr(runner, "upgrade_alembic", upgrade)
    with pytest.raises(RuntimeError, match="upgrade failed"):
        run(database)
    assert database.executed == []
    assert "=PASS" not in capsys.readouterr().out


def test_successful_upgrade_return_cannot_replace_readback(monkeypatch, capsys):
    database = Database(["0056_klyrow_delivery_events"])

    async def upgrade(*args):
        pass  # Simulate a runner returning success against the wrong database.

    monkeypatch.setattr(runner, "upgrade_alembic", upgrade)
    with pytest.raises(runner.MigrationError, match="actual Alembic head"):
        run(database)
    assert "RUNTIME_MIGRATION=PASS" not in capsys.readouterr().out


@pytest.mark.parametrize("corruption", ["head", "core", "automation", "platform"])
def test_incomplete_database_cannot_pass_verify_only(corruption, capsys):
    database = Database([HEAD])
    if corruption == "head":
        database.revisions = None
    elif corruption == "core":
        database.receipts["core"].pop()
    elif corruption == "automation":
        database.tables.remove(runner.RECEIPT_TABLES["automation-v2"])
    else:
        database.tables.remove("public.platform_services")
    with pytest.raises(runner.MigrationError):
        run(database, verify_only=True)
    assert database.executed == []
    assert "=PASS" not in capsys.readouterr().out


def test_verify_only_never_invokes_upgrade_or_ddl(monkeypatch, capsys):
    database = Database([HEAD])

    async def forbidden(*args):
        pytest.fail("verify-only must not upgrade")

    monkeypatch.setattr(runner, "upgrade_alembic", forbidden)
    run(database, verify_only=True)
    assert database.executed == []
    output = capsys.readouterr().out
    assert "RUNTIME_SCHEMA_VERIFIED=PASS" in output
    assert "RUNTIME_MIGRATION=PASS" not in output
    assert database.structural_checks == 1


def test_concurrent_runner_cannot_apply(monkeypatch):
    database = Database(lock=False)

    async def forbidden(*args):
        pytest.fail("lock contention must stop execution")

    monkeypatch.setattr(runner, "upgrade_alembic", forbidden)
    with pytest.raises(runner.MigrationError, match="in progress"):
        run(database)
    assert database.executed == []


def test_controller_independently_checks_all_schema_authorities_before_canary():
    source = (ROOT / "deploy/production/server/codestra-middleware-deploy").read_text()
    migration = source.index('STAGE="migration"')
    start = source.index('STAGE="canary_start"')
    for item in (
        "FROM public.alembic_version",
        "actual_alembic_head_mismatch",
        "FROM public.middleware_automation_schema_migrations",
        "platform_schema_incomplete",
    ):
        assert migration < source.index(item) < start
    assert "tablename LIKE 'platform_%'" in source


def test_distroless_image_carries_authority_helper_and_sql_source_exceptions():
    dockerfile = (ROOT / "Dockerfile.runtime").read_text()
    assert (
        "scripts/production_migration_authority.py ./scripts/production_migration_authority.py"
        in dockerfile
    )
    lines = (ROOT / ".dockerignore").read_text().splitlines()
    excluded = lines.index("*.sql")
    for include in (
        "!migrations/[0-9][0-9][0-9][0-9]_*.sql",
        "!migrations/automation/[0-9][0-9][0-9][0-9]_*.sql",
    ):
        assert lines.index(include) > excluded
    assert "*.dump" in lines and "*.sql.gz" in lines


@pytest.mark.parametrize(
    "parameter", ["host", "dbname", "database", "port", "user", "server_settings"]
)
def test_query_cannot_override_verified_database_identity(parameter):
    with pytest.raises(runner.MigrationError, match="override"):
        runner.database_urls(
            "postgresql://u@localhost/approved?" + parameter + "=other"
        )


def test_test_image_preserves_the_complete_dockerignore_policy():
    dockerfile = (ROOT / "Dockerfile.runtime").read_text()
    block = dockerfile.split("RUN printf '%s\\n' ", 1)[1].split(
        "      > .dockerignore", 1
    )[0]
    # This copy is inspected from inside the test image as well as from source.
    reconstructed = [
        line.strip().split("'", 2)[1] for line in block.splitlines() if "'" in line
    ]
    assert reconstructed == (ROOT / ".dockerignore").read_text().splitlines()


@pytest.mark.parametrize("verify_only", [False, True])
def test_structural_failure_never_reports_schema_success(
    monkeypatch, capsys, verify_only
):
    from scripts.runtime_sql_schema import SchemaDriftError

    database = Database([HEAD])
    database.structural_error = True

    async def upgrade(*args):
        pass

    monkeypatch.setattr(runner, "upgrade_alembic", upgrade)
    with pytest.raises(SchemaDriftError, match="damaged"):
        run(database, verify_only=verify_only)
    assert database.structural_checks == 1
    assert "=PASS" not in capsys.readouterr().out
    if verify_only:
        assert database.executed == []
