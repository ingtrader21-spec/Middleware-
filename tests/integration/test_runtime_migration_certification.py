"""Real migration tests on independently created, localhost-only disposable DBs."""

from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import unquote, urlsplit, urlunsplit
from uuid import uuid4

import pytest

from scripts import migrate_runtime as runner
from scripts.production_migration_authority import validate_authority
from scripts.runtime_sql_schema import campaign_tables, monitoring_tables

pytestmark = pytest.mark.skipif(
    os.getenv("RUNTIME_INTEGRATION_TESTS") != "1", reason="disposable PostgreSQL only"
)


@pytest.mark.parametrize("predecessor", [None, "0056_klyrow_delivery_events"])
def test_real_fresh_and_predecessor_migrations(predecessor, monkeypatch):
    import asyncpg

    async def scenario():
        # Validate again here so this test is safe even with --noconftest.
        base = os.environ["DATABASE_URL"]
        parsed = urlsplit(base)
        assert os.getenv("RUNTIME_INTEGRATION_ALLOW_DISPOSABLE") == "YES"
        assert parsed.scheme in {"postgres", "postgresql"}
        assert parsed.hostname in {"localhost", "127.0.0.1"}
        assert not parsed.query and not parsed.fragment
        assert re.fullmatch(
            r"middleware_test_[A-Za-z0-9_]+", unquote(parsed.path.lstrip("/"))
        )
        name = "middleware_test_migration_" + uuid4().hex
        url = urlunsplit((parsed.scheme, parsed.netloc, "/" + name, "", ""))
        admin = await asyncpg.connect(base)
        created = False
        try:
            await admin.execute(f'CREATE DATABASE "{name}"')
            created = True
            monkeypatch.setenv("DATABASE_URL", url)
            head, graph, _ = validate_authority(runner.ROOT)
            monkeypatch.setenv("SCHEMA_HEAD", head)
            if predecessor:
                await runner.upgrade_alembic(runner.database_urls(url)[1], predecessor)
            await runner.main()
            await runner.main()  # Re-running must be idempotent.
            await runner.main(verify_only=True)
            conn = await asyncpg.connect(url)
            try:
                assert (
                    await conn.fetchval(
                        "SELECT version_num FROM public.alembic_version"
                    )
                    == head
                )
                assert (
                    await conn.fetchval(
                        "SELECT count(*) FROM public.middleware_schema_migrations"
                    )
                    == 11
                )
                assert (
                    await conn.fetchval(
                        "SELECT count(*) FROM public.middleware_automation_schema_migrations"
                    )
                    == 1
                )
                assert (
                    await conn.fetchval("SELECT count(*) FROM public.platform_services")
                    == 0
                )
                assert (
                    await conn.fetchval(
                        "SELECT count(*) FROM public.middleware_automation_jobs"
                    )
                    == 0
                )
                # A second runner cannot race the migration session.
                await conn.fetchval(
                    "SELECT pg_advisory_lock($1)", runner.MIGRATION_LOCK
                )
                with pytest.raises(runner.MigrationError, match="in progress"):
                    await runner.main()
                await conn.fetchval(
                    "SELECT pg_advisory_unlock($1)", runner.MIGRATION_LOCK
                )
                # The correct version label is insufficient when an actual table is absent.
                await conn.execute("DROP TABLE public.platform_provisioning_audit")
                with pytest.raises(runner.MigrationError, match="catalog table"):
                    await runner.main(verify_only=True)
            finally:
                await conn.close()
        finally:
            if created:
                await admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
            await admin.close()

    asyncio.run(scenario())


SQL_CORRUPTIONS = {
    "table": "DROP TABLE public.middleware_realtime_tickets",
    "column": "ALTER TABLE public.middleware_automation_jobs DROP COLUMN safe_terminal_result",
    "column_type": "ALTER TABLE public.middleware_automation_jobs ALTER COLUMN safe_terminal_result TYPE text USING safe_terminal_result::text",
    "nullability": "ALTER TABLE public.middleware_automation_jobs ALTER COLUMN actor_context DROP NOT NULL",
    "default": "ALTER TABLE public.middleware_automation_jobs ALTER COLUMN max_attempts SET DEFAULT 9",
    "constraint": "ALTER TABLE public.middleware_automation_jobs DROP CONSTRAINT middleware_automation_jobs_workflow_version_check",
    "index": "DROP INDEX public.middleware_automation_jobs_event_idx",
    "trigger": "ALTER TABLE public.middleware_automation_audit DISABLE TRIGGER middleware_automation_audit_immutable",
    "trigger_function": "CREATE OR REPLACE FUNCTION public.middleware_reject_automation_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
    "fk_enforcement": "ALTER TABLE public.middleware_automation_dispatch_outbox DISABLE TRIGGER ALL",
    "sequence": "ALTER SEQUENCE public.middleware_outbox_id_seq INCREMENT BY 2",
    "rls": "ALTER TABLE public.middleware_automation_jobs ENABLE ROW LEVEL SECURITY",
}


# Every table introduced by campaign design must be covered by physical
# verification, including FK enforcement and the functions behind both guards.
SQL_CORRUPTIONS.update(
    {
        **{
            f"missing_{table}": f"DROP TABLE public.{table} CASCADE"
            for table in campaign_tables(runner.ROOT)
        },
        "campaign_column": "ALTER TABLE public.campaign_design_approval ALTER COLUMN reason TYPE text",
        "campaign_fk": "ALTER TABLE public.campaign_design_approval DROP CONSTRAINT fk_campaign_approval_revision",
        "campaign_index": "ALTER TABLE public.campaign_design_approval DROP CONSTRAINT campaign_design_approval_idempotency_key_key",
        "campaign_approval_trigger": "ALTER TABLE public.campaign_design_approval DISABLE TRIGGER campaign_design_approval_immutable",
        "campaign_revision_trigger": "ALTER TABLE public.campaign_design_revision DISABLE TRIGGER campaign_design_revision_immutable",
        "campaign_approval_function": "CREATE OR REPLACE FUNCTION public.reject_campaign_approval_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
        "campaign_revision_function": "CREATE OR REPLACE FUNCTION public.enforce_campaign_design_revision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$",
    }
)

SQL_CORRUPTIONS.update(
    {
        **{
            f"missing_{table}": f"DROP TABLE public.{table}"
            for table in monitoring_tables(runner.ROOT)
        },
        "monitoring_replay_unique": "ALTER TABLE public.monitoring_operations DROP CONSTRAINT uq_monitoring_operation_replay",
        "monitoring_scope_index": "DROP INDEX public.ix_monitoring_resource_scope",
        "monitoring_tenant_nullability": "ALTER TABLE public.monitoring_events ALTER COLUMN tenant DROP NOT NULL",
    }
)


@pytest.mark.parametrize("corruption", sorted(SQL_CORRUPTIONS))
def test_actual_sql_structure_cannot_be_certified_from_intact_receipts(
    corruption, monkeypatch, capsys
):
    import asyncpg
    from scripts.runtime_sql_schema import SchemaDriftError

    async def scenario():
        base = os.environ["DATABASE_URL"]
        parsed = urlsplit(base)
        assert os.getenv("RUNTIME_INTEGRATION_ALLOW_DISPOSABLE") == "YES"
        assert parsed.scheme in {"postgres", "postgresql"}
        assert parsed.hostname in {"localhost", "127.0.0.1"}
        assert not parsed.query and not parsed.fragment
        assert re.fullmatch(
            r"middleware_test_[A-Za-z0-9_]+", unquote(parsed.path.lstrip("/"))
        )
        name = "middleware_test_schema_" + uuid4().hex
        url = urlunsplit((parsed.scheme, parsed.netloc, "/" + name, "", ""))
        admin = await asyncpg.connect(base)
        created = False
        try:
            await admin.execute(f'CREATE DATABASE "{name}"')
            created = True
            monkeypatch.setenv("DATABASE_URL", url)
            head, _, _ = validate_authority(runner.ROOT)
            monkeypatch.setenv("SCHEMA_HEAD", head)
            await runner.main()
            conn = await asyncpg.connect(url)
            try:
                # Sequence *values* are data, not structural drift.
                await conn.fetchval("SELECT nextval('public.middleware_outbox_id_seq')")
                await runner.main(verify_only=True)
                receipts_before = await conn.fetch(
                    "SELECT * FROM public.middleware_automation_schema_migrations"
                )
                await conn.execute(SQL_CORRUPTIONS[corruption])
                assert (
                    await conn.fetchval(
                        "SELECT version_num FROM public.alembic_version"
                    )
                    == head
                )
                assert (
                    await conn.fetchval(
                        "SELECT count(*) FROM public.middleware_schema_migrations"
                    )
                    == 11
                )
                assert (
                    await conn.fetch(
                        "SELECT * FROM public.middleware_automation_schema_migrations"
                    )
                    == receipts_before
                )
                capsys.readouterr()
                with pytest.raises(SchemaDriftError):
                    await runner.main(verify_only=True)
                assert "=PASS" not in capsys.readouterr().out
                if corruption == "column":
                    # IF NOT EXISTS does not restore this dropped, unindexed
                    # column. A normal rerun must reject the damage too.
                    with pytest.raises(SchemaDriftError, match="structure mismatch"):
                        await runner.main()
                    assert "=PASS" not in capsys.readouterr().out
                    assert (
                        await conn.fetchval(
                            "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' "
                            "AND table_name='middleware_automation_jobs' AND column_name='safe_terminal_result'"
                        )
                        == 0
                    )
            finally:
                await conn.close()
        finally:
            if created:
                await admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
            await admin.close()

    asyncio.run(scenario())


def test_real_campaign_approval_is_hash_bound_and_append_only(monkeypatch):
    import asyncpg

    async def scenario():
        base = os.environ["DATABASE_URL"]
        parsed = urlsplit(base)
        assert os.getenv("RUNTIME_INTEGRATION_ALLOW_DISPOSABLE") == "YES"
        assert parsed.scheme in {"postgres", "postgresql"}
        assert parsed.hostname in {"localhost", "127.0.0.1"}
        assert not parsed.query and not parsed.fragment
        assert re.fullmatch(
            r"middleware_test_[A-Za-z0-9_]+", unquote(parsed.path.lstrip("/"))
        )
        name = "middleware_test_campaign_" + uuid4().hex
        url = urlunsplit((parsed.scheme, parsed.netloc, "/" + name, "", ""))
        admin = await asyncpg.connect(base)
        created = False
        try:
            await admin.execute(f'CREATE DATABASE "{name}"')
            created = True
            monkeypatch.setenv("DATABASE_URL", url)
            head, _, _ = validate_authority(runner.ROOT)
            monkeypatch.setenv("SCHEMA_HEAD", head)
            await runner.main()
            conn = await asyncpg.connect(url)
            try:
                integration = str(uuid4())
                await conn.execute(
                    "INSERT INTO campaign_design_revision "
                    "(integration_uuid,revision,payload_hash,manifest_hash,manifest,approval_state) "
                    "VALUES ($1,1,$2,$3,'{}'::jsonb,'preview')",
                    integration,
                    "a" * 64,
                    "b" * 64,
                )
                insert = (
                    "INSERT INTO campaign_design_approval "
                    "(approval_id,integration_uuid,design_revision,manifest_hash,approver_subject,"
                    "reason,idempotency_key,correlation_id) VALUES ($1,$2,1,$3,$4,$5,$6,$7)"
                )
                approval = str(uuid4())
                args = [
                    approval,
                    integration,
                    "b" * 64,
                    "synthetic-reviewer",
                    "Synthetic approved design",
                    str(uuid4()),
                    str(uuid4()),
                ]
                wrong = list(args)
                wrong[2] = "c" * 64
                with pytest.raises(asyncpg.ForeignKeyViolationError):
                    await conn.execute(insert, *wrong)
                await conn.execute(insert, *args)
                before = await conn.fetchrow(
                    "SELECT * FROM campaign_design_approval WHERE approval_id=$1",
                    approval,
                )
                for statement in (
                    "UPDATE campaign_design_approval SET reason='rewritten'",
                    "DELETE FROM campaign_design_approval",
                    "TRUNCATE campaign_design_approval",
                ):
                    with pytest.raises(asyncpg.RaiseError, match="append-only"):
                        await conn.execute(statement)
                    assert (
                        await conn.fetchrow(
                            "SELECT * FROM campaign_design_approval WHERE approval_id=$1",
                            approval,
                        )
                        == before
                    )
                await conn.execute(
                    "UPDATE campaign_design_revision SET approval_state='approved' WHERE integration_uuid=$1",
                    integration,
                )
                assert (
                    await conn.fetchval(
                        "SELECT approval_state FROM campaign_design_revision WHERE integration_uuid=$1",
                        integration,
                    )
                    == "approved"
                )
                await runner.main(verify_only=True)
            finally:
                await conn.close()
        finally:
            if created:
                await admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
            await admin.close()

    asyncio.run(scenario())
