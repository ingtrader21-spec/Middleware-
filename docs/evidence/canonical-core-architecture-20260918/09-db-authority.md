# 09 — Database authority

| Authority | Owns | Verified by |
| --- | --- | --- |
| Alembic (`migrations/versions`, head `0066_reconcile_odoo_campaign_scope`, 80 revisions) | the ORM schema used by the integration routers (`app/db/models`) | `scripts/production_migration_authority.py` (history digest pinned in `config/middleware-forward-release-authority.v1.json` and `config/runtime-sql-schema.v1.json`); CI `alembic upgrade head` / downgrade / re-upgrade / restore round-trip |
| Runtime SQL migrations (`scripts/migrate_runtime.py`) | `middleware_schema_migrations` (inbox/outbox/ledger, `RUNTIME_SCHEMA_VERSION`) and `middleware_automation_schema_migrations` (`AUTOMATION_SCHEMA_VERSION`) | `PostgresInboxStore.verify_schema()`, `PostgresCommandStore.ready()`, `PostgresAutomationStore.ready()` at container build; CI `python -m scripts.migrate_runtime --verify-only` |
| `Settings.schema_head` | the canonical Alembic head every process expects (`SCHEMA_HEAD`, pinned to `CANONICAL_SCHEMA_HEAD`) | `validate_domain()` refuses any other value |

New in Mission 2: the container's readiness includes **`alembic_head`** — the shared pool reads
`alembic_version.version_num`; equal to `Settings.schema_head` → `ready`; different → `not_ready` (the
process refuses readiness and startup); table absent → `not_configured` (a runtime-SQL-only database, e.g. a
canary that never ran Alembic). This turns the Mission-1 "stamping" defect class (a process serving against a
database at another head) into a readiness failure.

Engine ownership: `app/db/session.py` remains the only `create_async_engine` site for the application
(`tests/test_architecture_governance.py::test_sqlalchemy_engine_is_created_only_by_the_session_module`; the
migration runner and a benchmark script use their own `NullPool` engines by design); `RuntimeContainer.close()`
disposes it. Pools: `test_asyncpg_pools_are_opened_only_by_owners`.

No migration was added or changed by Mission 2; the migration history digest is unchanged from the base.

Tests: `tests/test_core_runtime_container.py::test_alembic_head_is_reported_from_the_shared_pool`,
`tests/test_runtime_sql_history_lock.py`, `tests/test_migration_authority*.py` (unchanged).
