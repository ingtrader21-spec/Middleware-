# 03 — Roles, schema ownership and migration authority

## 1. Login roles, meaning the roles the DSNs connect as

| Context | Role / database | Source |
| --- | --- | --- |
| Staging (k8s) | `middleware_staging` / `codestra_staging` | `config/runtime-profiles.v1.json:11-13` |
| Production (k8s) | `middleware_production` / `codestra_production` | `:43-45` |
| Production compose (canary) | `appolon_middleware_api` / `codestra_middleware_appolon` | `:75-77`, `deploy/production/server/deploy.conf.example:12` |
| CI | `middleware_ci` / `middleware_rehearsal` | `.github/workflows/required-ci.yml:129,206-207` |
| Realtime gateway | `codestra_realtime` | `deploy/websocket-ha/compose.standby.yaml:25` |
| postgres-exporter | `codestra_monitoring` | `deploy/monitoring/odoo-readiness/compose.yaml:6` |
| Deploy readback / backup | OS user `postgres` via `docker exec -u postgres` (peer auth) | `deploy/production/server/codestra-middleware-{deploy,backup}` |
| Connector runtime tests | `connector_app_test` (the only `CREATE ROLE` in the repo) | `services/connector-runtime/scripts/test_postgres.sh:50-63` |

## 2. Grant roles, the roles the migrations grant to

The migrations never `CREATE ROLE`, `ALTER … OWNER` or `SET ROLE`. Every `GRANT` is wrapped in
`IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=…)`, so it is a **silent no-op** when the role is missing:

| Role | Revision |
| --- | --- |
| `middleware_app` | `0020_campaign_registry_runtime_grants.py:15,36` |
| `mw_integration_api` | `0047_breero_runtime_grants.py:14,29`, `0048_agent_call_realtime.py:61-63`, `0051_callback_management.py:54-57`, `0052_callback_rls_hardening.py:61` |
| `mw_scheduler`, `mw_notification_worker` | `0053_callback_worker_grants.py:17,22,33` |

None of these is a login role in any profile, compose file or env example (F-05).

## 3. Schema ownership

- `public` holds all Middleware tables, including `alembic_version`, `middleware_schema_migrations` and
  `middleware_automation_schema_migrations`.
- `reporting` is created by `0004_automation_reporting.py:28`.
- `connector_sdk` is created by the connector runtime, with `SECURITY DEFINER` functions pinned to
  `search_path = pg_catalog, connector_sdk`.
- No schema or table has an explicit owner, so the owner is whichever role ran the migration. In
  production compose and the realtime gateway, that is the runtime role itself (F-04), which contradicts
  `docs/IMMUTABLE-EVENT-LEDGER.md:14-16`: "The application role should not own these tables and must not
  receive trigger or DDL privileges in production".

## 4. Migration authority

| Authority | Owns | Guard |
| --- | --- | --- |
| Alembic (`migrations/versions`, 81 revisions, single head `0067_service_catalog_monitoring_state`) | ORM schema (`app/db/models`, `app/monitoring/store`) | Offline: `scripts/production_migration_authority.py` (single head = `requiredSchemaHead`, history digest pinned in `config/middleware-forward-release-authority.v1.json:15,87`). Runtime: readiness `alembic_head` = `Settings.schema_head` |
| Runtime SQL `migrations/0001…0011_*.sql` | `middleware_schema_migrations` | `scripts/migrate_runtime.py`; `PostgresInboxStore.verify_schema()` |
| Automation SQL `migrations/automation/0001_automation_v2.sql` | `middleware_automation_schema_migrations` | same runner; `PostgresAutomationStore.ready()` |
| Runtime SQL contract `config/runtime-sql-schema.v1.json` | the table/column/index/trigger/RLS signature (owners are excluded, `scripts/runtime_sql_schema.py:27`) | read-only `REPEATABLE READ` transaction with `SET LOCAL search_path = pg_catalog` (`:218-219`) |
| Realtime gateway `websocket_gateway/migrations/0001_*` | `websocket_schema_migrations` in `codestra_realtime` | `websocket_gateway/migrate.py`, with a head check only |
| Connector runtime Alembic (`services/connector-runtime/migrations`) | `connector_sdk`, **default `alembic_version` table in the search_path** | none; `scripts/migration_lineage.py` + `config/migration-lineage.v1.json` read this lineage (F-15) |

### Runners

| Runner | DSN | Writes | Guards |
| --- | --- | --- | --- |
| `scripts/migrate_runtime.py` | `DATABASE_URL` only (`:177`) | `alembic upgrade <expected>` on a NullPool engine (`:85-120`), then runtime and automation SQL (`:150-155`) | Release authority and history hash checked before connecting (`:172-176`); `pg_try_advisory_lock(742603070118)` (`:20,147`); refuses unknown or redundant revisions (`:59-82`); `--verify-only`; **no environment/TLS requirement** |
| `alembic` CLI via `migrations/env.py` | `settings.database_url` (rewritten to `+asyncpg`, `:10-14`), or a supplied connection | Alembic DDL, `version_table_schema="public"` | none of its own |
| `scripts/reconcile_legacy_staging_database.py` | `DATABASE_URL_FILE` else `DATABASE_URL`, rewritten to `postgresql+psycopg` | Repairs legacy `alembic_version` (0058 → 0056), deletes provider-route rows, upgrades to 0067 in one transaction (`:244-297`) | `--execute`; git SHA checks; `current_database() == 'middleware_staging'` (`:208`); `pg_advisory_xact_lock` (`:245`) |
| `websocket_gateway/migrate.py` | `DATABASE_URL_FILE` | realtime SQL | head check |
| `scripts/migration_lineage.py` | `--database-url-env` | nothing (read only) | connector lineage only |
| `scripts/collect_staging_migration_evidence.sh` | none (`DATABASE_QUERIES=NO`, `:260`) | output directory | default target `0053_callback_worker_grants` (`:12`, stale) |

Who runs `migrate_runtime.py`:
- **Production deploy:** `codestra-middleware-deploy:498-504` runs `middleware-migrate-canary` **without
  `--verify-only`**, after the pre-migration backup (`:484-490`). The service is labelled
  `com.codestra.deployment.mode: read-only-canary` (`compose.canary.yaml:83`, F-06). The script then
  reads back receipts `1..10` (`:510`; main ships `0011`, already recorded as PAS-27 F-07) and
  `alembic_version`.
- **CI:** `required-ci.yml:218-240`.
