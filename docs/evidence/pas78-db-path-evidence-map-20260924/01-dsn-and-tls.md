# 01 — DSN sources, parsing and TLS semantics

## 1. Canonical settings (`app/core/config.py`)

| Setting (env var) | Default | Line | Consumer |
| --- | --- | --- | --- |
| `DATABASE_URL` | `postgresql+asyncpg://localhost/codestra_middleware` | 378 | pool P, engine E, Alembic env |
| `DATABASE_URL_FILE` | `""` | 379; loaded by `load_secret_files()` 1789-1809 (absolute path, non-empty, stripped) | overrides `database_url` |
| `DATABASE_POOL_SIZE` / `_MAX_OVERFLOW` / `_POOL_TIMEOUT_SECONDS` / `_COMMAND_TIMEOUT_SECONDS` / `_POOL_RECYCLE_SECONDS` | 8 / 4 / 5 / 30 / 1800 | 402-406 | **engine E only** |
| `HEALTH_REQUIRE_DATABASE` | False | 407 | narrow-service health |
| `DATABASE_CERTIFICATION_EVIDENCE_DIR` | `""` | 380 | private DB API backup/restore evidence |
| `SCHEMA_HEAD` | `CANONICAL_SCHEMA_HEAD` = `0067_service_catalog_monitoring_state` | 29, 264; enforced 1270 | readiness `alembic_head`, DB API |
| `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `application_name` | **no fields** | — | only expressible inside the DSN query |

Parse order for the process-wide `settings` object (`config.py:2280-2286`):
1. `Settings()`
2. `load_secret_files()`
3. **`postgresql://` → `postgresql+asyncpg://`**
4. `validate_safety()`

`Settings.from_env()` (`:895-921`) does **not** apply step 3. Scripts and workers that use `from_env()`
therefore see a different scheme than the API process (see F-01, F-08).

Normalizers that strip `+asyncpg` for asyncpg:
- `app/core/runtime.py:102` `_asyncpg_dsn`
- `app/db/session.py:28` `_native_asyncpg_dsn`, with identical bodies (`app/runtime.py:12-18` re-exports the first)
- `scripts/migrate_runtime.py` `database_urls()`, which also rejects target-override query keys (`host`,
  `user`, `dbname`, `port`, `server_settings`, …; `:35-46`)

The store `connect()` classmethods, `run_temporal`, the realtime gateway and the scripts do no
normalization. asyncpg rejects `postgresql+asyncpg://` with `ClientConfigurationError: invalid DSN`
(verified locally with asyncpg from `requirements-test.txt`).

## 2. Locked runtime profiles (`config/runtime-profiles.v1.json`)

`Settings._validate_database_profile` (`config.py:1537-1559`) runs from `validate_domain()` (`:1228` →
`:1449-1464`) whenever `APP_ENV` is `staging` or `production`. It requires:
- the scheme, host, port, database and username to equal the profile;
- a password to be present;
- the query to equal **exactly** `{"sslmode": [profile.sslmode]}`, or be empty when the profile's
  `sslmode` is null;
- no params and no fragment.

| Profile | Host / DB / role | sslmode |
| --- | --- | --- |
| `codestra-middleware-staging-v1` | `postgresql.middleware-staging.svc.cluster.local:5432` / `codestra_staging` / `middleware_staging` | `verify-full` |
| `codestra-middleware-production-v1` | `postgresql.middleware-production.svc.cluster.local:5432` / `codestra_production` / `middleware_production` | `verify-full` |
| `codestra-middleware-production-compose-v1` | `codestra-postgres-1:5432` / `codestra_middleware_appolon` / `appolon_middleware_api` | **null (no TLS)** |

Consequences:
- **F-02:** no `sslrootcert`, `sslcert` or `sslkey` can be carried in the DSN.
- **F-03:** the compose profile forbids TLS parameters.
- **F-01:** the profile's scheme `postgresql` never matches the process settings, which were already rewritten
  to `postgresql+asyncpg`.

## 3. TLS, certificate and secret paths

| Item | Evidence |
| --- | --- |
| TLS is enabled only by the `sslmode` value in the DSN query. No `ssl=` argument, `SSLContext` or `PGSSL*` env appears anywhere | `git grep -n "PGSSL\|ssl=\|SSLContext"` over `app workers worker websocket_gateway services`: no DB hits |
| `verify-full` env examples | `config/environments/staging.runtime.env.example:4`, `production.runtime.env.example:4`, `staging.intake-observability.runtime.env.example:17`, `deploy/observability-alerts/production.env.example:18` |
| Explicit plaintext | `config/runtime-profiles.v1.json:77` (compose profile); `deploy/monitoring/odoo-readiness/compose.yaml:5` (`sslmode=disable`, exporter) |
| `sslrootcert` / `sslcert` / `sslkey` | Only in tests: `tests/test_db_session_tls.py:29,37`, `tests/test_runtime_migration_tls.py:17-18`, `tests/test_internal_database_api.py:124` |
| CA material for Postgres | **No manifest mounts a Postgres CA**, and nothing sets `PGSSLROOTCERT` |
| DSN secret files | `/run/secrets/database_url`, a per-service secret `/etc/codestra/secrets/middleware-runtime/*-database-url` (`deploy/compose.runtime.yaml:158-538`); `deploy/external-webhook/compose.production.yaml:30,47`; `deploy/compose.telephony-command-worker.yaml.example:17`; `BEYVRA_EMAIL_DATABASE_URL_FILE` (`deploy/beyvra-email`) |
| `DATABASE_URL_FILE` readers | `app/core/config.py:1792`, `websocket_gateway/{migrate.py:15,app.py:169,certify.py:30}`, `scripts/reconcile_legacy_staging_database.py:124` |
| `DATABASE_URL`-only readers (no `_FILE`) | `scripts/migrate_runtime.py:177`, `scripts/verify_event_ledger.py:19`, `scripts/migration_lineage.py:232`, `services/connector-runtime/migrations/env.py:12` |
| Profile secret prefix `/run/secrets/middleware-<env>-` | Enforced for the NATS/Temporal files only (`config.py:1516-1528`), **not** for `DATABASE_URL_FILE` (F-12) |
| `POSTGRES_PASSWORD_FILE` (realtime DB server) | `websocket_gateway/compose.yaml:9`, `deploy/websocket-ha/compose.standby.yaml:18` |
| Exporter password | `DATA_SOURCE_PASS_FILE=/run/secrets/postgres_monitoring_password` ← `/etc/codestra/secrets/monitoring/postgres_exporter_password` (`deploy/monitoring/odoo-readiness/compose.yaml:7,54`) |
