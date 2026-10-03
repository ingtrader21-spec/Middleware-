# 06 — Tests and governance

## 1. How tests reach Postgres

- **Unit tests.** `tests/conftest.py:43-70` runs them in memory (`APP_ENV=test`,
  `ALLOW_IN_MEMORY_STORAGE=true`).
- **Integration tests.** `tests/integration/conftest.py:18-56` is a no-op unless
  `RUNTIME_INTEGRATION_TESTS=1`. When enabled, it requires:
  - `RUNTIME_INTEGRATION_ALLOW_DISPOSABLE=YES`
  - `DATABASE_URL` on localhost, database `^middleware_test_[A-Za-z0-9_]+$`, **no query string**. This
    means no integration run ever uses `sslmode`.
  - `REDIS_URL` on localhost with a numeric DB other than 0
  - `scripts/integration_ci.sh:7-63` mirrors these checks.
- **Other DSN env vars used by tests.** `TEST_DATABASE_URL`, `CALLING_TEST_DATABASE_URL`,
  `CAMPAIGN_DESIGN_TEST_DATABASE_URL` and `MONITORING_TEST_DATABASE_URL`, each as a skip condition.
  CI sets
  `TEST_DATABASE_URL=postgresql+asyncpg://middleware_ci:…@127.0.0.1:5432/middleware_rehearsal`
  (`required-ci.yml:129,207`).

## 2. Existing DB tests

| Test | Asserts |
| --- | --- |
| `tests/test_db_session_tls.py` | Engine E receives the native DSN (with `sslmode` and `sslrootcert`) via `connect_args.dsn`, with `command_timeout` 30 |
| `tests/test_runtime_migration_tls.py` | `migrate_runtime` keeps every `sslmode` in the native DSN and never puts credentials in the engine URL; `host=` override is rejected |
| `tests/test_runtime.py:502-509` | `_asyncpg_dsn` strips `+asyncpg` |
| `tests/test_runtime_migration_certification.py` (unit) and `tests/integration/test_runtime_migration_certification.py` | One target across schemes; query-override rejection; fresh and `0056` upgrade; idempotence; advisory lock; corruption matrix never prints `=PASS` |
| `tests/test_runtime_sql_schema.py` | Read-only `REPEATABLE READ` verifier; drift detection; contract loaded before `asyncpg.connect` |
| `tests/test_internal_database_api.py` | PAS-102 routes, scopes, no raw-SQL routes, no secret leakage |
| `tests/test_security.py:163-167,338-342,405-418` | `verify-full` staging/production fixtures; cross-profile DSN rejected (built with `Settings.from_env`, so the F-01 rewrite path is never exercised) |
| `tests/test_architecture_governance.py:268-291` | `asyncpg.create_pool(` only in named owners; `create_async_engine(` only in `app/db/session.py`, `scripts/migrate_runtime.py`, `scripts/benchmark_ai_orchestration.py`. Scans `app`, `workers` and `scripts` by regex |

Gaps closed by nothing in main today:
- no test on `application_name`
- no 401/403 tests on the DB API
- no test on `migrations/env.py`
- governance does not scan `websocket_gateway`, `migrations` or `services`, and does not match
  `asyncpg.connect(` or sync `create_engine(`

## 3. Related open work

PR #304 (`mission/db-connection-tls-authority-20260921-v2`, unmerged) adds
`app/db/connection.py::build_database_connection_authority(application_name=…)`, which enforces
`verify-full` in staging and production, and `tests/test_database_connection_authority.py`. Per
`docs/evidence/pas27-schema-0067-rc-20260921/07-known-gaps-pas13-handoff.md`, it must be rebased and
re-derived first. It is the natural owner of F-02, F-07 and F-08. This mission does not duplicate it.

## 4. PAS-78 ratchet: `tests/test_db_access_path_map.py`

| Test | Purpose |
| --- | --- |
| `test_every_connection_site_is_mapped` | Uses AST to find every `asyncpg.create_pool/connect`, `create_async_engine`, `async_engine_from_config`, `engine_from_config`, `create_engine`, `sqlite3/psycopg.connect` call in `app`, `workers`, `worker`, `scripts`, `websocket_gateway`, `migrations` and `services/connector-runtime/{src,migrations}`. The set must equal the JSON map in both directions |
| `test_connection_site_ids_are_unique_and_complete` | Every entry records file, call, components, DSN source, transform, TLS and status |
| `test_shell_paths_still_use_their_tool` | Backup, readback and exporter files still exist and still use their tool |
| `test_application_name_is_set_only_where_mapped` | `application_name` appears only in the mapped connector-runtime file |
| `test_duplicate_dsn_normalizers_agree` | `_asyncpg_dsn` and `_native_asyncpg_dsn` are equivalent (F-08) |
| `test_locked_profiles_admit_only_sslmode_in_the_dsn_query` | Pins F-02 |
| `test_profile_tls_policy_is_as_mapped` | Pins F-03 |
| `test_process_settings_rewrite_is_present` + `test_process_normalized_dsn_passes_its_locked_profile` (strict xfail, `raises=ConfigurationError`) | Pins F-01. When F-01 is fixed, the xfail flips to XPASS and the map must be updated |
| `test_every_finding_is_documented` | Every finding ID in the JSON has a section in 07 |
