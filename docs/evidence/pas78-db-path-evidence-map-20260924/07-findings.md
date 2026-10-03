# 07 — Findings

This mission records these findings; it fixes none of them. Severity reflects impact if the path is
exercised. "Verified" means reproduced locally or read directly from the code at `0606b0d`. Nothing
here was observed on a live host.

| ID | Severity | Owner lane |
| --- | --- | --- |
| F-01 | High | DB/TLS authority (PR #304 lane) |
| F-02 | High | DB/TLS authority (PR #304 lane) |
| F-03 | High | Production compose / security owner |
| F-04 | High | DB role provisioning / release owner |
| F-05 | Medium | DB role provisioning |
| F-06 | Medium | Release/deploy owner |
| F-07 | Medium | DB/TLS authority (PR #304 lane) |
| F-08 | Medium | Runtime container owner |
| F-09 | Low | Runtime container owner |
| F-10 | Low | Governance (closed at mapping level by this mission) |
| F-11 | Medium | PAS-102 owner |
| F-12 | Low | Config authority |
| F-13 | Medium | Backup/DR owner |
| F-14 | Low | Monitoring owner |
| F-15 | Low | Connector runtime owner |
| F-16 | Low | Deploy/runtime owner, plus stale docs |

## F-01 — Process settings DSN cannot pass its own locked profile

`app/core/config.py:2282-2285` rewrites the process-wide `settings.database_url` from `postgresql://` to
`postgresql+asyncpg://`. Both `create_app` (`application.py:102` → `bootstrap.py:158`) and `run_api` /
`run_worker` (`entrypoints/runtime.py:86`) then call `validate_domain()` on those same settings. In
staging and production that runs `_validate_database_profile`, which requires
`parsed.scheme == "postgresql"` (`:1546`).

The result is a DSN that can never pass:
- A profile-conformant DSN is rewritten to `+asyncpg` and fails.
- A DSN supplied as `+asyncpg` fails as well.

**Verified:** `_validate_database_profile` rejects the rewritten staging DSN with "DATABASE_URL does not
match the locked runtime profile". It is pinned by
`tests/test_db_access_path_map.py::test_process_normalized_dsn_passes_its_locked_profile` (strict xfail).

Existing tests miss it because they build `Settings.from_env()`, which skips the rewrite. Any
profile-bound process, including the production compose canary with `RUNTIME_PROFILE_ID`, should fail
closed at startup. Live confirmation is still required.

## F-02 — `verify-full` has no CA supply path

The locked staging and production profiles admit only `?sslmode=verify-full`. `sslrootcert`, `sslcert`
and `sslkey` in the DSN are rejected (`config.py:1552-1553`, pinned by
`test_locked_profiles_admit_only_sslmode_in_the_dsn_query`).

The other ways to supply a CA are also missing:
- No code sets `ssl=` or reads `PGSSLROOTCERT`.
- No manifest mounts a Postgres CA.

`verify-full` therefore depends on `~/.postgresql/root.crt` for the container user (10001 or 65532), or
on driver defaults.

Two surfaces assume otherwise:
- `tests/test_db_session_tls.py` uses a DSN with `sslrootcert`, which the profile would reject.
- The DB API's `client_certificate_configured` is always false under a profile.

## F-03 — Plaintext paths in production

- **Production-compose profile:** it locks `sslmode` to null (`runtime-profiles.v1.json:77`), so
  API↔Postgres traffic to `codestra-postgres-1` is unencrypted. This is pinned by
  `test_profile_tls_policy_is_as_mapped`.
- **postgres-exporter:** it uses `sslmode=disable` (`deploy/monitoring/odoo-readiness/compose.yaml:5`).
- **`migrate_runtime.py`:** it does not require any `sslmode`.

## F-04 — Migrator and runtime share one role

Two deployments run the migrator and the application under one DSN:
- **Production compose:** `middleware-migrate-canary` and `middleware-api-canary` share one `env_file`
  (`compose.canary.yaml:5-6`).
- **Realtime gateway:** migrate and app mount the same `database_url` secret
  (`deploy/websocket-ha/compose.standby.yaml:37,47`).

No migration changes ownership, so the runtime role owns the tables and holds DDL rights. That
contradicts `docs/IMMUTABLE-EVENT-LEDGER.md:14-16`. It also weakens the append-only triggers and
`FORCE ROW LEVEL SECURITY` (`0052_callback_rls_hardening.py:34`), because a table owner can disable
triggers.

## F-05 — Grant roles are not login roles

The grants in `0020`, `0047`, `0048`, `0051`, `0052` and `0053` target `middleware_app`,
`mw_integration_api`, `mw_scheduler` and `mw_notification_worker`. Each is guarded by `IF EXISTS … pg_roles`.

The profiles log in as different roles: `middleware_staging`, `middleware_production` and
`appolon_middleware_api`. The repo creates none of the `mw_*` roles, so the least-privilege grants are
silent no-ops unless someone provisions those roles out of band and uses them to log in.

## F-06 — The "read-only canary" applies DDL

`compose.canary.yaml:83` labels `middleware-migrate-canary` `read-only-canary`. The deploy script runs it
without `--verify-only` (`codestra-middleware-deploy:498-504`), so it applies Alembic and SQL DDL.

A pre-migration backup precedes it, so the gap is the label, not the safety net. The receipt readback
also expects `1..10` while main ships `0011`; that was recorded earlier as PAS-27 F-07.

## F-07 — `application_name` is absent from every Middleware path

Pools P, E, the store `connect()` pools, the realtime gateway and all scripts leave it unset. Only the
connector runtime sets it (`api/database.py:32`). As a result, `pg_stat_activity`, `pg_locks` and the
DB API `/capacity` and `/locks` endpoints cannot attribute sessions to a service. This is pinned by
`test_application_name_is_set_only_where_mapped`.

## F-08 — Duplicate and divergent DSN normalization

- **Two identical helpers:** `_asyncpg_dsn` (`core/runtime.py:102`) and `_native_asyncpg_dsn`
  (`db/session.py:28`). This mission pins their equivalence.
- **A third helper:** `migrate_runtime.database_urls()`, which also rejects override keys.
- **No normalization at all:** the five store `connect()` classmethods, `run_temporal` and the scripts.
  asyncpg rejects `postgresql+asyncpg://` (verified).
- **`workers/run_temporal.py:199-207`:** it opens its own pool from `Settings.from_env().database_url`,
  bypassing RuntimeContainer. It fails whenever the DSN is given in `+asyncpg` form, which is the
  `Settings` default and the CI `TEST_DATABASE_URL` form. Its `is None` guard (`:204`) can never
  trigger.

## F-09 — Pool and timeout divergence

- **Pool P:** hard-coded to 1–20 connections with a 10 s command timeout. It ignores the `DATABASE_*`
  settings and has no recycle.
- **Engine E:** 8 + 4 connections with a 30 s timeout.
- **Store `connect()` pools:** 10 s, or no timeout at all for communications and realtime.
- **Realtime gateway:** 5 s.
- **No `statement_timeout` or `lock_timeout` is set anywhere.**

Each container process can hold up to 32 connections, and the reconciler actively uses both handles.
Across the 20+ compose services, that should be checked against `max_connections`.

## F-10 — Governance scan blind spots

`tests/test_architecture_governance.py` scans only `app`, `workers` and `scripts`, using regexes for
`asyncpg.create_pool(` and `create_async_engine(`. That misses:
- `websocket_gateway/*`
- `migrations/env.py`
- `services/connector-runtime/*`
- `asyncpg.connect(`
- sync `create_engine(`

This mission's AST ratchet (`test_every_connection_site_is_mapped`) closes the gap at the mapping level.
New paths now fail CI until they are mapped, but ownership allowlists remain the governance test's job.

## F-11 — Private DB API contract drift

- **Mounting:** the docstring says "integration profile only", but the router is in `CANONICAL_ROUTERS`
  and mounts on all profiles.
- **Scopes:** `ADMIN_SCOPE` is unused, and `route-authority-report.v1.json` records `scope: null` for
  all 16 routes.
- **Postman:** `scripts/generate_postman.py --check` is not wired into CI.
- **Tests:** there are no 401/403 tests.
- **Stale docs:** `API-INVENTORY.md` and `docs/API-COMPLETION-MATRIX.md` omit the database domain.
- **Certification:** the Postman certification manifest is still `UNVERIFIED`.

## F-12 — `DATABASE_URL_FILE` is not bound to the profile secret prefix

The profile's `/run/secrets/middleware-<env>-` prefix is enforced for the NATS and Temporal secret files
(`config.py:1516-1528`), but not for the database secret file.

## F-13 — Backup gaps

- Backups are logical dumps only: no WAL archiving or PITR.
- The scheduled off-server backup dumps `codestra_middleware` (`scraper-middleware-offserver.sh:31`),
  while the production compose database is `codestra_middleware_appolon` (`deploy.conf.example:12`). If
  both describe the same host, the scheduled job backs up the wrong database.
- Backup and readback run as the `postgres` superuser (peer auth). That is acceptable for host-local
  tooling, but it is outside any application role.

## F-14 — postgres-exporter identity not provisioned

The repo never creates the `codestra_monitoring` role or grants it `pg_monitor`. The inventory marks the
exporter "unverified", and the OpenBao evidence describes a different, not-deployed rendering path.

## F-15 — Connector runtime split and lineage collision

- **Env var split:** the connector app reads `CONNECTOR_RUNTIME_DATABASE_URL`, but its Alembic env reads
  `DATABASE_URL` (`services/connector-runtime/migrations/env.py:12`).
- **Dead code:** `db.py` has no importer.
- **Lineage collision:** its lineage uses the default `alembic_version` table name, which is the same as
  canonical Middleware's `public.alembic_version`. `scripts/migration_lineage.py` validates only the
  connector lineage and rejects canonical revisions.
- **Driver:** `reconcile_legacy_staging_database.py` needs psycopg, which is absent from
  `requirements-runtime.txt`.

## F-16 — Deploy/runtime and documentation drift

**Deploy/runtime:**
- `deploy/compose.runtime.yaml:519` runs `workers.run_vicidial_odoo_projection` from
  `${MIDDLEWARE_IMAGE}` with `[python, -m, …]` as user 10001, which is the `Dockerfile` convention.
  `Dockerfile` does not copy `workers/` (`:123-127`), so the module would not import if the image comes
  from `Dockerfile`.
- `workers.run_outbox` and `workers.run_temporal` have no compose service.

**Documentation:**
- `docs/evidence/canonical-core-architecture-20260918/09-db-authority.md` still names head
  `0066_reconcile_odoo_campaign_scope` (current is `0067_service_catalog_monitoring_state`).
- `docs/STAGING-MIGRATION-LINEAGE.md` still describes the `0053` blocker and omits the 0058→0067
  reconciliation.
- `scripts/collect_staging_migration_evidence.sh:12` defaults to `0053`.
- `scripts/reconcile_legacy_staging_database.py:208` requires `current_database() == 'middleware_staging'`,
  while the staging profile names the database `codestra_staging` and the role `middleware_staging`. This
  is consistent only if the legacy staging host differs from the profile host; confirm before reuse.
