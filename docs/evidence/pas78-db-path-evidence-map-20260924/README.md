# PAS-78 — Middleware PostgreSQL access-path and role evidence map

Source: `origin/main` at `0606b0d` (schema head `0067_service_catalog_monitoring_state`).
Branch: `pas-78/db-path-evidence-map-20260924`. Scope: read-only mapping of code, configuration, deploy
manifests and contracts. **No runtime, database, deploy or production state was touched.**

| File | Content |
| --- | --- |
| [01-dsn-and-tls.md](01-dsn-and-tls.md) | DSN sources, parsers, secret files, TLS/`sslmode` semantics, locked runtime profiles |
| [02-connection-paths.md](02-connection-paths.md) | Every pool/engine/connection per component: API, workers, scheduler, reconciler, policy engine, event gateway, realtime gateway, connector runtime |
| [03-roles-schemas-migrations.md](03-roles-schemas-migrations.md) | Login roles, grant roles, schema ownership, migration authority and runners |
| [04-backup-and-exporter.md](04-backup-and-exporter.md) | Backup/restore tooling, superuser shell paths, postgres-exporter |
| [05-private-db-api-and-contracts.md](05-private-db-api-and-contracts.md) | `/internal/v1/database/*`, health surfaces, raw-SQL surfaces, OpenAPI/Postman/route authority |
| [06-tests-and-governance.md](06-tests-and-governance.md) | Test DSN sources, existing DB tests, governance rules, the PAS-78 ratchet test |
| [07-findings.md](07-findings.md) | F-01 … F-16: divergences, duplicates and gaps, each with evidence and owner lane |
| [db-access-paths.v1.json](db-access-paths.v1.json) | Machine-readable map, enforced by `tests/test_db_access_path_map.py` |

## Summary

* **Two shared handles per Middleware process.** `RuntimeContainer` opens one asyncpg pool
  (`app/core/runtime.py:344-350`, 1–20 connections, 10 s command timeout, hard-coded) and references the
  one SQLAlchemy engine (`app/db/session.py:36-52`, 8 + 4 connections, 30 s, from `DATABASE_*` settings).
  Neither sets `application_name`, `statement_timeout` or an `ssl=` argument; TLS comes only from the DSN
  query string.
* **22 Python connection sites** in the scanned trees (`app`, `workers`, `worker`, `scripts`,
  `websocket_gateway`, `migrations`, `services/connector-runtime`) plus 5 shell/exporter paths. The
  alternate owners are the 5 store `connect()` classmethods, the Temporal worker's own pool, the Beyvra email
  sync engine, the realtime gateway (separate `codestra_realtime` database), the migration runners and the
  connector runtime (the only path that sets `application_name`).
* **Migration authority:** `scripts/migrate_runtime.py` (Alembic to the pinned head, then runtime SQL
  0001–0011 and automation 0001, advisory lock `742603070118`), gated offline by
  `scripts/production_migration_authority.py`. No migration creates roles or changes ownership. The
  migrator and the API use the same DSN and role in production compose.
* **Highest-severity findings:**
  * **F-01:** under a locked runtime profile, the process settings DSN is rewritten to `postgresql+asyncpg://`
    before profile validation, which then rejects it (reproduced as a strict xfail).
  * **F-02:** `verify-full` has no path to supply a CA.
  * **F-03:** the production-compose profile and the exporter run without TLS.
  * **F-04:** the migration and runtime role are one role.

## Acceptance

| Requirement | Where |
| --- | --- |
| API, worker, scheduler, reconciler, policy engine, event gateway | 02 §1–§3 |
| Migration runner | 03 §3 |
| Backup tooling, postgres-exporter | 04 |
| Tests | 06 |
| DSN source/parser, TLS/SSL semantics | 01 |
| SQLAlchemy/asyncpg creation, pools/timeouts, `application_name` | 02, JSON map |
| Cert/secret paths | 01 §3 |
| DB role, schema ownership, migration authority | 03 |
| Duplicate/divergent logic | 07 (F-01, F-08, F-09, F-15) |
| Private DB APIs, raw SQL surfaces, OpenAPI/Postman/DB authority | 05 |
| Validator improvement | `tests/test_db_access_path_map.py` (06 §4) |

Every finding is recorded, not fixed: each needs its own governed change (see the owner lane column in 07).
