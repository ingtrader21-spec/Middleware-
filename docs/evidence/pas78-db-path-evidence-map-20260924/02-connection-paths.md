# 02 — Connection paths per component

The two shared handles are **P** (the RuntimeContainer asyncpg pool) and **E** (the SQLAlchemy engine). All
IDs refer to `db-access-paths.v1.json`.

| Handle | Where | DSN → driver | Pool / timeouts | `application_name` |
| --- | --- | --- | --- | --- |
| **P** `P-RUNTIME-POOL` | `app/core/runtime.py:344-350`, opened at `:399` | `settings.database_url` → `_asyncpg_dsn` | min 1 / max 20, `command_timeout` 10 s (constants `:78-80`). No connect timeout, no recycle, no `server_settings` | none |
| **E** `E-SQLALCHEMY-ENGINE` | `app/db/session.py:36-49`, built **at import** (`:52`); `configure()` rebinds it | bare `postgresql+asyncpg://` URL plus `connect_args.dsn` = native DSN | size 8, overflow 4, pool timeout 5 s, recycle 1800 s, `pre_ping`, `command_timeout` 30 s | none |

`build_runtime_container` attaches E (`runtime.py:450, 476-481`), so every container process holds both
handles. The worst case is 20 + 8 + 4 = 32 server connections per process (F-09).

## 1. API process (`app.main` / `create_app`, `app/application.py`)

- **Settings validation:** `validate_configuration(process_settings)` (`application.py:102`) runs
  `validate_domain()` on the rewritten settings (F-01).
- **P consumers (asyncpg, raw SQL):**
  - `PostgresInboxStore`, `PostgresCommandStore`, `PostgresAutomationStore`, `PostgresRealtimeStore`,
    `PostgresCommunicationsStore` and the email policy store, all with `owns_pool=False` (`runtime.py:402-436`)
  - `control_api.py:183-187`, `intake_observability.py:103`, `observability_incidents.py:1350`,
    `calling_ledger.py:81,106,185`, `temporal_activities.py:265+`, `platform/persistence.py:29,60`,
    `observability_projection.py:129`
  - the private DB API (`api/internal/database.py`, see 05)
- **E consumers (ORM plus `text()`):** about 40 routers in `app/api/v1/*` and `app/api/internal/*` via
  `get_session` (`db/session.py:82`, re-exported by `core/providers.py:31`).
- **Per-transaction RLS context:** `core/callback_rls.py:22-28` sets `set_config('app.*', …, true)`.
- **Readiness:** `sql_engine` (E, `SELECT 1`, `runtime.py:144-148`) and `alembic_head` (P, `:150-163`).
  `inbox_store.ready()` also checks `middleware_schema_migrations` against `RUNTIME_SCHEMA_VERSION`
  (`storage.py:618`).
- **Health DB probe:** `core/health.py:158-178` reuses E.

## 2. Background processes

| Process | Entrypoint | DSN | Handles | Tables / notes |
| --- | --- | --- | --- | --- |
| Outbox worker | `workers/run_outbox.py` (`Dockerfile.runtime` target `worker`, `:59`) | `Settings.from_env()` `:58` | P (the container, role `worker`, `:65-70`) plus E if the staging n8n adapter runs | `middleware_outbox` via raw SQL `:34-53` and `PostgresOutboxStore` `:138`. **No compose service** |
| Temporal worker | `workers/run_temporal.py` | `Settings.from_env()` `:199` | **Own pool** via `PostgresCommandStore.connect()` `:207` → `app/commands.py:860` (1/10, 10 s) | command ledger tables. No `+asyncpg` strip (F-08). **No deploy manifest** |
| Scheduler | `python -m app.entrypoints.scheduler` (`compose.runtime.yaml:394`; `Dockerfile.runtime:64`) | process `settings` | E only (`entrypoints/scheduler.py:23-36`, `app/workers/scheduler.py:17`) | `callback_record`, `callback_event`, `callback_delivery` (RLS `set_config`), `outbox_event`, `event_inbox`, `reconciliation_checkpoint` |
| Reconciler | `python -m app.entrypoints.reconciliation_worker` (`compose.runtime.yaml:383`; `Dockerfile.runtime:67`) | process `settings` | P (built on the first cycle, `:35`) **and** E (`:56`), both used | P: `middleware_outbox` (`FOR UPDATE SKIP LOCKED`), `middleware_control_audit`, `middleware_reconciliation_audit` (`platform/persistence.py:58-212`). E: `event_inbox`, `outbox_event`, `reconciliation_checkpoint`, `invalid_event_quarantine`, `audit_event` |
| ViciDial→Odoo projection | `workers.run_vicidial_odoo_projection` (`compose.runtime.yaml:519`) | process `settings` | E (`:172`), plus local **SQLite** state (`app/vicidial_odoo_projection_state.py:67`) | `telephony_call_lifecycle` `SELECT … FOR UPDATE` (`vicidial_odoo_projection_lifecycle_sync.py:143,206`) |
| Projection state init | `workers/init_vicidial_odoo_projection_state.py` | — | **no DB** | prepares a directory |
| Qwen polling worker | `worker/qwen_polling_worker.py` | — | **no DB** | HTTPS/mTLS client only |
| `app/workers/*` (16 modules) | via their entrypoints | process `settings` | E via `SessionFactory` | ORM plus `text()` on `outbox_event`, `event_inbox`, `audit_event`, `callback_*`, `telephony_*`, `n8n_*` |
| Beyvra email | `app/email/runtime.py` (`deploy/beyvra-email/compose.yaml`) | `BEYVRA_EMAIL_DATABASE_URL[_FILE]` (bypasses Settings) | **own sync `create_engine`** at import (`app/email/schema.py:26`), no timeouts | separate process |

## 3. Named components

| Component | Code | Postgres? |
| --- | --- | --- |
| Policy engine service | `app/entrypoints/policy_engine.py` → `api/v1/policy_engine.py:13,32`, `api/internal/authorization.py:45,53` | **Yes**, E: writes `policy_decision`, `audit_event`. Startup through `run_api` → `validate_startup(settings)` (F-01) |
| Policy engine logic | `app/core/policy_engine.py` | no (pure evaluation) |
| Safety gate | `app/platform/safety.py` | no |
| Command kernel / execution bus | `app/platform/kernel.py`, `bus.py` | indirectly through `CommandService` on P; denials go to `middleware_control_audit` (`persistence.py:27-44`) |
| Reconciler | `app/platform/reconciler.py` + `PostgresReconciliationSource` | P (see §2) |
| Event gateway (ingestion) | `app/entrypoints/event_gateway.py` → `events.py:23` `get_session` | E |
| Realtime gateway | `websocket_gateway/app.py:169-171` | **Own pool**, 2/20, 5 s; separate database `codestra_realtime` (`websocket_schema_migrations`, `realtime_sessions`, `realtime_tickets`, `realtime_events`); `certify.py:138` (1/10); `recovery_certify.mjs` shells an `asyncpg.connect` INSERT into `realtime_events` inside the certifier container |
| JetStream / NATS / Temporal transport | `app/eventing/jetstream.py`, `app/nats_transport.py`, `app/temporal_{runtime,transport,workflows}.py` | no |
| Automation policy | `app/automation_policy.py` | no (reads JSON) |
| Connector runtime | `services/connector-runtime/.../api/database.py:23-35` | **Own sync psycopg engine**, 10 + 20, recycle 300 s, `connect_timeout` 5, **`application_name=service_name`**, DSN `CONNECTOR_RUNTIME_DATABASE_URL`; schema `connector_sdk`, `set_config('codestra.tenant_id')`. `db.py:21-27` is dead code |

## 4. Deploy wiring

- **`deploy/compose.runtime.yaml`:**
  - Each service mounts a per-service `*-database-url` secret at `/run/secrets/database_url`. Examples:
    - event gateway `:158`
    - policy engine `:274`
    - reconciler `:383`
    - scheduler `:394`
    - projection `:538`
  - The klyrow, scraper, n8n-runtime, social-n8n and postly workers reuse the **integration-api** secret
    (`:238,251,330,352,367`), so they share the API's role.
  - `DATABASE_URL_FILE` is expected from `/opt/codestra/env/middleware.env` (`:16-17`), which is not in
    the repo.
  - Image is `${MIDDLEWARE_IMAGE}`, running as user `10001` with `[python, -m, …]` commands.
- **`deploy/production/compose.canary.yaml`:** the migrate and API canaries share one `env_file`
  (`:5-6`), with `RUNTIME_PROFILE_ID=codestra-middleware-production-compose-v1`, so no TLS (F-03).
  The migrate canary runs `/app/scripts/migrate_runtime.py` (`:76-79`).
- **Websocket gateway (`websocket_gateway/compose.yaml`, `deploy/websocket-ha/compose.standby.yaml`):**
  runs its own `postgres:16`. Migrate and app mount the same `database_url` secret
  (`compose.standby.yaml:37,47`).
- **Images:**
  - `Dockerfile` does not copy `workers/` (`:123-127`, user 10001).
  - `Dockerfile.runtime` does (`:41`, user 65532).
  - The compose projection service needs `workers/` (F-16).
