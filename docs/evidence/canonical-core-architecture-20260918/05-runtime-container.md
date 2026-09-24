# 05 — Runtime container: `app/core/runtime.py`

## Ownership

| Resource | Before | After |
| --- | --- | --- |
| asyncpg pools | 5 (`*.connect()` per store, each `min 1 / max 10` or `5`) | **1** `RuntimeContainer.pool` (`min 1 / max 20`, `command_timeout 10`); stores built with `owns_pool=False` and never close it |
| Redis client | `RedisReplayGuard.connect()` owned | **1** `RuntimeContainer.redis`; guard built with `owns_client=False` |
| SQLAlchemy engine | import-time global | still the one `app/db/session.py` engine; `RuntimeContainer.engine` references it (`get_engine()`), disposes it on close; `configure()`/`dispose()` added for bootstrap/tests |
| JWKS client | `KeycloakJwtVerifier(settings)` per `Runtime` | **1** `RuntimeContainer.tokens` |
| Email production policy store | `PostgresEmailProductionPolicyStore(communications_store.pool)` | same store on the shared pool |

`build_runtime_container(settings, *, engine=None, tokens=None)`:
1. in-memory container when `ALLOW_IN_MEMORY_STORAGE` (test/development only);
2. otherwise requires `DATABASE_URL` and `REDIS_URL`, opens the pool, pings Redis, verifies the inbox schema,
   command-ledger and automation schemas, loads the communications projection, builds every service;
3. runs `readiness()` and raises `RuntimeStartupError` naming the failed components when any is `not_ready`;
4. on **any** failure closes what it opened (container → stores → pool → Redis) before raising.

`RuntimeContainer.close()` is idempotent, closes every component and then the shared infrastructure, and
never raises (component failures are logged).

## Readiness (`readiness()` → `ReadinessReport`)

Bounded by `READINESS_TIMEOUT_SECONDS` per component (`asyncio.wait_for`); statuses `ready` /
`not_ready` / `not_configured`; components: `inbox_store`, `replay_guard`, `identity_jwks`, `command_store`,
`communications_store`, `incident_store`, `automation_store`, `realtime_store` (when configured), `sql_engine`
(when an engine is attached), `alembic_head` (when a pool is attached; see 09). `identity_jwks` is
`not_configured` when `identity_probe_required(settings)` is false (implicit identity in development/test).

## Recovery (`app/core/health.py::RuntimeState`)

`build()` records failures (`startup_failed`, `startup_error` = exception class name). `rebuild_if_due()` runs
from readiness probes: at most one guarded rebuild per `RUNTIME_REBUILD_INTERVAL_SECONDS`, serialized by an
`asyncio.Lock`; success publishes the new container to `app.state.runtime` (the guard refreshes it on every
request) and readiness flips to 200 without a restart.

## Tests (`tests/test_core_runtime_container.py`, 13)

In-memory container owns nothing; implicit identity not probed; bounded readiness names the failed component
and maps to dependency states; close releases every owned resource exactly once even when a store's close
raises; build releases the pool when Redis fails; empty `DATABASE_URL` refused; `ReadinessReport` semantics;
rebuild at most once per interval; successful rebuild published; `alembic_head` ready/stale/absent;
dependency aggregation never reports `online` on a failure; snapshot without runtime uses the settings probe.
Plus `tests/test_runtime.py` (Appolon runtime behaviour, 30) and `tests/test_integration_runtime_wiring.py`
(lifespan owns the container; startup failure leaves the process live but unready).
