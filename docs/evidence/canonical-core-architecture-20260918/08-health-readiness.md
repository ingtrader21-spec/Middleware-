# 08 — Health and readiness authority: `app/core/health.py`

| Route(s) | Status | Body |
| --- | --- | --- |
| `GET /health`, `/healthz`, `/health/live` | 200 always | `{"status":"ok","service":<service>,"component":"api"}` — no dependency is touched |
| `GET /ready`, `/readyz`, `/health/ready`, `/readiness` | 200 ready / 503 not ready | `status` (`ready`/`not-ready`), `service`, `components` (container probes), `dependencies` (`postgres`/`redis`/`keycloak`: `online`/`unavailable`/`not_configured`, derived from the components), `authorization`, `database`, `redis`, `delivery`, `reason`, `checked_at` |
| `GET /version` | 200 | `service`, `version`, `environment`, `runtime_profile_id`, `source_sha`, `git_sha`, `release_id`, `image_digest`, `build_timestamp`, `schema_head`, `schema_version`, `configuration_checksum`, `timestamp` — from `Settings` only |
| `GET /capabilities` | 200 | fail-closed flags (`business_writes_enabled`, `external_delivery_enabled`, `live_*`, `simulation_enabled`, `read_only_mode`, …) + `capabilities` (umbrella controls, `PRODUCTION_DIALING`) |
| `GET /dependencies`, `/health/dependencies` | 200 | dependency states + canonical flag readback + `checked_at` |

Two registrations exist for two kinds of process, both in this module: `register_health_routes(app, service,
state)` for container-backed applications (every `create_app` profile) and `register_service_health_routes(app,
service, settings)` for the narrow processes (`add_api_runtime`), whose readiness probes only the SQL engine and
only when `HEALTH_REQUIRE_DATABASE` is true (read per probe, not at import).

## Readiness decision (container-backed)

1. `RuntimeState.rebuild_if_due()` (see 05).
2. No container → **503**, `reason` = `runtime_unavailable` or the startup exception class; `dependencies` from
   an explicit settings probe (`dependency_states`: engine `SELECT 1`, Redis ping, JWKS fetch with RS256 key) so
   operators still see which dependency is down.
3. Container present → `RuntimeContainer.readiness()`; 200 only when every configured component is `ready`;
   otherwise **503** with `reason = components_not_ready:<names>`.

Addresses and credentials are never rendered (`tests/test_runtime.py::test_readiness_reports_named_failure_without_dependency_details`).

## Mapping to the certified CI failure modes (`required-ci.yml`, `app.entrypoints.integration_api:app`)

| Case | Path through the canonical code | `/healthz` | `/readyz` |
| --- | --- | --- | --- |
| healthy | container built (pool, Redis, JWKS fixture, schemas) | 200 | 200 |
| wrong DB credential | `_open_pool` raises → `RuntimeStartupError` → live/unready | 200 | 503 |
| DNS failure | same | 200 | 503 |
| TCP failure | same | 200 | 503 |
| Redis failure | `_open_redis` raises after the pool opened → pool closed → unready | 200 | 503 |
| JWKS outage (explicit synthetic identity) | `identity_jwks` `not_ready` → startup refused → unready; a later rebuild succeeds once the JWKS returns | 200 | 503 |

The CI "Application startup and disabled defaults" step (`uvicorn app.main:app`, implicit identity,
migrated DB, Redis) is expected to answer 200 on `/readyz`: `identity_jwks` is `not_configured`, `alembic_head`
matches after `alembic upgrade head`, runtime SQL schemas exist after `scripts.migrate_runtime`.

Tests: `tests/test_integration_manifest_health.py` (25), `tests/test_entrypoints.py` (health/version/
capabilities on integration API, narrow services and workers), `tests/test_runtime.py::test_health_ready_version`,
`tests/test_core_runtime_container.py` (rebuild, snapshot), `tests/test_architecture_governance.py::test_health_routes_are_registered_only_by_the_health_authority`.
