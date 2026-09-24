# Canonical Core Migration (Mission 2)

Base: `8995859` (Mission-1 certified, PR #278 head) · Branch: `mission/middleware-canonical-core-20260918` · Stacked on #278 (must not merge before it).

Initial state measured on the base commit: migration head `0066_reconcile_odoo_campaign_scope` (80 revisions, digest `sha256:b2270941…`); routes `app.main` 367 / `integration_api` 275 (261 shared); configuration authorities 2 (`app/config.py` dataclass `Settings`, `app/core/config.py` pydantic `Settings`); runtime authorities 3 (`app/runtime.py` `Runtime`, `app/entrypoints/runtime.py` `add_api_runtime`/`run_worker`, `app/appolon_factory.py` lifespan); FastAPI factories/instances for the primary process 3 (`app.main`, `app.appolon_factory.create_app`, `app.entrypoints.integration_api`).

## CURRENT_ARCHITECTURE

Two lineages are mounted into one deployed process by `app/router_registry.py`:

| Concern | "core" lineage | "Appolon" lineage |
| --- | --- | --- |
| Settings | `app/core/config.py` `Settings` (pydantic-settings, 88 importers; global `settings` built at import, `load_secret_files()`, `validate_safety()`) | `app/config.py` `Settings` (frozen dataclass, 38 importers incl. 18 tests; `Settings.from_env(mapping)` with strict `validate()`: issuer/JWKS per `APP_ENV`, synthetic CI identity only in development/test, umbrella controls, external effects, NATS/Temporal, runtime profiles, schema head, staging/production SHA+digest+build time+webhook secrets) |
| Identity | `app/core/jwt_auth.py` `KeycloakValidator` (sync, per-route construction, JWKS cache) | `app/security.py` `KeycloakJwtVerifier` (async, `PyJWKClient`, readiness, 401/403 split, 300 s lifetime, wildcard tenant rejection) |
| Runtime | `app/entrypoints/runtime.py`: guard middleware, rate windows, JSON logging, `/ready`,`/readyz`,`/health/ready`,`/dependencies` readiness on `app.state.runtime`, `run_worker`, `run_api` | `app/runtime.py`: `Runtime` dataclass (inbox, replay, tokens, commands, automation, communications, incidents, realtime), `build_runtime()` opening **five asyncpg pools** (inbox, commands, automation, realtime, communications) + one Redis client |
| DB | `app/db/session.py` module-global SQLAlchemy engine created at import from `settings.database_url` | per-store `asyncpg.create_pool()` |
| Application | `app/main.py` (8080 monolith, 367 routes, own guard copy, own health/readiness/version) · `app/entrypoints/integration_api.py` (deployed 8095: `FastAPI(routes=[…21 routers…])` + `mount_canonical_routers` + `add_api_runtime`, lifespan builds the Appolon `Runtime` from `DomainSettings.from_env()`) | `app/appolon_factory.py` `create_app(settings, runtime)` (24 inline routes: realtime tickets/stream, communications, `/health`,`/ready`,`/readiness`,`/dependencies`,`/capabilities`,`/metrics`,`/version`,`/v1/runtime/safety`) |
| Readiness | `entrypoints/runtime.py` `_readiness_report()` | `Runtime.readiness()` + `appolon_factory` `/ready` |
| Version/capabilities | `app/main.py` `/version`, `/capabilities` (core settings) | `appolon_factory` `/version`, `/capabilities` (domain settings, `runtime_safety_readback`) |
| Feature flags | 60 boolean fields on core `Settings` + `validate_safety()` production switch list | `external_effects` (24 env flags) + `umbrella_controls` (5) + `SUPPORTED_EXTERNAL_EFFECTS` allowlist |

Route divergence on the base: 106 routes exist only in `app.main` (orders, ai_jobs, social, postiz, ai*, recordings, tts, provider_commands, n8n_control_plane [denied], control `/events/*`, agent_realtime, `.well-known`, `/readiness`, lead_automation `/events/odoo`, publisher canary, n8n_target, klyrow_mail, campaign_search, registry); 14 only in `integration_api` (booking, quarantine, `/dependencies`, `/ready`). `POST /api/v1/events/vicidial` is served by `events.ingest_vicidial` (HMAC+nonce) on the monolith but by the **unauthenticated** `control.event` on the deployed app, on a path the guard exempts — a defect the canonical route set removes.

## Consumer inventory

### `app.config` (Appolon `Settings`) — 38 importers

| Consumer | Class | Attributes used |
| --- | --- | --- |
| `app/appolon_factory.py` | API factory | `app_env`, `app_version`, `allow_in_memory_storage`, `max_request_body_bytes`, `build_time`, `configuration_checksum`, `image_digest`, `release_id`, `runtime_profile_id`, `schema_head`, `source_sha`, `umbrella_controls` |
| `app/entrypoints/integration_api.py` | API entrypoint | `Settings.from_env()` |
| `app/runtime.py` | runtime | `allow_in_memory_storage`, `database_url`, `redis_url`, `readiness_timeout_seconds`, `umbrella_controls`, `app_env` |
| `app/runtime_safety.py` | security readback | `allow_in_memory_storage`, `build_time`, `external_effects`, `image_digest`, `nats_dispatch_mode`, `outbox_dispatch_enabled`, `production_dialing`, `runtime_profile_id`, `schema_head`, `temporal_worker_mode` |
| `app/security.py` | security | `issuer`, `jwks_uri`, `jwks_timeout_seconds`, `audience`, `webhook_max_clock_skew_seconds`, `webhook_secret()` |
| `app/email_production_control.py` | API+service | `app_env`, `email_delivery_enabled`, `production_activation_id`, `source_sha` |
| `app/klyrow_alert_adapter.py`, `app/klyrow_email_adapter.py`, `app/telnexa_provider_adapter.py`, `app/postly_social_adapter.py`, `app/odoo_provider_adapter.py`, `app/vicidial_internal_call_adapter.py` | adapters | `app_env`, `production_activation_id`, `email_delivery_enabled`, `sms_delivery_enabled`, `social_publishing_enabled`, `external_effects`, `umbrella_controls`, `odoo_source_delivery_enabled()` |
| `app/nats_transport.py`, `app/temporal_runtime.py` | transports | `nats_*`, `temporal_*` |
| `app/observability.py`, `app/observability_alert_contract.py`, `app/observability_alerts.py` | observability (alerts app is an approved isolated service) | `app_version`, `image_digest`, `schema_head`, `source_sha`, `production_activation_id` |
| `workers/run_outbox.py`, `workers/run_temporal.py` | workers | `database_url`, `odoo_base_url` (→ `ODOO_19_BASE_URL`), `odoo_default_hmac_secret`, `odoo_tenant_hmac_secrets`, `odoo_timeout_seconds`, `odoo_delivery_enabled`, `odoo_source_delivery_enabled()`, `outbox_dispatch_enabled`, `temporal_task_queue`, `klyrow_odoo_projection_enabled` |
| `scripts/generate_api_contracts.py` | CLI | `Settings.from_env()` |
| 18 test modules | tests | `Settings.from_env({...})`, `ConfigurationError` |

### `app.core.config` — 141 importers (API routers, adapters, workers, scripts, tests). Global `settings` instance; `Settings()` constructed directly in tests.

### `app.runtime` — 7 importers: `appolon_factory`, `entrypoints.integration_api`, `lead_intake`, `observability_alerts`, `sdk_events`, `service`, `survey_intake` (+22 tests).

### `app.entrypoints.runtime` — 20 importers (every entrypoint and worker; `add_api_runtime`, `run_api`, `run_worker`, `JsonFormatter`, `is_monitoring_route` style helpers).

### `app.main` — 2 importers (`scripts/audit`-style tooling, tests: 46). `app.appolon_factory` — 1 importer (`generate_api_contracts`) + 2 tests + tests using `create_app(settings=…, runtime=…)` (`test_runtime.py`, `test_calling_api.py`, …).

### Resource owners on the base

| Resource | Created by | Count |
| --- | --- | --- |
| `asyncpg.create_pool` | `storage.PostgresInboxStore.connect`, `commands.PostgresCommandStore.connect`, `automation_v2.PostgresAutomationStore.connect`, `communications.PostgresCommunicationsStore.connect`, `realtime.PostgresRealtimeStore.connect`, `email/*`, `websocket_gateway` | 5 in the primary runtime + isolated services |
| SQLAlchemy engine | `app/db/session.py` (import time) | 1 global |
| `Redis.from_url` | `replay.RedisReplayGuard.connect`, `endpoint_registry` (registry snapshot cache per `_build_odoo_client`), `sales/queue.py`, `social/queue.py`, `core/runtime_redis.py` | 5 sites |
| `PyJWKClient` | `security.KeycloakJwtVerifier.__init__` | 1 per `Runtime` |
| `httpx.AsyncClient` | adapters (`CommonServiceClient`, `OdooRuntimeClient`, provider adapters) | per adapter instance |
| `FastAPI(` | `app.main`, `appolon_factory.create_app`, `entrypoints.integration_api`, `entrypoints.runtime` (worker app), `entrypoints/{event_gateway,policy_engine,extension_allocator,telephony_provisioning,webphone_session_issuer,controller_api,server_a_agent}`, `observability_alerts`, `qwen_auth_verifier`, `email/api.py`, `websocket_gateway/app.py`, `scripts/generate_integrated_monitoring_openapi.py` | 16 |

## TARGET_ARCHITECTURE (delivered)

```
Environment / mounted secret files
        │
        ▼
app/core/config.py         ONE Settings (pydantic-settings) · ConfigurationError · IdentitySettings view
        │                  Settings.from_env(mapping) = build + secret files + validate_domain() + validate_safety()
        ▼
app/core/bootstrap.py      validate_configuration() (used by the factory) · validate_startup(service) (used by
        │                  run_api/run_worker): identity invariants, per-service secrets, flag gauges — fatal
        ▼
app/core/runtime.py        RuntimeContainer: ONE asyncpg pool (stores owns_pool=False), ONE Redis client
        │                  (replay guard owns_client=False), the ONE SQLAlchemy engine of app/db/session.py,
        │                  ONE KeycloakJwtVerifier; build_runtime_container() releases everything on failure;
        │                  readiness() = bounded probes incl. alembic_head against Settings.schema_head
        ▼
app/core/providers.py      FastAPI dependencies: get_settings/get_runtime/get_token_verifier/get_command_service …
        │
        ▼
app/application.py         create_app(settings=None, runtime=None, *, profile=CONTROL_PLANE, legacy_monolith=False)
        │                  ONE FastAPI · ONE RequestGuard (app/core/request_guard.py) · ONE health authority
        │                  (app/core/health.py) · canonical error envelope · assert_unique_routes()
        ▼
app/router_registry.py     CANONICAL · COMMON · INTEGRATION · APPOLON · MONOLITH · LEGACY_MONOLITH_ONLY groups
        │
        ├── AppProfile.INTEGRATION    app.entrypoints.integration_api:app   (deploy/compose.runtime.yaml, :8095)
        ├── AppProfile.CONTROL_PLANE  uvicorn app.main:create_app --factory (production read-only canary)
        └── AppProfile.MONOLITH       app.main:app                          (in-process monolith, CI startup step)
```

Route counts after the migration (test settings, unique `(method, path)` operations): integration 272,
control-plane 298, monolith 515; `assert_unique_routes()` refuses any duplicate at build time (previously two
shadowed duplicates existed on the monolith). Router groups: canonical 17, common 3, integration 18, Appolon 7,
monolith-only 19, legacy-denied 2.

### Decisions taken during the migration

| Topic | Decision | Why |
| --- | --- | --- |
| `SEND_EVENTS` | `SEND_EVENTS` gates the JetStream outbox transport (with `OUTBOX_DISPATCH_ENABLED`, `NATS_DISPATCH_MODE`, and in production the activation identity, TLS and mounted credential). The n8n broad-event pipeline's first switch is now `BROAD_EVENT_SEND_ENABLED` (new field `broad_event_send_enabled`), conjoined with `BROAD_EVENT_DELIVERY_ENABLED`, `PRODUCTION_N8N_ENABLED`, `N8N_PRODUCTION_WORKFLOWS_ENABLED` and a bounded scope exactly as before. Neither gate implies the other. | Both lineages used the name `SEND_EVENTS` for two unrelated pipelines; a union rule (tried in the first CI round) made the required isolated JetStream integration proof impossible, and the deployed process could never have enabled either. Splitting the switch keeps every existing rule for each pipeline. |
| Identity authority in development/test | Staging/production trust exactly their environment authority (issuer + derived JWKS). Development/test accept any explicit `https://` issuer/JWKS (a developer's or disposable CI Keycloak) or the approved synthetic CI pair; plaintext authorities are refused. | The former Appolon rule required the production issuer even on a developer box; the integrated-monitoring CI job and every test fixture use disposable issuers. |
| Identity | `IdentitySettings` carries a derived authority plus `explicit`. `KeycloakJwtVerifier` (control plane) uses the derived authority as before; `KeycloakValidator` sites bound to the Middleware identity use `identity_validator_kwargs()` and fail closed on an implicit identity. Readiness probes the JWKS in staging/production always, in development/test only when explicit. | Keeps the integration routes' "not configured → 401/503" behaviour, stops local processes from treating the production authority as a dependency. |
| `POST /api/v1/automation/policy-check` | `required_environment=settings.environment` (was pinned to `"production"`). | Mission-1 gap analysis item; staging n8n tokens were rejected in staging. `n8n_transport` keeps its production-only, BU-400/CMP-400 pin (controlled broad-event activation). |
| `POST /v1/telephony/calls/originate` | Owned by the documented Odoo calling contract (`app.telephony_api`, service JWT `telephony.calls.originate`). The agent-UI ORM handler `app.api.v1.telephony.originate_call` is no longer routed (kept callable for its lifecycle tests). | Two implementations on one operation would shadow one silently; `docs/ODOO-CALLING-ENDPOINTS.md` is the published contract. |
| Legacy `control` `/events/*` aliases, dead `lead_automation` `/events/odoo` | `POST /events/odoo` + `GET /events/{event_id}` moved to `control.legacy_events_router` (monolith only); `/events/vicidial` alias and the shadowed `lead_automation` registration removed. | They were dead or shadowed everywhere; the signed HMAC ingress owns `/api/v1/events/vicidial`. |
| Edge-denied n8n aliases | `LEGACY_MONOLITH_ONLY_ROUTERS` (+ `domain_api.legacy_n8n_router`) mount only on `AppProfile.MONOLITH`; the control-plane canary no longer serves them. | Contract classification `denied`; `scripts/audit_release_endpoints.py` fails closed if a deployed profile mounts them. |
| Validation errors | Control-plane routes: 400 canonical envelope; `/api/v1/sales/*`: sanitized 422; everything else: FastAPI 422 (as the integration contracts document). OpenAPI shaping follows the same rule. | The canary previously answered 400 for canonical routes while the integration API answered 422 for the same routes. |
| Correlation | A well-formed client `X-Correlation-ID` is echoed; otherwise a UUID is generated. Valid `traceparent` echoed, invalid dropped, absent → generated. | The Appolon canary echoed, the integration API always regenerated; echo-when-safe keeps tracing and prevents log injection. |
| `/metrics` on the canonical app | Authenticated (`monitoring-readonly`, `metrics.read`) as on the canary; worker processes keep the unauthenticated Prometheus mount on their own port. | Stricter of the two; the deployed API health checks use `/healthz` + `/readyz`. |
| `/version` | Read from `Settings` (`APP_SOURCE_SHA`, with `SOURCE_SHA` accepted as alias) instead of `os.getenv` at request time. | The entrypoint handler read `SOURCE_SHA`, which `Dockerfile.runtime` never sets (it bakes `APP_SOURCE_SHA`) — deployed `/version` reported `unknown`. |
| Readiness status string | `not-ready` (integration contract) everywhere; payload = `{status, service, components, dependencies, authorization, database, redis, delivery, reason, checked_at}`. | Superset of both former payloads; dependency *states* are named, addresses/credentials never. |
| Startup failure | The process stays live and unready (503) and retries the container build at most once per `RUNTIME_REBUILD_INTERVAL_SECONDS` (default 30 s) from a readiness probe. | The canary used to crash-loop, the integration API stayed unready forever; self-healing without hot loops. |
| Per-process validation | Every process now runs `validate_domain()` + `validate_safety()` + identity invariants at start (`validate_startup`), not only `validate_safety()`. | One startup validation. |

## MIGRATION_MAP

| From | To | Mechanism |
| --- | --- | --- |
| `app/config.py` `Settings` fields, `from_env`, `validate` | `app/core/config.py` `Settings` (fields added with explicit env aliases; `Settings.from_env(mapping)`; `validate_domain()`); domain attribute names preserved as properties (`issuer`, `jwks_uri`, `audience`, `external_effects`, `umbrella_controls`, `webhook_secret()`, …) | migrate consumers module by module, then shim |
| `KEYCLOAK_JWKS_URI` | `KEYCLOAK_JWKS_URL` (temporary compatibility alias, warns, removed after certification) | alias |
| `MIDDLEWARE_AUDIENCE` | `KEYCLOAK_AUDIENCE` (alias) | alias |
| `ODOO_19_BASE_URL` → `settings.odoo_base_url` (collides with core `ODOO_BASE_URL`) | `settings.odoo_19_base_url` | explicit rename in `workers/run_outbox.py`, `app/odoo_transport.py` |
| domain `odoo_delivery_enabled` property (collides with core bool field) | `odoo_19_delivery_enabled` | explicit rename |
| `app/runtime.py` `Runtime`/`build_runtime` | `app/core/runtime.py` `RuntimeContainer`/`build_runtime_container` (`app/runtime.py` is a deprecated shim; 30 importers migrated explicitly) | done |
| `appolon_factory.create_app` inline routes | `app/appolon_routes.py` router (realtime tickets/stream, `/metrics`, `/v1/runtime/safety`, communications, intake, commands, signed webhook ingress) + `install_error_handlers`/`install_canonical_openapi`; `app/appolon_factory.py` is a deprecated shim | done |
| `app.main` / `integration_api` / `appolon_factory` factories | `app/application.py` `create_app(profile=…)`; `integration_api.app = create_app(profile=INTEGRATION)`, `main.app = create_app(profile=MONOLITH)`, `main.create_app` = the factory (control-plane default for `--factory`) | done |
| `/health*`, `/ready*`, `/version`, `/capabilities`, `/dependencies` (3 implementations) | `app/core/health.py` (`register_health_routes` for container-backed apps, `register_service_health_routes` for narrow processes) | done |
| Guard (`main.py` + `entrypoints/runtime.py` + Appolon `observe_request`) | `app/core/request_guard.py` `RequestGuard` installed by `create_app` and by `add_api_runtime` | done |
| `os.getenv("SOURCE_SHA")` in `/version` | `Settings.source_sha` (`APP_SOURCE_SHA` / `SOURCE_SHA`) | done |
| Historical Stage-6 source contract (`scripts/validate_staging_intake_observability_contract.py`) | re-targeted to `app/application.py`, `app/core/request_guard.py`, `app/appolon_routes.py`, `app/core/health.py`, `app/router_registry.py`; every clause kept, 34 mutations × 2 modes fail closed | done |
| Generated API contract (`contracts/platform/*`, `config/api-completion-matrix.yaml`) | regenerated from `AppProfile.CONTROL_PLANE` (adds the canonical health aliases, drops the 5 deprecated n8n aliases, documents 422 on canonical routes) | done |

## APPROVED_EXCEPTIONS (isolated deployable services owning their own resources)

| Service | Module | Why isolated |
| --- | --- | --- |
| Observability alerts receiver | `app/observability_alerts.py` (own `FastAPI`, own `Runtime`) | separate deployment (`deploy/observability-alerts`), separate identity policy |
| Qwen auth verifier | `app/qwen_auth_verifier.py` | separate mTLS verifier process |
| Email service | `app/email/api.py`, `app/email/runtime.py` | separate service with own DB base |
| WebSocket gateway | `websocket_gateway/app.py` | separate process/port 6101 |
| Event gateway, policy engine, extension allocator, telephony provisioning, webphone session issuer | `app/entrypoints/*.py` | separate compose services; they use `add_api_runtime` and canonical settings but own no domain runtime |
| Controller API, Server A agent | `app/entrypoints/controller_api.py`, `server_a_agent.py` | development-only, inactive |
| Workers | `app/entrypoints/*_worker.py`, `workers/*.py` | own lifecycle via `run_worker`; use canonical settings; open their own pool through `RuntimeContainer` where they need domain services |

## DELETION_PLAN (status)

1. `app/config.py` → import shim with `DeprecationWarning` — **done** (no importer left; `tests/test_architecture_governance.py::test_no_consumer_imports_a_legacy_shim`).
2. `app/runtime.py` → import shim — **done**; removal of the file is scheduled for the release after certification.
3. `app/appolon_factory.py` → shim; inline routes moved to `app/appolon_routes.py` — **done**; removal scheduled with 2.
4. `app/main.py` → `app = create_app(profile=MONOLITH)`; guard/health copies deleted — **done** (module keeps the guard path constants as re-exports for tooling).
5. `app/entrypoints/integration_api.py` → `app = create_app(profile=INTEGRATION)`; route list deleted — **done**.
6. Duplicate readiness/version/capabilities/guard handlers deleted from `entrypoints/runtime.py` — **done** (`add_api_runtime` delegates to the core; `worker_app` keeps its own operational surface by design).
7. Governance tests `tests/test_architecture_governance.py` forbid re-introduction — **done**.

## REMAINING (not in scope of Mission 2, tracked for M3)

- Per-request `Redis.from_url` clients in `app/api/v1/agent_realtime.py`, `app/api/v1/registry.py`, `app/api/v1/readiness_challenge.py`, `app/adapters/odoo/results.py` and workers — should take `RuntimeContainer.redis` through `app.core.providers` where a container exists.
- `os.getenv` readers listed in `test_environment_is_read_only_by_configuration_authority` (ratchet: may only shrink).
- Removal of the three shims after one release.
- Promotion (or removal) of `N8N_PRODUCTION_WORKFLOWS_ENABLED` as a supported effect before the n8n broad-event pipeline can ever be enabled.
- Migration of `app/vicidial_internal_call_adapter.py` off the `app.config` shim (blocked in this PR by the lead-automation workflow gate on vicidial-named files).

## SECURITY_INVARIANTS (must hold after migration; each has a test)

- Synthetic CI identity (`https://ci-identity.example.invalid/realm`, `http://127.0.0.1:8120/certs.json`) valid only when `APP_ENV` ∈ {development, test}; rejected for staging/production.
- Staging/production require exact issuer per environment, JWKS derived from issuer, audience `middleware-api`, 40-char source SHA, sha256 image digest, build time, ≥32-byte webhook secrets, registered runtime profile.
- RS256 only; `exp`,`iat`,`iss`,`sub`,`aud`,`azp`,`jti`,`scope` required; lifetime ≤ 300 s; `azp` must equal the expected client; scope required; wildcard tenant rejected; missing tenant claim rejected.
- 401 for missing/invalid authentication; 403 for authenticated-but-unauthorized.
- Every provider-effect flag defaults to false; `validate_safety()` rejects production switches; umbrella controls off in staging.
- Liveness never depends on external dependencies; readiness is 503 on any mandatory dependency outage; configuration errors are startup-fatal.
- `POST /api/v1/events/vicidial` is served only by the HMAC+nonce ingress; the unauthenticated `control.event` alias on that path is removed.

## DEPENDENCY_OWNERSHIP

| Resource | Owner after migration |
| --- | --- |
| asyncpg pool (primary process) | `RuntimeContainer.pool` (stores built with `owns_pool=False`) |
| SQLAlchemy engine/session factory | `app/db/session.py` (`engine`, `SessionFactory`, `get_engine()`, `configure()`, `dispose()`); `RuntimeContainer.engine` references it and disposes it on close |
| Redis client | `RuntimeContainer.redis` (replay guard shares it, `owns_client=False`) |
| JWKS client | `RuntimeContainer.tokens` (`KeycloakJwtVerifier`); `KeycloakValidator` binds to `Settings.identity` per request |
| Domain services | `RuntimeContainer` attributes, resolved by handlers through `app.core.providers` |
| Adapter HTTP clients | adapter instances created per operation and closed in `finally` (unchanged) |
| Isolated services | listed above; each owns its resources and is excluded from the single-runtime invariant (allowlisted by name in `tests/test_architecture_governance.py`) |

## HEALTH CONTRACT (app/core/health.py)

| Route(s) | Answer |
| --- | --- |
| `GET /health`, `/healthz`, `/health/live` | 200 `{"status":"ok","service","component":"api"}` — never touches a dependency |
| `GET /ready`, `/readyz`, `/health/ready`, `/readiness` | 200/503; `components` = container probes (`inbox_store`, `replay_guard`, `identity_jwks`, `command_store`, `communications_store`, `incident_store`, `automation_store`, `realtime_store`, `sql_engine`, `alembic_head`), `dependencies` = `{postgres, redis, keycloak}` derived from them, `reason` names the failure (`runtime_unavailable`, `RuntimeStartupError`, `components_not_ready:<names>`) |
| `GET /version` | release labels from `Settings` only |
| `GET /capabilities` | fail-closed flags and umbrella controls |
| `GET /dependencies`, `/health/dependencies` | dependency states + canonical flag readback |

Readiness failure modes certified by `required-ci.yml` ("Certify required-database readiness failure modes") are unchanged: wrong credential, DNS failure, TCP failure, Redis failure and JWKS outage each leave `/healthz` at 200 and `/readyz` at 503 for `app.entrypoints.integration_api:app`.

Recovery: a process whose container failed to build stays live; each readiness probe after `RUNTIME_REBUILD_INTERVAL_SECONDS` triggers one guarded rebuild; success flips readiness to 200 without a restart.
