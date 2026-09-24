# Middleware Baseline (Mission 1)

Factual snapshot of the repository at the Mission 1 baseline. Every number below was
measured from the sources on branch `codex/cross-repo-authority-20260916`; the
measurement method is stated next to each value so it can be re-run.

| Identity | Value |
| --- | --- |
| Certified starting SHA (Mission input) | `123ad3342f6a1f94421e2449b6f06ad821be81d3` |
| Migration repair commit | `3c675d1d479e1d3c51581aaa421508e855a4abd5` (widens `alembic_version.version_num` inside 0066) |
| Baseline SHA | the commit that adds this document; recorded as `MIDDLEWARE_BASELINE_SHA` in the Mission 1 report |
| Pull request | ingtrader21-spec/Middleware- #278 |
| Public route contract digest | `7580123dead97ea342c704a57a3c8eed9f5dce69aab247d4b693db96bc7334d5` (unchanged by Mission 1) |

## Versions

| Component | Pinned / observed | Source |
| --- | --- | --- |
| Python (CI runner) | 3.12.14 | required-ci run 35216425875 log |
| Python (test image build) | 3.12.13 | same log, Docker build stage |
| Python (constraint) | `>=3.12,<3.14` | `pyproject.toml` |
| Python base image | `python@sha256:6d43704b…` (CI build arg), `python@sha256:d09d15e6…` (Dockerfile default) | `.github/workflows/required-ci.yml:199`, `Dockerfile:2` |
| Runtime image | `cgr.dev/chainguard/python@sha256:1f677977…` | `Dockerfile:4` |
| FastAPI | 0.139.2 (pinned) — local dev environment had 0.141.1 | `requirements-runtime.txt` |
| Starlette | 1.3.1 | `requirements-runtime.txt` |
| SQLAlchemy | 2.0.43 | `requirements-runtime.txt` |
| asyncpg | 0.30.0 | `requirements-runtime.txt` |
| Alembic | 1.16.4 (pinned) — local dev environment had 1.19.1 | `requirements-runtime.txt` |
| pydantic | 2.10.4 | `requirements-runtime.txt` |
| httpx | 0.28.1 | `requirements-runtime.txt` |
| redis (client) | 6.4.0 (pinned) — local dev environment had 5.3.1 | `requirements-runtime.txt` |
| nats-py | 2.15.0 | `requirements-runtime.txt` |
| uvicorn | 0.35.0 | `requirements-runtime.txt` |
| PostgreSQL (required CI) | 17.10 (`postgres@sha256:742f40ea…`) | CI service log "starting PostgreSQL 17.10 on x86_64-pc-linux-musl" |
| PostgreSQL (middleware-ci.yml) | 16-alpine (`postgres@sha256:cf78e766…`) | `.github/workflows/middleware-ci.yml:325` — two CI workflows pin different major versions |
| Redis (CI) | 7.4.11 (`redis@sha256:ff02b58f…`) | CI service log |
| Alembic `version_num` column | VARCHAR(32) created by Alembic; widened to VARCHAR(64) by revision 0066 | `migrations/versions/0066_reconcile_odoo_campaign_scope.py` |

Local development environments drift from the pinned versions (three packages differ on the certifying workstation); only the checksum-pinned CI environment is authoritative.

## Canonical runtime

| Item | Value | Source |
| --- | --- | --- |
| Canonical application entrypoint | `app.entrypoints.integration_api:app` (`python -m app.entrypoints.integration_api`) via `app.router_registry` | `deploy/compose.runtime.yaml` service `middleware-integration-api`, contract v2 `service` field |
| Canonical runtime port | 8095 (`PORT: "8095"`, contract `listener_port: 8095`) | `deploy/compose.runtime.yaml:23`, `deploy/public-api-route-contract.json` |
| Non-canonical application | `app.main:app` (8080 monolith, 369 routes) kept only until the published sunset of `/v1/integrations/n8n/*` aliases | `app/main.py` |
| Other FastAPI app objects | 16 total: `app.appolon_factory.create_app`, `app.email.api`, `app.observability_alerts`, `app.qwen_auth_verifier`, `websocket_gateway.app`, and the entrypoint apps (`event_gateway`, `policy_engine`, `extension_allocator`, `telephony_provisioning`, `webphone_session_issuer`, `controller_api`, `server_a_agent`, `runtime`) | inventory `fastapi_apps` |
| Canonical database | PostgreSQL via `settings.database_url` (`postgresql+asyncpg://…`), engine in `app/db/session.py` (`async_sessionmaker(expire_on_commit=False)`); runtime reads `DATABASE_URL` from `/run/secrets/database_url` per service | `app/core/config.py`, `deploy/compose.runtime.yaml` |
| Canonical Redis | `settings.redis_url` (default `redis://localhost:6379/2`); used for replay guards, registry snapshot cache, social/sales signal queues, telephony worker coordination | `app/core/config.py`, `app/replay.py`, `app/core/endpoint_registry.py` |
| Second Settings lineage | `app/config.py` (`Settings`, 20 callers) coexists with `app/core/config.py` (`Settings`, 88 callers) | inventory |

## Persistence

| Metric | Value | Method |
| --- | --- | --- |
| Migration head | `0066_reconcile_odoo_campaign_scope` | `alembic heads`; `scripts.production_migration_authority.validate_authority` |
| Alembic revisions | 80 | `migration_history()` graph size |
| Migration history digest (after repair) | `sha256:b22709416fd7b8815cd0fb19cd86e43823684e9135aa0b79c036b97c425056a4` | `migration_history()` over LF bytes; pinned in `config/middleware-forward-release-authority.v1.json` and `config/runtime-sql-schema.v1.json` |
| Numbered SQL bundles | 12 (`migrations/*.sql`, `migrations/automation/*.sql`) | glob |
| Tables created by Alembic (net of drops) | 112 | regex over `op.create_table`/`CREATE TABLE` in `migrations/versions` |
| Tables created by SQL bundles | 34 | regex over bundles |
| Tables (union) | 146 | |
| ORM models | 63 (`app.db.models` Base) + 9 (`app.db.recording_models` Base) + 16 (`app.email.models` Base) = 88 across three declarative bases | `Base.registry.mappers`, AST |
| Tables without an ORM model in `app.db.models` | 83 | set difference (listed in the inventory) |

## API surface

| Metric | Value | Method |
| --- | --- | --- |
| `APIRouter` instances in `app/` | 68 | AST |
| Route-bearing modules in `app/` | 77 | AST |
| Routes mounted by `app.main` | 369 (349 OpenAPI paths) | route walk expanding lazily included routers |
| Routes mounted by `integration_api` | 275 (261 OpenAPI paths) | same |
| Public operations (contract v2) | 92 operations: 80 `shared_edge`, 2 `private_only`, 10 `denied` | `deploy/public-api-route-contract.json` |
| Public operations mounted (method+path match) | 80 in `integration_api`, 80 in `app.main` | route walk ∩ contract |
| Internal / non-contract operations | 195 in `integration_api`, 289 in `app.main` | route walk − contract |
| OpenAPI digest `integration_api` | `34b8e60558660afab91023d0793ed50ccdc1b1713d052748043cf4a88dfc9f62` | sha256 of canonical JSON of `app.openapi()` |
| OpenAPI digest `app.main` | `87cadfaec7df370705d4c75556c39fcd874364e737dcbeeac1a96c407bf57aa5` | same — the two applications do not expose the same API |
| Health endpoints | `GET /healthz`, `/health`, `/health/live`, `/health/dependencies`, `/api/v1/integrations/odoo/health`, `/v1/observability/services/{service_id}/health`, `/platform/v1/tenants/{tenant_id}/health`, `/platform/v1/campaigns/{campaign_id}/health` | route walk |
| Readiness endpoints | `GET /readyz`, `/health/ready`, `/ready` (integration_api only), `/readiness` (main only), `/api/v1/integrations/odoo/health` | route walk |
| Metrics endpoints | `WEBSOCKET /metrics` (route walk reports the Prometheus mount as a websocket-less mount), `GET /platform/v1/queues/{queue_id}/metrics`, `GET /api/v1/crm-vicidial/reconciliation/metrics`, `POST /v1/observability/metrics/query`, `/query-range`; Prometheus scrape on compose healthcheck `http://127.0.0.1:8095/metrics` | route walk, `deploy/compose.runtime.yaml:260` |

## Components

| Metric | Value | Method |
| --- | --- | --- |
| Adapter modules | 40 (`app/adapters/**`, `app/providers/**`, `app/integrations/**`, `app/*_adapter.py`, `app/*_transport.py`) | AST |
| Worker modules | 32 (`app/workers/**`, `workers/**`, entrypoints calling `run_worker`) | AST |
| Entrypoint modules | 28 in `app/entrypoints/` (excluding the shared `runtime` module) | listing |
| Deployed services (compose) | 20 (`middleware-event-gateway`, `-integration-api`, `-klyrow-mail-odoo-worker`, `-scraper-odoo-delivery-worker`, `-policy-engine`, `-sync-worker`, `-notification-worker`, `-n8n-runtime-worker`, `-social-n8n-delivery-worker`, `-postly-polling-worker`, `-reconciliation-worker`, `-scheduler`, `-odoo-result-worker`, `-odoo-campaign-saga-worker`, `-evidence-runner`, `-extension-allocator`, `-telephony-provisioning`, `-vicidial-adapter`, `-pjsip-adapter`, `-webphone-session-issuer`, `-vicidial-odoo-projection`) | `deploy/compose.runtime.yaml` |
| Test files / collected tests | 301 / 3398 | `pytest --collect-only -q` |
| CI workflows | 55 (`.github/workflows/*.yml`); `required-ci.yml` is the exact-SHA required gate | listing |
| Runtime Python modules inventoried | 433 (`app/`, `workers/`, `scripts/`, `websocket_gateway/`) | AST |

## Live-write defaults

Every boolean setting that gates an external effect defaults to `false` (60 flags measured in
`app/core/config.py`, e.g. `live_writes_enabled`, `odoo_write_enabled`, `odoo_automation_writes_enabled`,
`odoo_result_delivery_enabled`, `odoo_campaign_saga_enabled`, `vicidial_write_enabled`, `klyrow_write_enabled`,
`telnexa_write_enabled`, `allow_live_email`, `allow_live_sms`, `external_dial_enabled`, `openai_provider_enabled`,
`elevenlabs_provider_enabled`, `n8n_production_workflows_enabled`, `outbox_worker_enabled`). The compose runtime
repeats `ODOO_RESULT_DELIVERY_ENABLED: "false"` and `ODOO_CAMPAIGN_SAGA_ENABLED: "false"`. Migration 0066 seeds
production Odoo write routes with `kill_switch=true`. `ODOO_CAMPAIGN_READER_CLIENT_IDS` and
`N8N_CAMPAIGN_SERVICE_CLIENT_IDS` default to empty (nobody authorized).

## Current command systems (all coexisting)

| System | Where | Persistence | Notes |
| --- | --- | --- | --- |
| Durable command/operation ledger | `app/commands.py`, `app/api/v1/commands.py`, `app/operations.py` | `telephony_command_journal`, `telephony_operation_journal`, `_transition`, `telephony_terminal_result`, `telephony_reconciliation_run` | 22 callers, 26 test files; strongest candidate for the command core |
| Telephony commands | `app/core/telephony_commands.py`, `app/workers/telephony_commands.py`, `app/adapters/telephony/client.py` | ledger tables + Redis coordination | claim → dispatch → readback → finalize with leases |
| `/v2/automation` jobs | `app/automation_v2.py` (2763 LOC) | automation tables (SQL bundles) | public contract surface; job claims, mirrored mutations |
| v1 automation | `app/api/v1/automation.py`, `app/automation_policy.py` | `integration_event`, `idempotency_record` | deprecated markers |
| Odoo gateway commands | `app/api/v1/integrations.py` (`/odoo/commands` placeholder returns static `queued`) | none for the placeholder | stub |
| Control envelope | `app/api/v1/control.py`, `app/control_api.py` (Appolon lineage) | mixed | duplicate control semantics |
| Approved-order orchestration | `app/api/v1/orders.py`, `app/order_orchestration.py` | in-memory `STORE` | non-durable; superseded |
| AI commands | `app/api/v1/ai_commands.py`, `app/core/ai_jobs.py`, `app/api/internal/ai_jobs.py` | AI job tables with leases and fencing tokens | durable |
| Communications commands | `app/communications.py` | communications tables | durable |
| Calling facade | `app/calling_ledger.py`, `app/telephony_api.py` | ledger + Temporal outbox | Temporal leg not deployed |
| Campaign-control saga | `app/odoo_campaign_saga.py` | `odoo_campaign_saga` | Odoo-authoritative, readback-closed |

## Current event transports

| Transport | Where | Status |
| --- | --- | --- |
| PostgreSQL outbox (`outbox_event`, `integration_delivery`) | `app/workers/outbox.py` (state machine), `app/workers/delivery.py`, `workers/run_outbox.py` + `app/worker.py` (second runner) | deployed via reconciliation/scheduler workers; two runner lineages |
| PostgreSQL inbox / immutable event ledger | `app/storage.py` (`PostgresInboxStore`, `EventLedgerRecord`), `app/api/internal/klyrow_events.py`, `app/api/v1/publisher.py`, `app/api/v1/events.py` | deployed |
| Odoo transactional outbox (pull) | `app/adapters/odoo/sync.py` (claim/persist/ack) | deployed as `middleware-sync-worker`, disabled by flag |
| NATS JetStream | `app/nats_transport.py`, `app/eventing/jetstream.py`, `app/entrypoints/jetstream_dlq_worker.py` | example compose only; two publisher implementations |
| Temporal | `app/temporal_*`, `workers/run_temporal.py` | not in the deployed compose |
| Redis signal queues | `app/social/queue.py`, `app/sales/queue.py`, `app/core/runtime_redis.py` | deployed (social/sales), PostgreSQL authoritative |
| HTTP webhooks (in) | `app/api/v1/provider_webhooks.py` (HMAC + timestamp), `app/api/v1/events.py` (HMAC + nonce), `app/api/internal/*` (JWT), `app/webhook_api.py` | deployed |
| HTTP callbacks (out) | `app/core/service_client.py` (registry-resolved), n8n/Odoo/Klyrow/Telnexa adapters | deployed, gated |
| WebSocket | `app/api/v1/agent_realtime.py`, `websocket_gateway/app.py` | deployed |

## Current idempotency implementations

| Implementation | Where | Store |
| --- | --- | --- |
| `IdempotencyRecord` (scope + key hash + request hash + cached response) with `pg_advisory_xact_lock` | `app/api/v1/integrations.py`, `app/api/v1/provider_webhooks.py`, `app/db/models.py` | PostgreSQL |
| `PublisherNonce` (key_id + nonce PK) | `app/api/v1/events.py`, `app/api/v1/publisher.py` | PostgreSQL |
| Unique `integration_event.original_event_id` + payload-hash conflict | `app/adapters/odoo/sync.py`, `app/storage.py` | PostgreSQL |
| Unique `odoo_campaign_saga.integration_event_id`, readback idempotency key per observation | `app/odoo_campaign_saga.py` | PostgreSQL |
| `Idempotency-Key` header on every outbound mutation | `app/core/service_client.py` | header |
| `ReplayGuard` (Redis / memory) | `app/replay.py` | Redis |
| `IdempotencyDecision` / `canonical_hash` | `app/core/automation.py` | pure |
| `IdempotencyLedger` (in-memory) | `app/core/reliability.py`, `app/core/appointments.py`, `app/core/ivr.py`, `app/core/transcription.py` | memory (unwired) |
| `NonceLedger` (scraper HMAC) | `app/sales/auth.py` | memory/Redis |
| Recording `ReplayGuard` | `app/recording/security.py` | memory |

## Current reconciliation implementations

| Implementation | Where | Scope |
| --- | --- | --- |
| Internal outbox reconciliation worker | `app/workers/reconciliation.py`, `app/entrypoints/reconciliation_worker.py` | outbox/delivery rows |
| Telephony reconciliation runs | `app/api/v1/commands.py`, `telephony_reconciliation_run` | command ledger |
| Odoo result delivery readback + stale-reservation recovery | `app/adapters/odoo/results.py` | deliveries |
| Campaign actual-state readback (saga) | `app/odoo_campaign_saga.py`, `app/adapters/odoo/campaign_control.py` | campaign control |
| VICIdial→Odoo lifecycle sync | `app/vicidial_odoo_projection_lifecycle_sync.py` | call lifecycle |
| CRM/VICIdial lead identity reconciliation | `app/core/lead_reconciliation.py` (no runtime callers), `app/api/v1/lead_reconciliation.py` | leads |
| Sales identity matching | `app/sales/identity.py` | leads |
| Monitoring sync/reconciliation | `app/monitoring/routes.py` (`/platform/v1/sync/*`) | configuration vs runtime evidence |
| `Reconciler` primitive | `app/core/reliability.py` | in-memory, unwired |

## Current audit implementations

| Implementation | Where |
| --- | --- |
| `AuditEvent` rows (action, subject, correlation, decision, redacted payload) | `app/db/models.py`; written by integrations, provider webhooks, Odoo sync, campaign saga, callbacks |
| Immutable event ledger (`EventLedgerRecord`, integrity errors) | `app/storage.py`; verified by `scripts/verify_event_ledger.py` |
| Quarantine (encrypted payloads, privileged reviewer surface) | `app/core/quarantine.py`, `app/api/v1/quarantine.py` |
| Monitoring store events with replay evidence | `app/monitoring/store.py` |
| Sales audit records | `app/sales/service.py` |
| Calling ledger | `app/calling_ledger.py` |
| Recording playback audit | `app/db/recording_models.py` |

## Current tenant isolation mechanisms

- Claim-based scope checks: `campaigns`/`campaign_scope`, `business_units`/`business_unit_scope`, `tenant_id` claims compared to request/event scope (`app/api/v1/integrations.py` `_scope_values`, `_require_campaign_claim`, `_require_context_binding`; `app/core/jwt_auth.py` `required_business_unit`/`required_campaign`).
- Registry route bindings scoped by organization/business unit/campaign with precedence scoring (`app/core/endpoint_registry.py`); staging Odoo writes bound to `TEST_SYN_TENANT/TEST_SYN/TEST_SYN` by migration 0066.
- Fixed-tenant policy for the alerts app (`X-Tenant-ID` must equal the policy tenant, `app/observability_alerts.py`).
- Transaction-local PostgreSQL RLS context for callback data (`app/core/callback_rls.py`).
- Tenant-bound AI conversations/jobs (`app/api/v1/ai_console.py`, `app/core/ai_jobs.py`).
- Identical 404 for missing vs out-of-scope resources on the n8n readback and campaign command reads.

## Current identity / auth mechanisms

| Mechanism | Where | Notes |
| --- | --- | --- |
| Keycloak service JWT (`KeycloakValidator`: issuer, audience, `azp` allowlist, scopes, `environment`, BU/campaign) | `app/core/jwt_auth.py` (13 callers) | canonical validator; JWKS cached |
| Keycloak JWT (Appolon lineage `KeycloakJwtVerifier`, `TokenVerifier`, `SignedRequest`) | `app/security.py` (20 callers) | duplicate validator |
| Additional validators/principals | `app/email/security.py`, `app/monitoring/auth.py`, `app/core/platform_auth.py`, `app/core/provisioning_auth.py`, `app/control_plane_auth.py`, `app/campaign_design_api.py` | duplicated derivations |
| Shared-secret bearer guard (`middleware_secret`) for every `/api/*` and `/v1/*` route not delegated | `app/core/auth.py`, `app/main.py`, `app/entrypoints/runtime.py`, `app/core/route_policy.py` (shared exemption table) | |
| HMAC signatures: provider webhooks (`"{ts}." + body`), signed events (nonce + ts), scraper HMAC (`NonceLedger`), publisher HMAC, lead callback HMAC, GitHub webhook | `app/api/v1/provider_webhooks.py`, `app/api/v1/events.py`, `app/sales/auth.py`, `app/core/publisher_auth.py`, `app/core/lead_callback_auth.py`, `app/monitoring/routes.py` | |
| mTLS: VICIdial Server B client, recording exporter, private agents | `app/vicidial_internal_call_adapter.py`, `app/adapters/vicidial/mtls_client.py`, `app/recording/security.py`, `app/agent/security.py` | |
| Outbound client credentials (`TokenManager`, `ClientSecretTokenManager`, `service_tokens`) | `app/core/token_manager.py`, `app/core/service_tokens.py` | |
| Edge: Caddy → Kong (`openid-connect` per route) → Middleware | `deploy/public-api-route-contract.json` | Middleware still verifies every JWT itself |
