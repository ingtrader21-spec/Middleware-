# Middleware intake runtime v1

> **Status (2026-09-20):** the canonical Alembic head is now
> `0069_agent_provisioning_rls` (`config/middleware-forward-release-authority.v1.json`,
> `.github/workflows/release.yml`). References to `0057_platform_service_catalog` below
> describe the signed evidence generation of 2026-09-08 and are retained as history; they
> are not the current forward release or runtime requirement.

This branch converts the reviewed middleware ingress contracts into executable FastAPI source without enabling any external delivery.

## Runtime surface

Health:

- `GET /health`
- `GET /ready`
- `GET /version`
- `GET /metrics` (Keycloak `monitoring-readonly` client with `metrics.read`)
- `GET /v1/runtime/safety` (Keycloak `monitoring-readonly` client with `health.read`)

Authenticated signed ingress:
- `POST /api/v1/odoo/events`
- `POST /api/v1/n8n/results`
- `POST /api/v1/vicidial/events`
- `POST /api/v1/telnexa/events`
- `POST /api/v1/klyrow/events`
- `POST /api/v1/kyqra/results`
- `POST /api/v1/kyqra/progress`
- `POST /api/v1/postly/events`

The route set is loaded from `config/api-webhook-contracts.json`; code and contract cannot silently drift.

## Operational evidence

`/health` proves only that the API process can answer. `/ready` performs bounded,
parallel checks of the inbox store, replay guard, Keycloak JWKS, and command store;
it returns `503` with named component states if a mandatory dependency is not ready.
The response includes immutable release and migration identity but never connection
strings, credentials, tenant data, or dependency exception text.

`/metrics` exports low-cardinality Prometheus request, latency, active-request,
authentication-denial, readiness, process-start, and release-identity series. The
endpoint is not anonymous: the caller must be the existing `monitoring-readonly`
service identity and hold `metrics.read`. Metric labels use route templates and do
not include tenant, event, idempotency, correlation, or payload values.

`/v1/runtime/safety` requires the monitoring identity's `health.read` scope and
returns only effective non-secret controls from the running process. The
staging acceptance gate validates this response against
`contracts/runtime-safety-readback.v1.1.schema.json` before it submits a
synthetic event.

Every HTTP response receives a validated or server-generated `X-Correlation-ID`.
A valid W3C `traceparent` is propagated; malformed values are dropped. Completed
requests are logged as structured JSON with safe operation names and release
identity, without headers, bodies, tokens, customer data, or raw URLs.

## Security

Every ingress request must pass all of these checks before durable acceptance:

1. canonical Keycloak issuer `https://auth.codestra.co/realms/codestra`;
2. audience exactly `middleware-api`;
3. `azp` exactly matches the producer assigned to the route;
4. the route's least-privilege scope is present;
5. all required signed-webhook headers are present;
6. timestamp is inside the configured maximum skew (maximum 300 seconds);
7. HMAC-SHA256 signature matches the exact raw body and canonical request fields;
8. header event, tenant, source, correlation and idempotency values match the body;
9. event type is explicitly allowed for that producer/route.

Webhook HMAC secrets are separate per producer and must be injected outside Git.

## Durable inbox and replay behavior

Production/staging require PostgreSQL and Redis.

PostgreSQL is the correctness boundary. `middleware_inbox` has unique constraints for tenant/event and tenant/idempotency key. An identical retry returns the original logical result as `duplicate=true`; reusing the same event/idempotency identity with a different body is a `409`.

Redis is a short lease guard against concurrent duplicate processing. PostgreSQL remains authoritative if Redis state expires.

Apply every numbered migration through `0057_platform_service_catalog` before
starting a non-test runtime.

## Outbox, JetStream, retry and DLQ

The same PostgreSQL transaction that accepts a new inbox event now creates its `nats-jetstream` outbox row. The store and worker implement `FOR UPDATE SKIP LOCKED`, bounded exponential retry, lease ownership, unknown-outcome quarantine, and dead-letter transition. JetStream publication uses a domain-separated `codestra.events.*` subject and a deterministic `Nats-Msg-Id`; the outbox is completed only after the server acknowledges the publish.

`workers/run_outbox.py` registers only the NATS JetStream transport. Provider, Odoo, n8n, telephony, SMS, email, social, and crawler writes are not registered. Dispatch requires `SEND_EVENTS=true`, `OUTBOX_DISPATCH_ENABLED=true`, and a non-disabled `NATS_DISPATCH_MODE` together. Production additionally requires `PRODUCTION_ACTIVATION_ID`, an exact immutable release identity, TLS, and a mounted NATS service credential.

Since the canonical configuration authority (`app/core/config.py`) merged both settings lineages, `SEND_EVENTS` gates only this JetStream outbox transport. The separate n8n broad-event pipeline is gated by its own first switch `BROAD_EVENT_SEND_ENABLED` together with `BROAD_EVENT_DELIVERY_ENABLED`, `PRODUCTION_N8N_ENABLED`, `N8N_PRODUCTION_WORKFLOWS_ENABLED` and a bounded `CONTROLLED_BROAD_EVENT_ACTIVATION` scope; the two gates never imply each other. Every deployed profile keeps all of them disabled. See `docs/architecture/canonical-core-migration.md`.

Staging may exercise the event plane only with `NATS_DISPATCH_MODE=isolated`, stream `CODESTRA_STAGING_EVENTS`, and subjects below `codestra.staging.events.*`. It cannot use the production stream or subject namespace, and provider/business delivery flags remain disabled. `NATS_ALLOW_INSECURE_TEST_CONNECTION` exists only for a disposable localhost server in test/development; staging and production require TLS and a mounted service credential.

## Fail-closed runtime

In staging/production:

- the environment-specific runtime profile and resource identities must match;
- in-memory storage is prohibited;
- PostgreSQL and Redis are required;
- all provider/business external-effect flags must be false;
- JetStream dispatch is disabled unless separately production-authorized;
- API docs are disabled;
- the application fails startup on unsafe or incomplete configuration.

This branch does not add Kong routes, mutate Keycloak, change Odoo/n8n/provider systems, or deploy to Server A. Deployment requires a separate reviewed exact-SHA staging change.
