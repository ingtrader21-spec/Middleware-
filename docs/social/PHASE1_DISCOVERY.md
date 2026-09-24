# Phase 1 discovery

## Scope and repository

- Execution host: Middleware Server A (`65.109.65.169`), inspected without runtime mutation.
- Repository: `Codestra-SRL/codestra-middleware`; baseline `main` at `4bc12bf`.
- Isolated branch: `agent/social-publishing-middleware`. A separate checkout contained unrelated sales-lead changes and was not modified.
- Framework: Python 3.12, FastAPI, Pydantic Settings, async SQLAlchemy/asyncpg, Alembic, Redis, httpx and Prometheus.

## Reusable platform patterns

- API routes live in `app/api/v1` and are registered in `app/main.py`.
- Persistence uses SQLAlchemy models plus linear Alembic migrations. Durable outbox records use PostgreSQL as source of truth.
- Redis is already the runtime dependency used for asynchronous work; social jobs follow the same database-first/Redis-notification pattern.
- `IntegrationEvent`, durable outbox, retry, lease recovery and dead-letter implementations already exist. Social events are normalized for later projection into that contract rather than introducing a second general event bus.
- n8n and Odoo deliveries are middleware-owned and feature gated. Social n8n and Odoo flags remain off; no provider calls either system directly.
- Global API bearer authentication, request size limits, HMAC verification patterns, replay windows, safe error redaction and secret-file loading already exist.
- Correlation IDs are returned by middleware and persisted by established jobs/outbox records. Social commands additionally preserve request/job/post/provider identifiers.
- Prometheus is mounted at `/metrics`. Existing labels avoid PII.
- Feature switches default off and `Settings.validate_safety()` rejects write switches, including social publish and social Odoo writes.
- CI runs Python 3.12, pinned dependencies, Ruff, mypy, full pytest, Alembic upgrade/downgrade, Docker build, secret scanning and exact-SHA checks.
- Docker uses a multi-stage test/runtime image; deployment targets are explicitly approval-gated.

## Existing Postiz integration

`app/integrations/postiz` contains a safe, disabled-by-default client and compatibility routes. It already handles timeout/network errors, 429, authentication, provider 4xx/5xx and secret-file API keys. It was retained and wrapped by `PostlyProviderAdapter`; provider payloads no longer need to enter business-facing APIs.

## Decisions

1. Codestra UUIDs remain canonical; provider IDs are nullable external references paired with an immutable provider owner.
2. Historical posts resolve through `social_posts.provider`, never the runtime default.
3. PostgreSQL is authoritative for jobs/idempotency/audit; Redis only signals job availability.
4. Hootsuite is contract-complete but reports `NOT_CONFIGURED`/`DISABLED`; it never returns fake success.
5. Public endpoints are provider-neutral. Provider metadata is an opaque optional map.
6. Webhooks are self-authenticated only at their narrow route and must pass provider verification, replay-window validation, schema normalization and deduplication before dispatch.
7. Phase 1 performs no deployment, provider publishing or Odoo writes.
