# Integrated monitoring API

The 36 operations extend the existing platform and alert APIs. They are registered on `app.main`, `app.entrypoints.integration_api` and `app.appolon_factory.create_app`. The extension owns original-JWT validation; legacy shared-secret guards exempt only its exact registered method/path pairs.

Host details filter the requested host in the database before keyset pagination.
Host and generic integration detail reads accept `cursor` and `limit` (1–200)
and return `next_cursor` when more observations exist. A generic integration
observation's `resource_id` must equal its configured integration ID; details
include only that ID within the authorized tenant and service.

OpenAPI imports read regular files beneath the configured artifact root through
directory descriptors. The root and each artifact path component must not be a
symbolic link. Reads enforce the byte budget and approved SHA-256 before parsing.
Alembic includes monitoring metadata and its scoped indexes in autogeneration.

## Configuration and identity

Apply Alembic `0059_integrated_monitoring` after `0058_campaign_design` before enabling ingestion. Runtime uses the existing async PostgreSQL session and never creates tables at startup. Mount `MONITORING_CONFIG_FILE` as a reviewed JSON release artifact; missing configuration returns 503. Set the existing Keycloak issuer, audience, JWKS URL and authorized-party settings. JWT claims include `sub`, `azp`, `tenant_id`, `realm_access.roles`, `scope` and, for collectors, approved `services`/`campaigns`.

| Configuration key | Required contents |
| --- | --- |
| `schema_version`, `revision` | Integer 1 and approved release revision |
| `repositories` | Records containing repository name, tenant and release/CI evidence |
| `services` | Map keyed by service ID, with tenant, repository, environments, dependencies, required signals/components, approved config digest |
| `services.*.observation_sources` | Deployment ID → authorized client and environments; retire old sources in approved configuration |
| `services.*.browser_bff_clients`, `browser_origins` | Exact authorized BFF clients and allowed origins |
| `backends` | Prometheus/Loki/Tempo/OpenBao/Blackbox/Backstage/Sentry/Wazuh bindings: `base_url`, optional `token_file`, optional `ca_file`; Loki/Tempo require `tenant_map` |
| `queries` | Reviewed query IDs with `family`, allowed `services` and query containing `${tenant}`, `${service}`, `${environment}` placeholders |
| `artifact_root`, `artifacts` | Approved local root and artifact IDs bound to service, environment, relative path and SHA-256; no remote contract fetching |
| `probe_targets` | Target IDs bound to service, environment, approved URL and Blackbox module |
| `integrations` | Integration IDs bound to service and backend; Sentry also needs organization/project |
| `github.secret_file` | Release-mounted webhook HMAC secret |

Backend URLs, project identities, tenants and query expressions are release configuration, never request-supplied destinations. TLS verification is mandatory; an existing protected private HTTP listener requires explicit `private_network_http: true`. Backstage/Sentry/Wazuh tokens are read from files; issue/agent results expose only selected metadata. Wazuh token renewal belongs to the release identity service. Ensure backend identities can access only their registered tenant/project; shared Backstage or Wazuh administration must be confined to the platform tenant.

Metrics use reviewed PromQL templates, logs use reviewed LogQL and trace search uses reviewed TraceQL. All three placeholders must constrain every selector in a template; a template containing an unscoped alternate selector is invalid release configuration. Trace-by-ID requests use the JWT tenant's Tempo organization mapping. Configure backend tenancy enforcement, distinct tenant mappings, query quotas, retention and gateway rate limits before rollout. Requests time out after five seconds, responses are capped at 2 MiB and metric results at 10,000 points.

## Semantics

Writes require bounded `Idempotency-Key` and `X-Correlation-ID` headers. Reusing a key with a different request returns 409. Resource revision, event and replay response commit together. Telemetry also requires increasing source sequence and observation time. Missing observations are unknown; evidence older than 90 seconds is stale. Heartbeat signals are collector reports, not independent proof of delivery to every backend.

Profiles are staged revisions. Reconciliation persists a comparison against the approved release and fresh component observations, returning `runtime_mutated: false`. Actual apply/rollback continues through the existing approved deployment authority. GitHub webhook ingestion validates the exact raw body and registered repository, records minimal evidence and never authorizes deployment or rewrites the approved catalog.

Browser events require an authorized BFF identity, service binding and exact Origin; the browser receives no backend credentials. Serve the BFF on the application's origin and enforce body/rate/cardinality budgets at ingress. SSE returns up to 100 persisted events per connection and a 30-second reconnect instruction; use `Last-Event-ID` and a freshly authorized BFF connection. It is not an unbounded in-memory event bus.

## Verification and release

`pytest -q tests/test_integrated_monitoring.py` exercises all 36 method/path pairs and negative authorization, replay, ordering, persistence, backend failure and entrypoint behavior. By default it applies the real migration to disposable SQLite. Set `MONITORING_TEST_DATABASE_URL` to a disposable `monitoring_test*` PostgreSQL database to execute the same suite and concurrent replay test on PostgreSQL. The fixture deletes only its three test tables afterward; never use a production URL. CI supplies an isolated PostgreSQL container.

Generate/check the contract with `python scripts/generate_integrated_monitoring_openapi.py [--check]`. Existing platform, incident and product authorization tests remain independent regression gates.

Before production: independent review and exact-SHA CI; immutable release; migration backup and rehearsal; approved catalog/identities and private ingress; per-app instrumentation and collectors; synthetic signal/alert/restore evidence. Preserve the new audit/replay tables during application rollback. Downgrade locks all three tables and refuses to remove any nonempty evidence. Empty tables support the existing isolated downgrade/reupgrade rehearsal. No live deployment or universal application connectivity is established by the source tests.
