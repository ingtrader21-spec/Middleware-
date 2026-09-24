# Service catalog monitoring state

Middleware is the operational control plane: it owns the service catalog,
monitoring desired and observed state, certification state, incidents,
Alertmanager ingestion, delivery intent and read-back, correlation, audit and
reconciliation. It is never a metrics, log or trace database, and it never
stores a secret value.

## Catalog descriptor (Alembic `0067_service_catalog_monitoring_state`)

`POST /platform/v1/services` and `PATCH /platform/v1/services/{service_id}`
accept, in addition to the existing fields, the monitoring descriptor the
integrated monitoring design proposes:

| Group | Fields |
| --- | --- |
| Identity | `deployment_id`, `host_id`, `instance_id` (a stable `service_id` stays separate from where it runs) |
| Origins | `public_origin`, `private_origin` (declared from deployment configuration, never derived from a repository name) |
| Contract paths | `liveness_path`, `readiness_path` (defaults to `health_path`), `metrics_path`, `openapi_path` |
| Collection owners | `metrics_profile` (`prometheus`/`otel`/`not-applicable`), `logs_profile` (`alloy`/`otel`/`not-applicable`), `traces_profile` (`otel`/`not-applicable`) |
| Bindings | `prometheus_target_id`, `blackbox_target_id`, `grafana_dashboard_ids` |
| Expected release identity | `expected_git_sha`, `expected_image_digest`, `expected_config_digest`, `expected_migration_head` |
| Observed release identity | `observed_git_sha`, `observed_image_digest`, `observed_config_digest`, `observed_migration_head` — written only by `POST .../monitoring-state/observations` |
| Secret references | `secret_references[]` — `app.secret_reference.SecretReference` objects (pointer only) |
| State | `monitoring_state`, `monitoring_state_reason`, `last_observed_at`, `last_observation_source`, `last_certified_at`, `last_certified_by` |

Every transition is written to `platform_service_monitoring_audit` with the
actor, correlation id and the sha256 of the evidence that justified it. The
migration's downgrade refuses to drop the audit table while it holds rows.

## Monitoring states

```text
unregistered → registered → pending → synced → certified
                              ↓         ↓         ↓
                            unknown   drifted   (re-derived on every observation)
                            applying / failed   (reported by the collector)
```

| State | Meaning |
| --- | --- |
| `unregistered` | not in the catalog |
| `registered` | approved descriptor imported; no expected release identity, or nothing observed yet without one |
| `pending` | expected release identity declared; no runtime observation yet |
| `applying` | an authorized collector reported an apply in progress |
| `synced` | every declared expected field equals fresh (≤ 15 min) runtime evidence |
| `drifted` | fresh evidence differs from the expected identity (fields named in the reason) |
| `failed` | the collector reported a failed apply or read-back |
| `unknown` | evidence stale, partial or absent for a declared expectation |
| `certified` | granted by a `platform_admin`/`platform_reviewer` with runtime proof; kept only while synced and fresh |

`app.platform_catalog_monitoring.derive_state` is the single implementation.
A Git descriptor alone never yields `synced`; an HTTP 200 never yields
`synced`; certification never comes from configuration existing.

## Endpoints (private network, not edge-routed; same class as the catalog CRUD)

| Operation | Scope / role | Purpose |
| --- | --- | --- |
| `GET /platform/v1/services/{id}/monitoring-state` | `platform.services.read` | expected vs observed per field, derived state, freshness, bindings, references (never values), last 20 audit rows |
| `POST /platform/v1/services/{id}/monitoring-state/observations` | `platform.runtime.observe` (`platform_operator`/`platform_admin`), `X-Correlation-ID` required | collector read-back of git SHA / image / config / migration head; refuses observations older than the last one (delayed evidence never overwrites newer state); `status: applying|failed` supported |
| `POST /platform/v1/services/{id}/monitoring-state/certification` | `platform.services.write` (`platform_admin`/`platform_reviewer`), `X-Correlation-ID` required | 409 with the blocker list unless synced, fresh, targets and dashboards bound, and every applicable evidence flag (`health_endpoints`, `metrics_scraped`, `logs_received`, `traces_received`, `alert_route_test`, `dashboards_bound`, `secret_references_reconciled`) is true |

Changing an expected field through `PATCH` re-derives the state; a certified
service whose desired release changes falls back until fresh evidence matches.

## Per-component reconciliation

`GET /platform/v1/sync/status` and `POST /platform/v1/sync/reconciliations`
now return `component_states` beside the existing `state`: each required
component (Prometheus targets/rules, Alertmanager configuration, Grafana
datasources/dashboards, Loki, Tempo, Alloy, OpenBao health, exporters,
Blackbox) is `pending`, `applying`, `synced`, `drifted`, `failed` or
`unknown`, from a fresh `config` observation carrying the active
configuration digest (and optionally `status`). A component without a fresh
digest read-back is `unknown`, never `synced`. The service `state` folds the
component states worst-first (`failed` > `applying` > `unknown` > `drifted` >
`synced`; `pending-release-approval` when the desired digest is not yet the
approved one), so an unreachable Prometheus or a collector-reported failure
can never leave a service `synced`.

## Monitoring collector (runtime wiring)

`app/monitoring/collector.py` / `python -m scripts.monitoring_collector
--config /abs/collector.json --output /abs/dir` is the read-only runtime half
of the reconciler. From a profile such as
`config/monitoring/collector.staging.v1.json.example` it reads, with GET only,
verified TLS and no redirects: Prometheus `/-/ready`, `/api/v1/status/config`
(digest of the *active* YAML), `/api/v1/targets` (health, last scrape,
freshness), `/api/v1/rules`; Alertmanager `/-/ready`, `/api/v2/status`
(`config.original` digest), `/api/v2/alerts`; Grafana `/api/health`,
`/api/datasources` + per-datasource health, `/api/search?type=dash-db`
(digest of the datasource/dashboard binding) with a read-only service-account
token file; Loki `/ready`, `/config`, `/loki/api/v1/labels` (bounded label
count) with `X-Scope-OrgID`; Tempo `/ready`, `/status/config`; Alloy
`/-/ready`, `/api/v0/web/components`; the OTel gateway health extension;
OpenBao `/v1/sys/health` (sealed/standby recorded, never unsealed); and each
exporter's `/metrics` sentinel (`node_exporter_build_info`,
`cadvisor_version_info`, `redis_up`, `pg_up`,
`blackbox_exporter_build_info`). It then posts one `config` observation per
(service, component) to `POST /platform/v1/runtime/observations` with
monotonic per-resource sequences, `Idempotency-Key` and `X-Correlation-ID`
(a component that could not be read is posted as `status: failed`, never
omitted), reads `/version` to post `observed_git_sha` /
`observed_image_digest` / `observed_migration_head` to
`POST /platform/v1/services/{id}/monitoring-state/observations`, and writes a
redacted `collector-report.json` plus the Section-10 `target-records.md`
(expected vs actual endpoint, environment, service_id, authentication
method, scrape status, last-scrape age, freshness, contract SHA). Tokens come
only from absolute 0600 files; if Middleware is unreachable or answers 5xx the
run fails closed without advancing sequence state; a report that would
contain secret-shaped material is refused (`tests/test_monitoring_collector.py`).

## TEST_SYN certification runner

`python -m scripts.certify_test_syn --output /abs/dir` performs the eight
fail-closed steps of the TEST_SYN end-to-end certification from environment
variables whose credentials are `*_FILE` paths: runtime-safety read-back
(staging profile, exact SHA/digest, every effect control off), one signed
TEST_SYN event through the public edge (Caddy → Kong → Middleware, 202 then
200 duplicate, carrying `traceparent` and `X-Correlation-ID`), trace
propagation in Tempo (caddy/kong/middleware spans sharing the correlation id;
odoo/n8n reported as observed or planned, span links counted), log
correlation in Loki (the line for the correlation id carries the trace id and
no secret-shaped content), metrics freshness in Prometheus (middleware target
up on 8095, never 8080, scraped within 90 s, request counter moved), alert
ingestion (an informational synthetic alert posted twice to Alertmanager
yields exactly one Middleware incident), dashboard read-back (Grafana
Middleware datasource healthy, required dashboards present, observability
overview answering the monitoring-readonly token) and no business effect
(runtime safety and provider-effect counters unchanged). Evidence
`test-syn-certification.json` carries `TEST_SYN_GO=YES|NO` and is refused if
it would contain a credential (`tests/test_certify_test_syn.py`).

## Failure modes (source certification)

`tests/test_monitoring_failure_modes.py` proves that Middleware readiness
never consults a telemetry backend; that a Prometheus/Loki/Tempo outage
answers 503 and never fabricates data; that no observation, a stale
observation or a collector-reported failure yields `unknown`/`failed`, never
`synced`; and that a sealed OpenBao is reported without any unseal attempt.

## Secret references

`contracts/secrets/secret-reference.v1.schema.json` is the OpenBao-owned
contract vendored byte-for-byte and pinned by canonical sha256
(`scripts/validate_secret_reference_contract.py [--openbao-repo …]`).
`SecretReference` rejects, at any depth, `value`, `password`, `token`,
`private_key`, `client_secret`, `secret`, `secret_value`, `unseal_key`,
`recovery_key`, `root_token`, any `*_password|*_token|*_secret` key and any
secret-shaped string; it requires `secret_ref` to lie inside its own
environment, derives `reference_uri = openbao:// + secret_ref`, and the
catalog additionally requires the environment to be one the service declares.
Middleware may hold `rotation_status`, hashed lease metadata and
reconciliation timestamps; no Middleware API resolves a reference.

## Alertmanager → incidents

Unchanged and reused: `POST /v1/integrations/alertmanager/events` and
`/status-events` with fingerprint deduplication, idempotency keys, source
timestamps, suppression reconciliation and tenant/environment isolation
(`tests/test_observability_alerts.py`: a replayed delivery returns the same
`incident_id` with `duplicate: true`). Incident lifecycle stays under
`/v1/observability/incidents/*`.
