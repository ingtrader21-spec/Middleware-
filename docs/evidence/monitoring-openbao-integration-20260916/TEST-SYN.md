# TEST_SYN certification (2026-09-16)

Only `TEST_SYN` is referenced by any probe or contract. Nothing below was executed against a runtime in this mission; the procedure and the source hooks are complete.

## Procedure (staging)

1. One safe request: `GET /platform/v1/services/test-syn-api/monitoring-state` through Caddy -> Kong -> Middleware with `X-Correlation-ID: test-syn-<uuid>` and a `traceparent` (Keycloak staging token, scope `platform.services.read`).
2. Metric: `codestra_http_requests_total{service="middleware",campaign="TEST_SYN"}` visible in Prometheus through `codestra-middleware-metrics` (monitoring-readonly, `metrics.read`).
3. Sanitised log: the Middleware JSON log line for the request in Loki `{service="middleware"} | json | correlation_id="test-syn-<uuid>"` with `Authorization` redacted (structured metadata `correlation_id`, `trace_id`).
4. Trace: TraceQL `{ span.correlation.id = "test-syn-<uuid>" }` returns the Caddy -> Kong -> Middleware spans (contract `Codestra-Tempo/codestra/trace-propagation-contract.v1.json`; hop instrumentation owned by Caddy/Kong/Middleware/Odoo/N8N repositories, declared `planned`).
5. Controlled alert: `CodestraTestSynCertificationSignalMissing` (informational) fires when no TEST_SYN metric exists for 24 h; the certification run resolves it, or a synthetic firing is posted via `amtool` to the staging Alertmanager.
6. Middleware incident: Alertmanager -> `POST /v1/integrations/alertmanager/events` creates exactly one incident (a second delivery returns the same `incident_id`, `duplicate: true`); `GET /v1/observability/incidents/<id>/timeline` shows the same `correlation_id`.
7. Grafana drilldown: Middleware Operational Control Plane (incident row) -> Tempo trace by `correlation.id` -> Loki logs via derived fields.
8. OpenBao: the audit stream shows only the `middleware-api-staging` read of `codestra/staging/middleware/api/*` metadata (HMAC'd accessor, path, operation) — never a value; `OpenBaoAuthFailureSurge` stays silent.

## Certification write-back

`POST /platform/v1/services/test-syn-api/monitoring-state/certification` with all evidence flags true is accepted only when the catalog state is `synced` and fresh; it records `certified` with the evidence hash in `platform_service_monitoring_audit`.

## Status

`STAGING_MONITORING_GO=NO` — no staging Middleware, Keycloak, OpenBao, Prometheus, Loki, Tempo, Alertmanager or Grafana was reachable from this session, and GitHub Actions could not run.
