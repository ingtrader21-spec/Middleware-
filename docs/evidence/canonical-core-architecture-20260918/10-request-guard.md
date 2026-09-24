# 10 — The single request guard: `app/core/request_guard.py`

`RequestGuard` is the one HTTP middleware of every Middleware application (installed by `create_app` and by
`add_api_runtime` for the narrow processes). It replaces `app.main.control_request_guard`,
`app.entrypoints.runtime.request_controls` and the Appolon `observe_request`.

Order of decisions per request:

1. Content-Length parsing and the generic `REQUEST_MAX_BYTES` cap (400/413) — skipped for control-plane
   routes, whose handlers enforce `MAX_REQUEST_BODY_BYTES` with the canonical envelope (`read_limited_body`).
2. Correlation: a well-formed client `X-Correlation-ID` is echoed, otherwise a UUID; `x-kong-request-id`
   validated into `request.state.gateway_request_id`; `traceparent` validated.
3. `/api/v1/sales/*`: content type (415) and size (413) with the sales error shape.
4. Per-client rate limit on signed write routes (429, `Retry-After: 60`).
5. Shared-secret bearer for `/api/*` and `/v1/*` routes that do **not** authenticate in their handler:
   401, or 503 `authentication unavailable` when the process has no secret.
6. Routing, telemetry (`MiddlewareObservability`), `X-Correlation-ID` / `Cache-Control: no-store` /
   `traceparent` on the response, `request_complete` log line.

Handler-authenticated routes are declared, never inferred: `SIGNED_WEBHOOK_PATHS`, `SELF_AUTHENTICATED_PATHS`,
`SOCIAL_WEBHOOK_PATH`, `AI_CONSOLE_SELF_AUTHENTICATED_PATHS`, `N8N_TRANSITION_PATH`, `RECORDING_EXPORTER_PATH`,
`app.core.route_policy.handler_authenticated` (the shared service-JWT table checked against the edge contract),
and the compiled route patterns of the control-plane routers passed by the factory (`APPOLON_ROUTERS`, plus the
legacy aliases on the monolith). Monitoring and observability-sync routes keep their own JWT dependencies.

## Behaviour changes versus the three former guards

| Area | Integration API before | Canary before | Now |
| --- | --- | --- | --- |
| Correlation id | always regenerated | safe echo | safe echo, else UUID |
| `traceparent` | always generated | echo valid, drop invalid | echo valid, drop invalid, generate when absent |
| Validation errors | FastAPI 422 | 400 envelope everywhere | 400 envelope on control-plane routes; sanitized 422 on sales; FastAPI 422 elsewhere |
| `/metrics` | unauthenticated Prometheus mount | authenticated (`metrics.read`) | authenticated on every `create_app` profile; workers keep the mount |
| Body cap | 256 KiB everywhere | 1 MiB per route | 256 KiB on guarded routes, per-route 1 MiB on control-plane routes |
| Runtime unavailable | — | lifespan crash | control-plane routes answer 503 via `app.core.providers`; ORM routes unaffected |

Tests: `tests/test_n8n_jwt_guard_routing.py` (shared policy, no local copies), `tests/test_entrypoints.py::test_api_runtime_health_and_correlation`,
`tests/test_observability.py` (traceparent, correlation, metrics auth), `tests/test_lead_intake_api.py`
(content-length envelope, oversized body), `tests/test_sales_api.py` (415/413/422), `tests/test_readiness_challenge.py`
(rate limit windows via `app.state.request_guard.reset_rate_limits()`), `tests/test_booking_api.py`,
`tests/test_architecture_governance.py::test_single_request_guard`, staging-intake source contract (11).
