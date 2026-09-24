# TEST_SYN certification (2026-09-17)

Runner: `Middleware-/scripts/certify_test_syn.py` (`python -m scripts.certify_test_syn --output /abs/dir`), unit-proven by `tests/test_certify_test_syn.py` (13 tests, fake platform behind `httpx.MockTransport`).

| # | Step | Proof | Fail-closed behaviour |
| --- | --- | --- | --- |
| 1 | runtime-safety-readback | `GET /v1/runtime/safety` (monitoring-readonly): staging profile `codestra-middleware-staging-v1`, exact `EXPECTED_SOURCE_SHA` / `EXPECTED_IMAGE_DIGEST`, schema head `0067_service_catalog_monitoring_state`, durable persistence, dispatch planes disabled, every effect and umbrella control off, `production_dialing=DISABLED` | any deviation → all later steps skipped; **no synthetic traffic sent** |
| 2 | edge-synthetic-request | signed TEST_SYN event (`build_signed_event`, HMAC v1) with `traceparent` + `X-Correlation-ID` through the public edge → Caddy → Kong → Middleware: 202 `accepted`, replay 200 `duplicate`, correlation echoed, Kong `Via` observed | non-202/200 → fail; steps 3–4 skipped |
| 3 | trace-propagation | Tempo trace contains caddy, kong, middleware spans with the request `correlation.id`; odoo/n8n reported observed/planned; span links counted; single trace id | missing required hop or trace never arriving → fail |
| 4 | log-correlation | Loki line for the correlation id carries `trace_id`; no secret-shaped content | leak → "redaction is broken" |
| 5 | metrics-freshness | Prometheus middleware target `up`, scraped ≤ 90 s ago, **port ≠ 8080**, request counter increased; provider-effect counter captured | stale/8080/no increase → fail |
| 6 | alert-ingestion | informational synthetic alert posted twice to Alertmanager → exactly one Middleware incident (`service=test-syn`) | 0 or > 1 incidents → fail |
| 7 | dashboard-readback | Grafana Middleware datasource OK, `codestra-openbao` + `codestra-middleware-operations` present, `/v1/observability/overview` 200 | missing → fail |
| 8 | no-business-effect | runtime safety unchanged (effects, umbrella, dispatch, dialing); provider-effect counter unchanged | any movement → fail |

Writes performed by a run: two POSTs of one signed TEST_SYN event (tenant `TEST_SYN_TENANT`, `external_effects_expected: false`) and two POSTs of one informational alert. Nothing else is mutated. Evidence `test-syn-certification.json` holds ids, counts, statuses, hashes and `TEST_SYN_GO`; it is refused if it would contain any loaded credential or secret-shaped string.

**Runtime execution: not performed.** Required inputs (edge producer token, webhook secret, monitoring/operator/Grafana tokens as 0600 files, staging Tempo/Loki/Prometheus/Alertmanager/Grafana reachability) were not available to this session, and the staging Middleware release with 0067 is not deployed. `TEST_SYN_GO = NO`.
