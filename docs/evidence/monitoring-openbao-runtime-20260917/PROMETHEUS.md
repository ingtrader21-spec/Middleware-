# Prometheus (2026-09-17) — Codestra-Prometheus @ `1e1089a26860`

## Runtime target record (Section 10) — desired view, generated from the repository

`codestra/target-inventory.v1.json` (44 records; `config_digest sha256:d2c7566486ed…` over LF bytes of `prometheus.yml`). Selected records:

| job | service_id | environment | activation | expected endpoint | authentication | contract SHA |
| --- | --- | --- | --- | --- | --- | --- |
| codestra-middleware-metrics | middleware | production | active | `middleware-integration-api:8095` `/metrics` | oauth2 client=monitoring-readonly scopes=metrics.read secret=file | `1e1089a26860` |
| codestra-openbao | openbao | production | pending | `codestra-bao-production-01:8200` `/v1/sys/metrics?format=prometheus` | bearer credentials=file; mtls client-cert=file | `1e1089a26860` |
| blackbox | middleware-readiness | production | active | `http://middleware-integration-api:8095/readiness` | probe `http_2xx_internal` via blackbox-exporter:9115 | `1e1089a26860` |
| blackbox | openbao-health | production | pending | `https://codestra-bao-production-01:8200/v1/sys/health` | probe `https_openbao_health` (GET) | `1e1089a26860` |
| codestra-targets | node-exporter ×3, cadvisor ×3, postgres-exporter, redis-exporter, caddy, kong, keycloak, n8n, odoo, opentelemetry-collector, alertmanager | production | active | private `host:port` | none (private network) | `1e1089a26860` |
| codestra-targets | loki, tempo, grafana, alloy + 13 business backends | production | pending | private `host:port` | none (private network) | `1e1089a26860` |

Actual endpoint / scrape status / last scrape / metric freshness columns are filled by `target_inventory.py --runtime-url http://prometheus:9090` (or `--runtime-file`) into `target-inventory.runtime.{json,md}`, and independently by the Middleware collector's `target-records.md`. **Runtime columns for staging: not observed** (no access).

## Invariants (fail closed in `validate.py`, CI and the inventory tool)

- Middleware is scraped only by the dedicated authenticated job at `middleware-integration-api:8095`; any Middleware target on legacy `8080` or elsewhere fails validation (`test_legacy_middleware_port_is_rejected`).
- No inline `bearer_token`, `password`, `client_secret`, `credentials`; only `*_file` references (`/run/secrets/monitoring-readonly-client-secret`, `/run/secrets/openbao-prometheus-token`, mTLS material) rendered by the OpenBao agent from `codestra/<env>/observability/prometheus/scrape-credentials/…` / `observability/openbao/metrics-client/`.
- OpenBao job: https, `/v1/sys/metrics`, `format=prometheus`, mTLS, pending until the OpenBao runtime is certified.
- Blackbox modules limited to GET/HEAD/DNS/TCP/TLS (`https_2xx http_2xx_internal tcp_connect https_openbao_health dns_a_record tls_expiry`).
- Every target carries `service` and `environment`; `metric_relabel_configs` drop identity/PII labels.
- Committed inventory must equal the derived one (`--check`; `validate_target_inventory()`).

Local validation: `validate.py` PASS, `promtool 3.14.0 check config --syntax-only` PASS, `promtool check rules` PASS (source stage), pytest 27 passed, unittest 15 OK.

Staging profile note: the committed configuration is the production-labelled authority (`environment: production`, `token_url: auth.codestra.co`). Staging activation uses `Codestra-OpenBao/monitoring/prometheus/openbao-scrape.staging.yml` and the staging issuer per `integration/staging-activation-contract-v1.json` (`prometheus_target_current_state: pending`, activation PR must cite image digest and evidence checksum; Blackbox must remain pending). No activation PR was raised.
