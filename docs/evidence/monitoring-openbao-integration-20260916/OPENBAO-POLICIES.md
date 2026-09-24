# OpenBao policies (2026-09-16)

Source: `Codestra-OpenBao` `28f009c6` — `config/policies/workload-identities.v1.json` (26 identities) -> `config/workload-secret-authority.v1.json` (78 roles) -> `openbao/policies/<environment>/<identity>.hcl` (generated, drift is a validation failure).

## Namespaces

`codestra/<environment>/<workload prefix>/...` under one KV v2 engine (`codestra/`, CAS required, 10 versions). Environment roots: `codestra/development/`, `codestra/test/`, `codestra/staging/`, `codestra/production/`.

## Monitoring-plane identities

| Identity | Prefixes | Environments |
| --- | --- | --- |
| `prometheus-openbao` | `observability/openbao/metrics-client/`, `observability/prometheus/scrape-credentials/` (+ `sys/metrics` read) | all four |
| `grafana-runtime` | `observability/grafana/` | staging, production |
| `alertmanager` | `observability/alertmanager/` | staging, production |
| `alloy-collector` | `observability/alloy/` | staging, production |
| `otel-gateway` | `observability/otel-gateway/` | staging, production |
| `loki-runtime` / `tempo-runtime` | `observability/loki/`, `observability/tempo/` | staging, production |
| `redis-exporter` / `postgres-exporter` | `observability/exporters/redis/`, `observability/exporters/postgres/` | staging, production |
| `superset-analytics` | `analytics/superset/` | staging, production |

Every generated policy grants `read` on `codestra/data/<env>/<prefix>*` and `read,list` on the matching metadata path, then denies every other environment root, `sys/*`, `database/*`, `pki-*`, `transit-*` and `auth/token/create*`; only `lookup-self`, `renew-self` and `revoke-self` remain. No wildcard reader exists (`explicitDeny.observability-general` denies every environment root). `tests/policy/test_generated_policies.py` and `tests/security/test_monitoring_identities.py` prove cross-environment denial, non-overlapping prefixes and that no monitoring identity can read Middleware or Odoo paths.

Node Exporter, cAdvisor and Blackbox Exporter have no policy: they hold no credential (`monitoring-platform.v1.json` in each repository, validator-enforced).
