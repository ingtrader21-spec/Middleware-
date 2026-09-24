# Reconciliation (2026-09-17)

## Desired vs observed

| Desired (Git / catalog) | Observed (collector, actual runtime) | Reader |
| --- | --- | --- |
| approved `config_digest` per service; Prometheus `target-inventory.v1.json` (44 targets) | active configuration digest from `/api/v1/status/config`; `/api/v1/targets` health, last scrape, freshness; rules digest | `read_prometheus` |
| Alertmanager release bundle (`config-bundle.manifest.json`, LF digests) | `config.original` digest from `/api/v2/status`; active alert count; cluster status | `read_alertmanager` |
| Grafana provisioning (5 datasources incl. `codestra-middleware-observability`; 53 generated dashboards) | datasource uid/type/url/readOnly + per-datasource health; dashboard uids | `read_grafana` |
| Loki `redaction-contract` label policy | `/config` digest; label-name count (bounded ≤ 15) | `read_loki` |
| Tempo `trace-propagation-contract` | `/status/config` digest; echo | `read_tempo` |
| Alloy `runtime.v1.json` | component list + health digest | `read_alloy` |
| OTel gateway | health extension | `read_otel_gateway` |
| OpenBao health list | `/v1/sys/health` fields | `read_openbao` |
| exporter presence | `/metrics` sentinel family | `read_exporter` (node_exporter_build_info, cadvisor_version_info, redis_up, pg_up, blackbox_exporter_build_info) |
| Blackbox probe state | via Prometheus `probe_success` targets | `read_prometheus` targets |

## State vocabulary (Middleware `app/monitoring/routes.py`)

Per component (`component_state`): `failed` (collector reported) > `applying` > `pending` (desired ≠ approved) > `unknown` (no fresh digest ≤ 90 s, or not required) > `synced` (digest equals desired) / `drifted`. Per service (`service_state`, new): `pending-release-approval` when desired ≠ approved; otherwise worst-first over required components `failed > applying > unknown > drifted > synced`. **`synced` is never derived from an HTTP 200** — it requires a fresh read-back whose digest equals the approved desired revision.

## Freshness

Collector observations older than 90 s are ignored by the reconciler (state falls to `unknown`); catalog observed state older than 15 min is stale (`certification_blockers`); Prometheus inventory marks a target `stale` beyond 2 × scrape interval + 5 s; the TEST_SYN metrics step requires a Middleware scrape within 90 s.

## Proofs

- `tests/test_monitoring_collector.py` (18): full read → post → report; monotonic sequences; component failure reported not omitted; sealed OpenBao failed without unseal; missing sentinel failed; Middleware unreachable / 5xx / missing token fail closed without advancing state; redirects refused; report refused if secret-shaped; CLI exit codes 0/2/3.
- `tests/test_monitoring_failure_modes.py` (9): no observation → `unknown`; collector `failed` → service `failed`; stale success → `unknown`; drift folding; backend outage → 503 without fabricated data; readiness independence; sealed OpenBao never unsealed.
- `tests/test_monitoring_component_states.py` (3), `tests/test_integrated_monitoring.py` (33 of 34; the 34th needs symlink privilege on Windows).

Runtime reconciliation against staging: **not performed**.
