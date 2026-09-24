# OpenBao health monitoring (2026-09-17)

Health is monitored, never acted upon automatically: **no component unseals OpenBao because a probe reports sealed**. Unseal/initialisation remain operator ceremonies (`scripts/initialize.sh`, `scripts/unseal_from_files.py` under the recovery procedure).

## What is monitored

| Signal | Source | Consumer | Alert |
| --- | --- | --- | --- |
| `initialized`, `sealed`, `standby`, `performance_standby`, `version`, `cluster_name`, HTTP status (200/429/473/503) | `GET /v1/sys/health` | Blackbox `https_openbao_health` (GET only, valid codes 200/429, body must show initialized and unsealed); Middleware collector reader `openbao`; identity certifier `health-unauthenticated` | OpenBaoSealed, OpenBaoStandbyOnly, OpenBaoHealthProbeFailure, OpenBaoHealthProbeLatencyHigh |
| `/v1/sys/metrics?format=prometheus` | job `codestra-openbao` (https, mTLS, file-backed bearer bound to `workload-prometheus-openbao-<env>`, `sys/metrics` read only), `activation: pending` | Prometheus | OpenBaoMetricsMissing, OpenBaoScrapeTokenExpiring |
| audit device availability / silence | audit log via Alloy → Loki, `vault_audit_log_failure` metric | Loki rules, Prometheus | OpenBaoAuditDeviceUnavailable, OpenBaoAuditSilence |
| authentication failures, policy denials, lease revocations | metrics + audit | Prometheus, Loki | OpenBaoAuthFailureSurge, OpenBaoPolicyDenialRateHigh, OpenBaoLeaseRevocationSurge |
| backup freshness | `monitoring/prometheus/openbao-backup.prom` textfile | Prometheus | OpenBaoBackupStale |

Rule counts: OpenBao repo `monitoring/alerts/openbao-alerts.yml` 24 rules; Prometheus repo `rules/openbao-alerts.yml` 10 rules + `rules/monitoring-platform-alerts.yml` 8 rules (promtool check rules PASS, `promtool check config --syntax-only` PASS at `1e1089a26860`).

## Collector reading (`app/monitoring/collector.py::read_openbao`)

GET `/v1/sys/health` only; a sealed or uninitialised response yields component status `failed` with the message "operator action; the collector never unseals", posted to Middleware as `config` observation `status=failed`, which folds the service state to `failed`. Unit test `test_sealed_openbao_is_failed_and_never_unsealed` asserts no non-GET request reaches the OpenBao base.

Runtime observation of the staging node: **not performed** (no host/network access; see STAGING-CERTIFICATION.md).
