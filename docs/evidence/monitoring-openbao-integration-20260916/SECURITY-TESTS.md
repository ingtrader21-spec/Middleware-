# Security tests (2026-09-16)

All fail closed. "Source" = executed on this host at the recorded heads; "Runtime" = requires a staging environment (not performed).

| Test | Where | Result |
| --- | --- | --- |
| Plaintext secrets in Git | OpenBao `reject_repository_secrets.sh`; Prometheus/Alertmanager/Loki/Tempo/Telemetry/Alloy/Grafana/Superset secret-scan and `validate_secret_safety` steps; secret-reference validators (forbidden keys, secret-shaped strings) | PASS (source) |
| Secrets in CI output | evidence/plan writers print hashes only (`token_values_recorded=false`, `secret_values_recorded=false`); Keycloak/OpenBao reconcilers write secrets to 0600 files outside the checkout | PASS (source design); runtime not exercised |
| Secrets in Prometheus labels | `labeldrop` on every job incl. `token|secret|password|accessor|lease_id`; validator rejects inline credentials | PASS (source) |
| Secrets in Loki | Alloy/OTel redaction; Loki redaction contract; OpenBao audit HMAC preserved | PASS (source); runtime sample scan pending |
| Secrets in Tempo | agent + gateway attribute deletion and secret-shaped scrubbing; Tempo never logs spans/headers | PASS (source) |
| Secrets in Grafana variables/datasources | validator: `secureJsonData` only as `$__file{}`; dashboards scanned for forbidden tokens | PASS (source) |
| Cross-environment OpenBao access | generated policies deny every other environment root; CEL roles bind `codestra_environment`; per-environment issuer | PASS (source, `tests/policy`, `tests/security`) |
| Cross-service secret access | non-overlapping prefixes; `test_no_monitoring_identity_can_read_another_workload` | PASS (source) |
| Long-lived monitoring token | 300 s TTL/max TTL for every role; Prometheus bearer from a rendered file; `OpenBaoScrapeCredentialNearExpiry` alert | PASS (source) |
| Overly broad / wildcard policies | validator rejects `*`, `..`, `//`, non-prefix paths; no `observability-general` reader | PASS (source) |
| Anonymous sensitive metrics | OpenBao `unauthenticatedMetricsAccess=false`; Middleware `/metrics` behind monitoring-readonly | PASS (source) |
| Public exporter listeners | exporter validators reject non-loopback host ports; Loki/Tempo no public ingest | PASS (source) |
| Unauthorized incident mutation | existing `tests/test_observability_alerts.py` (403 on wrong client/scope) | PASS |
| Unauthorized service-catalog mutation | `tests/test_platform_verified_authority.py` (66), `tests/test_platform_catalog_monitoring.py` (observation scope/role, certification role, forged identity) | PASS |
| OpenBao unavailable -> fail closed, no plaintext fallback | `tests/test_secret_file_fail_closed.py` (missing/empty/relative rendered file raises, default never promoted) | PASS |
| Foreign issuer / wrong audience / wrong client / tampered JWT | CEL programs + Keycloak `test_openbao_workload_identity.py` | PASS (source); live negative reads pending |
