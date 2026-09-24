# Staging certification (2026-09-16)

## OpenBao (Section 27)

| Requirement | Source evidence | Runtime evidence |
| --- | --- | --- |
| Initialised through the approved operator procedure; custody documented | `scripts/initialize.sh`, `docs/recovery/*`, PGP 3-of-5 custody | not performed |
| No root token in Git | `reject_repository_secrets.sh`, `tests/security` | — |
| Audit device active before secret use | `config/audit/audit.v1.json` (`requiredBeforeSecretUse`, `failClosed`) | not performed |
| Keycloak/JWT works; staging identity reads its path; cannot read production; another service cannot read Middleware paths | CEL roles, generated policies, `tests/security/test_monitoring_identities.py`, Keycloak cross-check PASS | not performed (`scripts/verify.sh`, `reconcile_openbao_workload_identity_staging.py --mode apply`) |
| Prometheus retrieves `/v1/sys/metrics`; health observed through `/v1/sys/health` | scrape job, blackbox module, alerts | not performed |
| Audit telemetry reaches Loki; Grafana displays OpenBao health | Alloy audit tail, Loki ruler rules, OpenBao dashboard | not performed |
| No secret values in metrics/logs/traces/dashboards | validators and redaction stages | runtime sample scan not performed |

## Monitoring (Section 26/28)

Static certification executed at every recorded head (see FINAL-GATE.md). Runtime steps that remain: apply the Keycloak staging desired state, render OpenBao secrets to the collectors, activate the pending Prometheus targets, run TEST-SYN.md, capture the matrix cells Runtime/Metrics/Logs/Traces/Alerts/Dashboard from live evidence, then certify the catalog services.

Verdicts: `STAGING_MONITORING_GO=NO`, `STAGING_OPENBAO_GO=NO`.
