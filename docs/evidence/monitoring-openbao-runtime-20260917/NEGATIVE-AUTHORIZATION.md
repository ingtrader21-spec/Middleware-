# Negative authorization tests (2026-09-17) — all fail closed

| Case | Where proven | Result |
| --- | --- | --- |
| monitoring-readonly requests provider/odoo/sms/email/telephony/secret/production scopes | Keycloak client `monitoring-readonly` optional scopes exactly `health.read`, `metrics.read`; Middleware `require_platform_scope` | denied (source) |
| monitoring-readonly used against OpenBao | never-bound list in Keycloak desired state; no OpenBao role; certifier optional check | denied |
| collector without `monitoring_collector` role / `platform.runtime.observe` | `app/monitoring/auth.py require()`; `validate_source` (service in principal.services, source_deployment bound to client + environment) | 403 |
| observation with unsupported fields / oversize / future timestamp / campaign not granted | `observe` endpoint | 422 / 413 / 422 / 403 |
| older observed_at for a service | `POST …/monitoring-state/observations` | 409 |
| certification without runtime evidence | `POST …/monitoring-state/certification` | 409 with blockers |
| Alertmanager events from a non-`alertmanager` client, missing Idempotency-Key / X-Correlation-ID, unapproved receiver | `app/observability_alerts.py` | 403 / 422 / 403 |
| staging token → production OpenBao path; service A → service B; wrong role; wrong audience; tampered signature; rewritten issuer; revoked token | `certify_staging_identity.py` + fake-authority tests (`test_production_path_readable_fails`, `test_cross_service_readable_fails`, `test_wrong_audience_accepted_fails`, `test_plain_token_carrying_openbao_audience_fails`) | 403 / ≥ 400 (fail if accepted) |
| unauthenticated OpenBao admin mutation (`sys/seal`, policy write, `sys/audit`, policy list) and the same with a workload token | `admin-mutation-unauthorized`, `admin-with-workload-token`; `test_open_admin_surface_fails` | non-2xx / 403 (fail if accepted) |
| OpenBao native listener reachable on the public name | `private-listeners`; `test_native_listener_reachable_fails` | fail |
| Blackbox non-GET/HEAD module; Middleware target on 8080; inline credential in prometheus.yml | Prometheus `validate.py`, `target_inventory.py` invariants, tests | validation failure |
| Superset datasource pointing at a telemetry/secrets host | `validate_monitoring_platform_boundary.py` | validation failure |
| collector run with redirect, unsafe token file, relative paths, unknown component, non-governed environment | `test_monitoring_collector.py` | refused / failed |

Runtime execution of the live negative cases against staging: **not performed** (see STAGING-CERTIFICATION.md).
