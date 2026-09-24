# Service catalog — expected versus observed monitoring state (2026-09-16)

Authority: Middleware `platform_services` (Alembic `0067_service_catalog_monitoring_state`, head `281bb7a6f153`).

## Descriptor fields

`service_id`, `repository`, `owner`, `service_type`, `environments`, `deployment_id`, `host_id`, `instance_id`, `public_origin`, `private_origin`, `liveness_path`, `readiness_path` (defaults to `health_path`), `metrics_path`, `openapi_path`, `dependencies`, `data_classification`, `metrics_profile`, `logs_profile`, `traces_profile`, `slo_profile`, `alert_profile`, `prometheus_target_id`, `blackbox_target_id`, `grafana_dashboard_ids`, `expected_git_sha`, `observed_git_sha`, `expected_image_digest`, `observed_image_digest`, `expected_config_digest`, `observed_config_digest`, `expected_migration_head`, `observed_migration_head`, `secret_references[]`, `monitoring_state`, `monitoring_state_reason`, `last_observed_at`, `last_observation_source`, `last_certified_at`, `last_certified_by`.

## States and transitions

`unregistered` -> `registered` (descriptor imported) -> `pending` (expected identity declared, nothing observed) -> `synced` (fresh evidence matches every expected field) -> `certified` (granted only with runtime proof). `drifted`, `unknown` (stale/partial evidence), `applying` and `failed` (collector-reported) are derived on every observation. A Git descriptor never yields `synced`; an HTTP 200 never yields `synced`; certification is revoked automatically when evidence stops matching or goes stale, and when the expected release changes.

## Operations

| Operation | Scope / role | Notes |
| --- | --- | --- |
| `POST /platform/v1/services` | `platform.services.write`, `platform_admin` | descriptor + secret references validated (pointers only) |
| `PATCH /platform/v1/services/{id}` | same | desired-state changes re-derive state; a certified service whose expected release changes falls back |
| `GET /platform/v1/services/{id}/monitoring-state` | `platform.services.read` | expected vs observed per field, freshness, bindings, references, last 20 audit rows |
| `POST /platform/v1/services/{id}/monitoring-state/observations` | `platform.runtime.observe`, `platform_operator`/`platform_admin`, `X-Correlation-ID` | collector read-back; delayed evidence never overwrites newer state |
| `POST /platform/v1/services/{id}/monitoring-state/certification` | `platform.services.write`, `platform_admin`/`platform_reviewer`, `X-Correlation-ID` | 409 with blockers unless synced, fresh, targets/dashboards bound and every applicable evidence flag true |
| `GET /platform/v1/sync/status`, `POST /platform/v1/sync/reconciliations` | existing | now return `component_states` |

Tests: `tests/test_platform_catalog_monitoring.py` (19), `tests/test_monitoring_component_states.py` (3), `tests/test_platform_verified_authority.py` (66, unchanged). Every transition is written to `platform_service_monitoring_audit` with the evidence hash; the migration's downgrade refuses to drop it while rows exist.

## Deployable services registered by this mission's descriptors

The component repositories declare their catalog profile in `codestra/monitoring-platform.v1.json` (exporters) or their platform contract (Loki, Tempo, Telemetry, Alloy, Grafana, Superset): `metrics_profile=prometheus`, `logs_profile=alloy`, `traces_profile=not-applicable` for exporters. Registration itself is a runtime act (POST against staging Middleware) and is not performed from source.
