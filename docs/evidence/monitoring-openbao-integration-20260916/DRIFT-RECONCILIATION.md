# Drift and reconciliation (2026-09-16)

Two reconciliation surfaces exist in Middleware, both read-only with respect to runtime (`runtime_mutated: false`):

1. **Component reconciliation** (`app/monitoring/routes.py::reconcile_one`): compares the approved release digest with fresh (<= 90 s) `config` observations per component (Prometheus targets/rules, Alertmanager configuration, Grafana datasources/dashboards, Loki, Tempo, Alloy, OpenBao health, exporters, Blackbox) and returns `component_states` in the vocabulary `pending | applying | synced | drifted | failed | unknown`. A component with no fresh digest read-back is `unknown`; a digest differing from the approved revision is `drifted`; a desired revision not yet approved is `pending`; collectors may report `applying`/`failed`. An HTTP 200 alone never yields `synced` (`tests/test_monitoring_component_states.py`).
2. **Catalog reconciliation** (`app/platform_catalog_monitoring.py::derive_state`): expected vs observed Git SHA, image digest, config digest and migration head from authorized collector observations; stale after 15 minutes; certification survives only while synced and fresh.

Collectors read the actual active configuration (Prometheus `/api/v1/status/config` digest, Alertmanager `/api/v2/status` config hash, Grafana provisioning digests, Loki/Tempo `/config`, Alloy component digests, OpenBao `/v1/sys/health`) and post `POST /platform/v1/runtime/observations` (kind `config`, `payload.component`, `payload.config_digest`, optional `payload.status`) and `POST /platform/v1/services/{id}/monitoring-state/observations`. Desired state comes from Git descriptors and the approved release lock; Git events never authorize deployment.

Exporter/collector repositories expose their expected digests through their config-bundle manifests (Alertmanager, Loki, Blackbox, Tempo release locks) so the observed digest can be compared without ambiguity.
