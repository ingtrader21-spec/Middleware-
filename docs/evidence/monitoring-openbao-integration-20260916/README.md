# Evidence — monitoring / OpenBao integration (2026-09-16)

Mission: wire the Codestra monitoring platform to Middleware (operational control plane) and OpenBao (secrets plane) with Prometheus, Loki, Tempo and Alloy/OTel as the telemetry data plane, without enabling any production provider activity.

Files: ARCHITECTURE, REPOSITORY-MATRIX, SERVICE-CATALOG, OPENBAO-POLICIES, OPENBAO-IDENTITY, OPENBAO-METRICS, SECRET-REFERENCE-CONTRACT, PROMETHEUS, ALERTMANAGER, LOKI, TEMPO, ALLOY-OTEL, GRAFANA, EXPORTERS, SECURITY-TESTS, TEST-SYN, STAGING-CERTIFICATION, DRIFT-RECONCILIATION, ROLLBACK, FINAL-GATE (verdicts, static certification, certification matrix, blockers).

All secrets are redacted by construction: this package contains references, digests, identities and paths only.
