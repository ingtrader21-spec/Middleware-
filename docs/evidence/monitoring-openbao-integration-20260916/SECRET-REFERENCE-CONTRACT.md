# Secret-reference contract (2026-09-16)

Authority `Codestra-OpenBao/contracts/secret-reference.v1.schema.json`, canonical sha256 `8762a999da747a9450d73dc876718a3f70a3fb47fd1e065689cdf2357849a665`, vendored byte-for-byte with a pin in every consuming repository.

```json
{"provider": "openbao", "environment": "staging", "service_id": "middleware",
 "secret_ref": "codestra/staging/middleware/api/database", "secret_class": "database_credentials",
 "version": null, "reference_uri": "openbao://codestra/staging/middleware/api/database",
 "workload_identity": "middleware-api"}
```

Rules enforced by `Codestra-OpenBao/scripts/validate_secret_references.py`, `Middleware-/app/secret_reference.py` and every component validator: forbidden keys `value`, `password`, `token`, `private_key`, `client_secret`, `secret`, `secret_value`, `unseal_key`, `recovery_key`, `root_token` and any `*_password|*_token|*_secret` key at any depth; secret-shaped strings (OpenBao tokens `hvs.`/`hvb.`, PEM keys, AWS keys, GitHub tokens) rejected; `secret_ref` must be `codestra/<environment>/<workload>/<name>` inside its own environment with no wildcard or traversal; `reference_uri == "openbao://" + secret_ref`; the path must lie beneath a prefix admitted to `workload_identity` in that environment; Middleware additionally requires the environment to be one the service declares.

Middleware may hold: `secret_owner`, `rotation_status`, `lease_metadata` (`lease_id_hash`, `ttl_seconds`, `renewable`, `issued_at`, `expires_at`), `last_reconciled_at`, `last_reconciliation_status` (`readable|denied|missing|openbao_unavailable`). No Middleware API resolves a reference (`tests/test_secret_reference_contract.py`, `tests/test_platform_catalog_monitoring.py::test_monitoring_state_read_exposes_references_without_values`).

Reviewed catalog: `Codestra-OpenBao/config/secret-references.v1.json` — 50 references, 11 identities, staging and production. Per-component declarations: Alertmanager, Telemetry, Alloy, Loki, Tempo, Redis/Postgres exporters, Grafana, Superset (`codestra/secret-references.v1.json` each), every `/run/secrets/*` file they read must be covered (validator-enforced).
