# Secret references (2026-09-17)

Contract: `Codestra-OpenBao/contracts/secret-reference.v1.schema.json` (canonical sha256 `8762a999da747a9450d73dc876718a3f70a3fb47fd1e065689cdf2357849a665`), vendored and pinned in Middleware (`contracts/secrets/secret-reference.v1.schema.json` + `.sha256`), Alertmanager, Redis/Postgres exporters, Grafana, Loki, Tempo, Alloy, Telemetry, Superset.

Required fields: `provider environment service_id secret_ref secret_class version`. Optional: `reference_uri (openbao://…)`, `workload_identity`, `secret_owner`, `consumer_repository`, `rotation_status`, `lease_metadata{lease_id_hash, ttl_seconds, renewable, issued_at, expires_at}`, `last_reconciled_at`, `last_reconciliation_status`.

**Forbidden anywhere in catalog, configuration or evidence** (`x-codestra-forbidden-keys`, enforced at any depth by every validator and by Middleware `SecretReference.reject_secret_material`): `password`, `token`, `value`, `client_secret`, `private_key`, `root_token`, `recovery_key`, `unseal_key`, plus `secret`, `secret_value`, any `*_password|*_token|*_secret` key and any secret-shaped string.

Inventory: `config/secret-references.v1.json` — 50 references across 11 identities (`SECRET_REFERENCE_CONTRACT=PASS references=50 identities=11`). Example reference (metadata only):

```json
{"provider": "openbao", "environment": "staging", "service_id": "middleware-integration-api",
 "secret_ref": "codestra/staging/middleware/database", "secret_class": "database_credentials",
 "version": 1, "reference_uri": "openbao://codestra/staging/middleware/database",
 "workload_identity": "middleware-api", "rotation_status": "current"}
```

Middleware behaviour: the catalog stores `secret_references` (jsonb, validated), never a value; no Middleware API resolves a reference; `tests/test_secret_reference_contract.py` (13) and `test_platform_catalog_monitoring.py` (19) pass; the collector and TEST_SYN runner read credentials only from `*_FILE` paths and refuse to write any evidence containing them.

Evidence-package scan: every file in this directory was scanned for the forbidden keys and secret shapes before commit (SECRET-LEAK-SCAN.md).
