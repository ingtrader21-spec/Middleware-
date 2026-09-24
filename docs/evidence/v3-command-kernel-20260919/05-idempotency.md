# 05 — Idempotency

Authority: middleware_commands UNIQUE(tenant_id, idempotency_key) + payload_sha256 over the authenticated payload (command id, type, target, tenant, requested_by, correlation, key, capability, payload, authenticated client). Exact replay → the original operation, duplicate=true, no new intent; same key + different payload → 409 command_conflict; different client → 409.

Proofs: tests/test_platform_kernel.py::test_hundred_concurrent_identical_submissions_create_one_operation (memory), tests/integration/test_platform_kernel_postgres.py::test_hundred_concurrent_identical_submissions (PostgreSQL 16, CI digest cf78e766…): COMMAND_ROWS=1, OUTBOX_EFFECT_INTENTS=1, EXTERNAL_EFFECTS=1 (TEST_SYN fixture), DUPLICATE_EXTERNAL_EFFECTS=0, 99 duplicates, 10 conflicting → 409. CRM wrappers derive the command id from (tenant, command type, key) so retries replay the same row.
