# Middleware API completion matrix

The authoritative inventory is `config/api-completion-matrix.yaml`. It is
generated from the registered FastAPI runtime by
`scripts/generate_api_contracts.py`; the same run writes the JSON OpenAPI and
`contracts/platform/integration-fabric-api.v2.yaml`.

The inventory contains every registered method/path operation, classifies each
entry as `IMPLEMENTED` or `DEPRECATED`, and contains no `UNKNOWN`, `PARTIAL`, or
`MISSING` entry. Deprecated compatibility routes remain executable. Run
`scripts/generate_api_contracts.py --check` to prove that all three committed
artifacts still match the current generator and registered runtime surface.

Tenant-scoped reads validate a bearer token for the `middleware-api` audience,
enforce the configured caller `status_scope`, and require the token tenant to
match `X-Tenant-ID`. Mutations enforce `command_scope` and, where applicable,
require `X-Correlation-ID`, `Idempotency-Key`, a safe reason, and
`expected_version`.

Inbox, outbox, command, operation, mutation, audit, and reconciliation state is
PostgreSQL-backed. Provider webhooks enforce configured bearer identity, HMAC
signature, timestamp tolerance, payload digest, replay protection, durable
inbox storage, immutable event evidence, and transactional outbox insertion.

All external-effect capabilities remain disabled. Live email, SMS, PSTN,
social publishing, advertising, external model calls, and N8N provider writes
are denied. `CALLS_PLACED` remains zero.
