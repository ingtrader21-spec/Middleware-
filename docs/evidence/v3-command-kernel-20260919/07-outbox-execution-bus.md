# 07 — Transactional outbox / execution bus

Acceptance writes the command, its audit row and the outbox intent in ONE transaction (PostgresCommandStore.submit_on_connection). Chaos B (tests/integration): a failure after the command insert leaves no command, audit or intent; the client's retry is a clean first acceptance. Chaos A (tests/test_platform_api.py): persistence failure → 503, nothing persisted, never a 202.

ExecutionBus = middleware_outbox + app/worker.OutboxWorker (existing lease primitives: `FOR UPDATE SKIP LOCKED` claim, lease_owner/lease_until, attempt_count, quarantine-before-provider, heartbeat, sticky timeout, KnownSafeRetryError, resolve_reconciliation, dead-letter after max attempts) with the new `adapter-command` handler. NATS remains wake-up/fan-out only; losing a NATS message loses nothing (PostgreSQL backlog). Temporal keeps the long-running families (destination temporal-command).
