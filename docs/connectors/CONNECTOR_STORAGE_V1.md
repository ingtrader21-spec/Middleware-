# Connector Runtime Storage v1

This branch converts the source SQL contract into an Alembic-managed PostgreSQL schema. It remains a source change only.

The migration provides tenant RLS, append-only audit records, idempotency claims, webhook replay keys, a durable webhook inbox, operations, dead letters and a transactional outbox. Upgrade, downgrade, repeat-upgrade, RLS, concurrent idempotency, replay-race and `pg_dump`/restore tests run against disposable PostgreSQL in CI.
