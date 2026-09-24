# Postly staging runtime

The durable runtime uses PostgreSQL as canonical state and Redis only for minimal `{job_id, correlation_id}` signals. `SqlSocialRepository` commits intent, persistent idempotency, job, audit, and outbox signal intent before any worker dispatch. `app.entrypoints.social_worker` runs a fail-closed, single-concurrency worker with atomic PostgreSQL leases and stale-lease recovery.

Provider results create attempts, update the canonical post/job, and create normalized IntegrationEvent records. Postly read timeouts become `UNKNOWN_AFTER_SEND` and are dead-lettered rather than blindly retried. Full provider lookup reconciliation remains limited until the deployed Postly API can be inspected.

Runtime switches `SOCIAL_SQL_REPOSITORY_ENABLED` and `SOCIAL_WORKER_ENABLED` default to false. Worker concurrency is constrained to one.
