# Odoo transactional outbox contract

Business changes and outbox creation share one Odoo transaction. Immutable identity/payload fields include event, tenant/business-unit/campaign scope, aggregate, schema, payload/hash, correlation, causation, and idempotency keys. Mutable transport state is capability-protected.

Workers claim bounded batches with PostgreSQL row locking, a consumer identity, lease token/generation, and expiry. Only the current tenant-bound owner can renew, acknowledge, fail, or release. Identical terminal acknowledgement is harmless; conflicting ownership fails closed. Retryable transport failures receive bounded exponential backoff with jitter. Permanent validation/auth/contract failures dead-letter without copying unnecessary sensitive payload.
