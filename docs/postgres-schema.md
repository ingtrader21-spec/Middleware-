# PostgreSQL schema

`integration_event` stores the accepted payload and SHA-256 payload hash. `integration_delivery` is the transactional outbox with a unique event/target pair. `idempotency_record` stores only a hashed key, request hash, status, and safe cached response. Payloads are retained for processing; credentials are not accepted or stored by this API.
