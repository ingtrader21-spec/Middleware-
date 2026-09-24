# Invalid-event quarantine

## Ingestion boundary

The gateway applies controls in this order: request-size limit, per-source rate
limit, server correlation ID generation, transport identity, raw-byte
signature verification, timestamp and nonce validation, JSON parsing, canonical
schema validation, business validation, idempotency, and the canonical
inbox/delivery transaction.

Caller correlation values are syntax-validated and retained only as
`client_correlation_id`. The server-generated UUID is authoritative.

Authentication failures are never quarantine records. `security_rejection`
contains only bounded identity claims marked `UNVERIFIED`, a keyed fingerprint,
source classification, reason, correlation ID, and time. It has no raw-payload
column and is never replay eligible.

## Authenticated invalid records

Exact raw bytes are fingerprinted with a dedicated HMAC-SHA256 key. When replay
retention is enabled, bytes are encrypted with AES-256-GCM using a random
96-bit nonce and the fingerprint as associated data. The key version and nonce
are stored separately. Logs, metrics, list/detail responses, audit records, and
correction diffs contain only allowlisted previews.

Keys are separate secret references:

- `QUARANTINE_FINGERPRINT_SECRET_FILE`
- `QUARANTINE_ENCRYPTION_KEY_FILE`
- `QUARANTINE_REVIEWER_SECRET_FILE`

## Review and reprocessing

Allowed states are `PENDING_REVIEW`, `UNDER_REVIEW`, `CORRECTABLE`,
`REPLAY_APPROVED`, `REPLAYING`, `REPLAYED`, `RESOLVED_NO_REPLAY`, `EXPIRED`,
and `REJECTED`. Application checks and a PostgreSQL trigger enforce transitions.
Review uses both a row lock and `record_version`.

Reviewer scopes and business units are bound to the reviewer identity by a
separate keyed authorization context. Required scopes are `quarantine:read`,
`quarantine:review`, and `quarantine:replay`.

Reprocessing does not resubmit the original publisher signature. It locks the
record, verifies original authentication, decrypts and fingerprints immutable
bytes, applies current schema/business rules and the canonical policy evaluator,
then performs idempotency and creates at most one canonical event. The original
timestamp and nonce are recorded as historical, not current authentication.

Corrections create encrypted `quarantine_correction` versions with a new
fingerprint/correlation identity, reason, reviewer, and sanitized before/after
preview. They never overwrite the original.

## Retention and operations

Retention days and policy version are configured. Cleanup excludes legal holds,
destroys ciphertext/nonces after the deadline, retains auditable metadata, and
records an audit event. The reconciliation runtime invokes cleanup.

Alert windows and thresholds are defined in
`monitoring/middleware-alerts.yaml`: 25 quarantines/10m, 5% quarantine ratio
over 15m, pending age over one hour, any reprocessing or cleanup failure, and
50 security rejections/5m.
