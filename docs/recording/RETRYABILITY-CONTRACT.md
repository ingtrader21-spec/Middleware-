# Recording delivery retryability contract

Retries use the same deterministic idempotency key. Automatic delay is
`min(3600, 2^attempt)` seconds, with at most three transport attempts per API
operation. Redirects are always denied.

| Condition | Retry automatically | Terminal behavior |
|---|---:|---|
| Network timeout | Yes | `FAILED` after bounded attempts |
| Reservation timeout | Yes | Preserve `HASHED`; retry same key |
| Upload timeout | Yes | Preserve reservation; retry same object URL only while unexpired |
| Completion timeout | Yes | Query status or repeat completion with same key |
| Middleware `429` | Yes | Bounded exponential backoff |
| Middleware `5xx` | Yes | Bounded exponential backoff |
| Authentication denial (`401`/`403`) | No | Fail closed |
| Schema rejection (`400`/`422`) | No | `QUARANTINED` |
| Checksum conflict (`409`) | No | `QUARANTINED` |
| Quarantine | No | Manual reviewed release only |

An expired upload reservation is never reused. Missing, extra, malformed, or
expired reservation response fields are schema rejection and fail closed.
