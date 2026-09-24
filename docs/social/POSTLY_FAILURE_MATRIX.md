# Postly failure matrix

| Condition | Classification | Action |
|---|---|---|
| Connect timeout/refused, temporary network failure | `FAILED_BEFORE_SEND`, retryable | Bounded exponential backoff with jitter |
| HTTP 429 | rate limited, retryable | Bounded retry; deployed Retry-After behavior still requires discovery |
| HTTP 500/502/503/504 | unavailable, retryable | Bounded retry |
| Read timeout after request send | `UNKNOWN_AFTER_SEND` | Fail closed; reconcile before any retry |
| HTTP 401 | authentication failed | Non-retryable, operator action |
| HTTP 403 or permanent 4xx | rejected | Non-retryable |
| Unsupported capability/media | capability/validation error | Non-retryable |
| Retry exhaustion | dead letter | Persist safe evidence, no raw stack trace |

Postly-specific reconciliation endpoints and idempotency support cannot be claimed until the installed runtime is accessible and inspected.
