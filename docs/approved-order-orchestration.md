# Approved-order orchestration

Middleware owns the order record, approval, content hash, idempotency key,
canonical lifecycle, retry/dead-letter policy, audit trail, and kill switches.
The n8n exports in `integrations/n8n/approved-orders/` are inactive and are
allowlisted by `workflow-registry.json`. They call only middleware APIs.

The initial feature flags are false:

```text
ORDER_ORCHESTRATION_ENABLED=false
N8N_ORDER_DISPATCH_ENABLED=false
CUSTOMER_MESSAGING_ENABLED=false
EXTERNAL_DIAL_ENABLED=false
POSTIZ_PUBLISH_ENABLED=false
PAYMENT_EXECUTION_ENABLED=false
```

Synthetic validation may enable only the first two flags for records prefixed
`CODESTRA-INTEGRATION-TEST-`. Production activation requires a separate
reviewed rollout. n8n never receives credentials, payment data, full customer
records, or arbitrary provider URLs.

Retryable classes are limited to network timeout, dependency unavailable, rate
limit, and temporary provider errors. Authentication, authorization, payload,
business, expiry, and duplicate failures do not retry automatically.
