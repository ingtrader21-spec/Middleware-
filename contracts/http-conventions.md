# Middleware HTTP and webhook conventions

## Purpose

All middleware-facing APIs, adapter calls, callbacks, and webhooks use one security and reliability contract. A system-specific branch may extend this contract, but it may not silently weaken authentication, tenant isolation, replay protection, idempotency, or auditability.

## Required request metadata

Authenticated middleware requests carry these values when applicable:

```text
Authorization: Bearer <short-lived access token>
X-Tenant-ID: <canonical tenant identifier>
X-Correlation-ID: <request or workflow correlation identifier>
X-Causation-ID: <identifier of the command or event that caused this request>
Idempotency-Key: <stable key for every externally effective write>
traceparent: <W3C trace context when available>
```

The canonical human and service issuer is `https://auth.codestra.co`. Services validate issuer, audience, signature, expiry, not-before time, and authorized roles or scopes. A request must not gain access merely because a token is syntactically valid.

`X-Tenant-ID` is checked against the authenticated identity and authoritative local mapping. Caller-supplied tenant values are never trusted without authorization.

## Request and response behavior

- JSON requests use `Content-Type: application/json` and explicit schema versions.
- Every write is idempotent. Retries with the same idempotency key return the original result or a deterministic conflict; they do not repeat the external effect.
- Optimistic concurrency uses an explicit version, ETag, or equivalent precondition.
- Unknown fields, invalid enum values, malformed identifiers, and unsupported schema versions fail closed.
- Timeouts are finite and defined per adapter. A timeout is an unknown outcome, not proof that the provider did nothing.
- Logs and error messages redact access tokens, credentials, message bodies containing personal data, and signed webhook material.

## Canonical error envelope

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Safe operator-facing explanation",
    "correlation_id": "correlation-id",
    "retryable": false,
    "details": {}
  }
}
```

Use stable error codes. Do not expose stack traces, secrets, raw provider responses containing credentials, or customer data.

Recommended status semantics:

```text
400 malformed or semantically invalid request
401 missing or invalid authentication
403 authenticated but unauthorized
404 authorized resource not found
409 idempotency, state-transition, or optimistic-concurrency conflict
422 valid JSON that violates the command contract
429 rate limited; include bounded retry guidance
500 internal failure with no safe automatic retry assumption
502/503/504 dependency unavailable or outcome unknown
```

## Signed webhook contract

Inbound webhooks include:

```text
X-Codestra-Event-ID: <provider-stable event identifier>
X-Codestra-Timestamp: <signed event timestamp>
X-Codestra-Signature: <versioned signature>
X-Correlation-ID: <correlation identifier when supplied or generated>
```

Webhook processing must:

1. Read the raw body before parsing.
2. Select the expected provider and credential by authenticated route or trusted mapping.
3. Verify the signature using constant-time comparison.
4. Enforce a bounded timestamp window.
5. Insert the event ID and body digest into the durable inbox before acknowledging success.
6. Reject or quarantine duplicates, stale timestamps, unknown signature versions, and mapping conflicts.
7. Return success only after durable acceptance, not after every downstream action finishes.
8. Dispatch asynchronously through controlled workers and preserve correlation and causation IDs.

A replay operation uses an audited operator command and never bypasses signature, tenant, idempotency, or capability controls.

## Retry and delivery rules

- Read-only requests may use bounded retries with exponential backoff and jitter.
- Writes retry only when an idempotency key and provider reconciliation strategy exist.
- `429`, `502`, `503`, and `504` may be retryable according to adapter policy; other failures are not automatically retryable without an explicit contract.
- Every retry has a maximum attempt count and maximum age.
- Exhausted work moves to a dead-letter or operational-exception state with a safe replay path.
- Provider timeouts trigger reconciliation before a second externally effective attempt.

## Health, readiness, and release identity

Every deployable middleware service exposes or provides equivalent authenticated/private checks for:

```text
/health   process is alive
/ready    required local dependencies and startup checks are ready
/version  exact source SHA, immutable image digest, schema head, and build time
/metrics  authenticated or private operational metrics
/v1/runtime/safety  authenticated effective non-secret safety controls
```

Readiness must not report success when required database migrations, identity configuration, or mandatory safety controls are missing.

## Compatibility

- Additive fields may be introduced within a compatible schema version only when consumers ignore unknown fields by explicit policy.
- Removing or changing field meaning requires a new schema or API version.
- Producers publish the schema version; consumers reject unsupported versions safely.
- Cross-branch changes merge in dependency order: canonical contract first, shared persistence/worker primitives second, adapter implementation third, Kong/Caddy routing fourth, and observability last.

## Staging safety

Staging and test environments start with external delivery and live writes disabled. Contract tests use fakes, isolated test tenants, or explicitly approved sandbox providers. A successful contract test is not permission to activate production delivery, dialing, publishing, crawling, or callbacks.
