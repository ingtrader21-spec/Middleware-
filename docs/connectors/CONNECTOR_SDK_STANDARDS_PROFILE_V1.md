# Codestra Connector SDK v1 — Standards Compatibility Profile

This profile defines the interoperability baseline for connector manifests,
management APIs, webhook ingress, event transport, OAuth clients, tracing,
errors, versioning, and persistence.

## Normative standards

| Area | Standard/profile | Codestra use |
|---|---|---|
| HTTP API description | OpenAPI 3.1.1 | `connector-management-api.v1.yaml` |
| Data contracts | JSON Schema Draft 2020-12 | Connector and CloudEvent schemas |
| Events | CloudEvents 1.0 JSON format | Canonical normalized provider events |
| Distributed tracing | W3C Trace Context | `traceparent` and `tracestate` |
| API errors | RFC 9457 | `application/problem+json` |
| OAuth security | RFC 9700 | Client Credentials, exact audience and least privilege |
| HTTP semantics | RFC 9110 | Status, conditional requests and headers |
| Timestamps | RFC 3339 | CloudEvent `time` and audit timestamps |
| Versioning | Semantic Versioning 2.0.0 | Immutable manifest versions and precedence |
| Optional message signing | RFC 9421 extension point | Trusted adapters may implement it when providers support it |

The current built-in provider callback profile is `codestra-hmac-sha256-v1`:
HMAC-SHA256 over `<unix_timestamp>.<exact_raw_body>`. It is intentionally not
misrepresented as RFC 9421. A connector that supports RFC 9421 must implement
that verifier in its trusted adapter and declare a separately reviewed profile.

## CloudEvents mapping

Provider callbacks are normalized into structured CloudEvents 1.0:

```json
{
  "specversion": "1.0",
  "id": "provider-event-id",
  "source": "urn:codestra:connector:klyrow-email",
  "type": "email.message.delivered.v1",
  "subject": "provider-account-reference",
  "time": "2026-08-27T21:00:00Z",
  "datacontenttype": "application/json",
  "dataschema": "https://contracts.codestra.co/events/email.message.delivered.v1.schema.json",
  "tenantid": "authoritative-tenant-uuid",
  "correlationid": "correlation-id",
  "causationid": "causation-id",
  "connectorid": "klyrow-email",
  "endpointkey": "postal-events",
  "traceparent": "00-...",
  "data": {}
}
```

`tenantid` is derived from a trusted provider-account mapping. It is never
accepted from the provider body as authoritative.

## HTTP behavior

- Mutating management requests require `Idempotency-Key`.
- Concurrency-sensitive changes require `If-Match`.
- Asynchronous operations return `202 Accepted` and an operation resource.
- Errors use `application/problem+json`.
- List endpoints use bounded cursor pagination.
- `X-Correlation-ID`, `traceparent`, and `tracestate` are propagated.
- Exact webhook duplicates are acknowledged idempotently.
- Reuse of an event ID with a changed body is a semantic conflict.

## OAuth and identity

- Machine clients use OAuth 2.0 Client Credentials.
- Tokens require the exact `codestra-middleware-api` audience.
- Each connector receives connector-specific scopes.
- Human login, refresh tokens, realm administration, and provider credentials
  are prohibited for connector clients.
- mTLS remains required for high-risk private connector paths.

## Manifest and supply-chain rules

- Manifest versions follow Semantic Versioning 2.0.0.
- A released semantic version is immutable: the same version cannot be
  associated with a different manifest digest.
- Build metadata does not affect precedence.
- Pre-release identifiers follow SemVer numeric and lexical precedence.
- Generated Kong, Keycloak, n8n, and command artifacts are deterministic.
- Manifests contain references to external secrets, never secret values.
- Manifests cannot dynamically name or load executable adapter code.

## Webhook rules

- Signature, timestamp, event-ID, request-size, and route ownership checks
  happen before durable acceptance.
- Current and previous secret versions may overlap during rotation.
- Replay retention is at least seven days in the SDK profile.
- Event IDs are constrained to log-safe characters.
- Duplicate header names are rejected case-insensitively.
- JSON and CloudEvents JSON media types are supported.
- Production persists verified raw-body evidence before normalization and `202`.

## Persistence and tenancy

- Manifest version and digest are bound by a composite foreign key.
- Tenant connections use row-level security.
- Webhook event keys are tenant-scoped and row-level protected.
- Shared provider route paths are allowed across tenant connections; tenant
  resolution is explicit rather than relying on a globally unique route.
- CloudEvents, trace context, operation state, inbox, and outbox evidence are
  stored durably.
- Worker roles require separately reviewed least-privilege policies.

## Compatibility tests

The hardening suite verifies:

- SemVer precedence and immutable version digests;
- deep immutability after validation;
- canonical URL/path rejection, including encoded traversal;
- duplicate signature-header rejection;
- state-transition enforcement;
- capability and destination read-back enforcement;
- result and event secret-leak rejection;
- W3C trace-context validation;
- HMAC validation with rotation overlap;
- exact replay and semantic conflict behavior;
- authoritative tenant resolution;
- CloudEvents 1.0 projection;
- OpenAPI, JSON Schema, RFC 9457, and SQL contract markers.

## Non-claims

This source branch does not claim that:

- RFC 9421 is implemented for all providers;
- live DNS, TLS, Kong, Keycloak, PostgreSQL, or webhook routes are configured;
- database migrations have been applied;
- product adapters are deployed;
- connectors or external delivery capabilities are active.
