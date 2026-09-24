# ADR-0002: N4 command-envelope authority

- **Status:** Accepted
- **Date:** 2026-09-04
- **Authority:** `appolon1908-hue/Middleware-`
- **Applies to:** Middleware, N8N, Keycloak, Kong, Caddy, Klyrow and Odoo integration contracts

## Decision

Middleware's durable automation job is authoritative for tenant, actor, workflow family and execution identity. Every mutating `/v2/automation/*` request carries `tenant_id`, `correlation_id` and `idempotency_key` in the schema-validated JSON body. The exact same values must be mirrored in `X-Tenant-ID`, `X-Correlation-ID` and `Idempotency-Key`.

Middleware rejects any header/body mismatch and any disagreement with the durable job. Kong may validate and route the mirrored headers, but it may not rewrite them. `X-Request-ID` and `traceparent` remain transport/observability values and are not business identity.

Command names are normalized and unversioned. A command uses:

```json
{
  "command_type": "email.message.send",
  "command_version": "1.0"
}
```

A destination adapter may map that canonical pair to a provider's legacy wire name, such as `email.message.send.v1`, but the provider format does not become the Middleware command identity.

Every command is also bound to the active job lease, execution, workflow key/version, step, event, causation and idempotency identities. Unknown outcomes require destination read-back before any retry.

## Consequences

- N8N templates and executable workflows use `/v2/automation/*` only.
- Keycloak clients receive exact domain and operation scopes; generic execute/command scopes remain prohibited.
- Kong preserves the bearer token for Middleware revalidation and enforces the mirrored headers.
- Caddy forwards `/v2/automation/*` only to Kong and never directly to Middleware.
- Klyrow and other adapters translate canonical command type/version to provider-specific compatibility names at the adapter boundary.
- Header/body mismatch, stale lease, wrong client family, wrong command prefix, or unknown outcome retry fails closed.

## Release separation

This ADR resolves the source contract only. It does not activate workflows, create secrets, apply a Keycloak realm, reconcile Kong, reload Caddy, deploy Middleware/N8N, move traffic, or authorize an external effect.
