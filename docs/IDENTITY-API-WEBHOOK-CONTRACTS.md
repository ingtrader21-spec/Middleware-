# Keycloak identity, API, and webhook contracts

## Purpose

This repository is the canonical middleware communication boundary. The files
below bind its existing connectivity graph and event envelope to the reviewed
Keycloak machine-client, audience, scope, API-path, and webhook rules:

```text
config/identity-access-map.json
config/api-webhook-contracts.json
contracts/event-envelope.schema.json
scripts/validate_identity_webhook_contracts.py
```

The contracts are fail-closed CI policy. They do not claim that a service is
installed, reachable, authenticated, or production-ready. Runtime readiness
still requires imported source, credentials outside Git, read-only inventory,
staging tests, rollback evidence, and explicit activation approval.

## Canonical identity

```text
issuer=https://auth.codestra.co/realms/codestra
token_endpoint=https://auth.codestra.co/realms/codestra/protocol/openid-connect/token
jwks_uri=https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs
machine_grant=client_credentials
maximum_machine_token_lifetime_seconds=300
```

Every machine token requires `iss`, `sub`, `aud`, `azp`, `iat`, `exp`, `jti`,
and `scope`. Refresh tokens, wildcard scopes, and full-scope mode are prohibited.
Every resource server rejects the token unless its exact client ID is present as
the audience and the caller has the exact operation scope.

## Call boundaries

- Kong forwards authorized requests to `middleware-api`.
- n8n calls only `middleware-api`; it receives no direct Odoo, telephony, SMS,
  email, crawler, or social-provider grant.
- Middleware is the normal command boundary to Odoo, VICIdial, Telnexa, Klyrow,
  Kyqra, and Postly.
- Provider and adapter events return only to `middleware-api` using an exact
  middleware audience and producer-specific publish scope.
- `monitoring-readonly` receives only `health.read` and `metrics.read`.
- `provisioning-service` receives no Keycloak Admin API permission and no
  `realm-admin`, `manage-realm`, or `manage-clients` role.

Application base URLs are protected runtime variables, not invented or committed
hosts:

```text
KONG_GATEWAY_BASE_URL
MIDDLEWARE_API_BASE_URL
ODOO_INTEGRATION_BASE_URL
N8N_AUTOMATION_BASE_URL
VICIDIAL_ADAPTER_BASE_URL
TELNEXA_GATEWAY_BASE_URL
KLYROW_GATEWAY_BASE_URL
KYQRA_GATEWAY_BASE_URL
POSTLY_ADAPTER_BASE_URL
```

## Webhook boundary

Every provider callback uses the canonical event envelope and requires:

```text
Authorization: Bearer <short-lived token>
Content-Type: application/json
Idempotency-Key: <event-id>
X-Codestra-Event-Id
X-Codestra-Event-Type
X-Codestra-Source
X-Codestra-Tenant-Id
X-Codestra-Timestamp
X-Codestra-Signature: sha256=<lowercase-hex>
X-Correlation-Id
```

The signature input is:

```text
v1
POST
<relative-path>
<unix-timestamp>
<event-id>
<source-client-id>
<sha256-body>
```

The middleware receiver permits at most 300 seconds of clock skew, persists
replay keys for at least 24 hours, stores the event in a durable inbox before
acknowledgment, and deduplicates by authoritative event ID. Delivery is at least
once, so every handler must be idempotent.

All event types use the `codestra.` namespace required by
`contracts/platform/event-envelope.v1.schema.json`.

## Source-readiness record

The access map deliberately records current source gaps instead of claiming live
integration:

- middleware API and worker implementation source is not yet imported;
- Odoo adapter source is present on both sides — the Odoo bridge add-on and
  the Middleware delivery adapter — but runtime remains unverified;
- the n8n repository does not yet contain workflow source;
- VICIdial, Telnexa, Klyrow, and Kyqra have source but runtime remains unverified;
- a Postly repository has not been confirmed;
- Kong, provisioning, and monitoring are contract-only in this repository.

These states must move only through separately reviewed implementation PRs with
exact-head tests and staging evidence.
