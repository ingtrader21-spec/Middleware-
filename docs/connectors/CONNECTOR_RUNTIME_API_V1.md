# Codestra Connector Runtime API v1

## Scope

This branch turns the Connector SDK contracts into a real FastAPI and PostgreSQL runtime while preserving the Integration Fabric safety boundary.

```text
Caddy -> Kong -> Connector Runtime API -> Middleware connector ledgers
                                      -> encrypted webhook body store
                                      -> durable inbox/outbox
                                      -> trusted adapters in later branches
```

The API does not activate connectors, bind provider credentials, publish n8n workflows, or enable external effects.

## Implemented controls

- OAuth 2.0 access-token validation against Keycloak JWKS.
- Exact issuer, audience, authorized-party, expiry, issue-time and maximum-lifetime checks.
- Tenant derivation from validated token claims; wildcard tenant claims are rejected.
- Scope-specific FastAPI dependencies.
- RFC 9457 `application/problem+json` errors.
- Correlation IDs and `traceparent` propagation.
- Opaque HMAC-authenticated cursor pagination.
- Persistent idempotency with request-digest conflict detection.
- ETag and `If-Match` optimistic concurrency.
- Append-only audit records.
- Connector catalog, manifest validation, disabled-first installation and tenant connection handlers.
- Webhook endpoint, delivery evidence and secret-reference rotation handlers.
- Health, readiness and release identity endpoints.
- Raw-body HMAC verification with timestamp and event-ID checks.
- Current/previous secret overlap during rotation.
- AES-GCM encrypted raw-body persistence to a durable mounted volume.
- Webhook replay identity and changed-body semantic conflict detection.
- Transactional webhook inbox and outbox insertion before `202 Accepted`.
- PostgreSQL RLS and composite tenant foreign keys.

## Fail-closed defaults

```text
CONNECTOR_RUNTIME_EXTERNAL_EFFECTS_ENABLED=false
CONNECTOR_RUNTIME_CONNECTOR_ACTIVATION_ENABLED=false
CONNECTOR_RUNTIME_WEBHOOK_INGRESS_ENABLED=false
CONNECTOR_RUNTIME_CONNECTOR_INSTALL_ENABLED=false
CONNECTOR_RUNTIME_CONNECTOR_UPGRADE_ENABLED=false
CONNECTOR_RUNTIME_CONNECTOR_DISABLE_ENABLED=false
CONNECTOR_RUNTIME_WEBHOOK_SECRET_ROTATION_ENABLED=false
CONNECTOR_RUNTIME_WEBHOOK_REPLAY_REQUEST_ENABLED=false
```

There is no ordinary connector activation endpoint. Activation remains a protected release/canary operation.

## Required runtime bindings

```text
CONNECTOR_RUNTIME_DATABASE_URL
CONNECTOR_RUNTIME_CURSOR_HMAC_KEY
CONNECTOR_RUNTIME_BODY_ENCRYPTION_KEY_FILE
CONNECTOR_RUNTIME_RELEASE_SHA
CONNECTOR_RUNTIME_KEYCLOAK_ISSUER
CONNECTOR_RUNTIME_KEYCLOAK_JWKS_URL
CONNECTOR_RUNTIME_OAUTH_AUDIENCE
CONNECTOR_RUNTIME_ALLOWED_AZP
```

Webhook secret aliases are resolved from `<ALIAS>_FILE` first and then `<ALIAS>`. Secret values are never returned by the API or stored in Git.

## Webhook acknowledgement rule

A provider callback receives `202` only after:

1. route ownership is resolved from the secret-free webhook index;
2. connector and endpoint state are active;
3. exact raw-body signature and timestamp are verified;
4. the raw body is encrypted and fsynced to durable storage;
5. the tenant-bound event key is claimed or classified as an exact duplicate;
6. a durable inbox row exists;
7. a transactional outbox row exists for a new delivery.

Reusing an event ID with a changed body returns `409 WEBHOOK_SEMANTIC_CONFLICT`.

## Remaining separate workstreams

- trusted product adapters;
- durable normalization, command, outbox, reconciliation, retention and dead-letter workers;
- immutable Docker images and Compose/Kubernetes deployment;
- Keycloak and Kong desired-state apply;
- inactive n8n workflow-pack import;
- isolated no-effect staging, backup/restore and rollback;
- bounded production activation canaries.
