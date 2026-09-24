# Middleware staging-sync production blockers

Date: 2026-09-03  
Source authority: `appolon1908-hue/Middleware-`  
Protected base: `9cd3fd3e46fb0366fbff69aeef251a1b85beff1d`

## Purpose

PR #105 compares the legacy `staging` branch with protected `main`. Its exact-head review exposed four current-main defects that must be repaired in a dedicated protected PR before staging synchronization or production runtime certification.

## Required remediation

### 1. Durable reconciliation dispatch

Manual reconciliation for operations in `dispatching`, `accepted`, or `readback_pending` must not enqueue an unsupported partial payload to the normal `temporal-command` dispatcher. Implement a dedicated reconciliation destination/handler or produce a versioned, fully authenticated reconciliation envelope that the dispatcher validates and executes without blind provider resubmission.

Acceptance:

- authenticated tenant and machine-client provenance are durable;
- operation ID, expected version, safe reason, correlation, and idempotency are validated;
- one transactional mutation/audit/outbox intent is written;
- provider calls are not made synchronously;
- unknown outcomes remain read-back/reconciliation only;
- retry/dead-letter behavior is deterministic;
- source and PostgreSQL integration tests cover success, replay, stale version, unsupported state, missing provenance, and dispatch failure.

### 2. Multi-endpoint generic webhook routing

Generic webhook contract lookup must use both connector identity and endpoint identity. A connector with multiple endpoints, including `kyqra-gateway` results and progress routes, must not overwrite one contract with another.

Acceptance:

- lookup key includes `connector_key` and `endpoint_key`;
- each declared endpoint accepts only its allowed event types;
- wrong endpoint/event combinations fail closed;
- duplicate, changed-body, signature, replay, tenant, and bounded-body protections remain unchanged;
- tests cover at least two endpoints on one connector.

### 3. Klyrow production secret mount paths

The observability-alert production environment values must match the actual Docker Compose secret targets. Either set explicit Compose `target` values or use the underscore-based `/run/secrets/<secret_name>` paths created by short syntax.

Acceptance:

- client secret, CA, certificate, and private-key paths match Compose mounts exactly;
- files remain external secrets and are never committed;
- startup/readiness fail closed when any secret is absent or unreadable;
- static Compose/environment validation prevents future drift;
- no provider connection or email is attempted by source validation.

### 4. Compatibility capability resolution

The compatibility policy API must resolve effective implementation capabilities and umbrella controls from the same runtime-safety structure as the canonical policy-decision API. It must not return `DENY` for an effectively enabled capability while the canonical endpoint returns `ALLOW`.

Acceptance:

- both APIs use one shared resolver;
- implementation capability and umbrella-control semantics are explicit;
- malformed, unknown, absent, or disabled values fail closed;
- tests prove parity for enabled, disabled, umbrella-denied, unknown, and malformed cases;
- all checked-in production effects remain disabled.

## Mandatory validation

- exact source-head and merge-result validation;
- complete locked test suite;
- PostgreSQL/Redis, NATS JetStream, Temporal, and synthetic no-effect E2E;
- runtime and test image builds;
- Connector Runtime independent build and API/storage suites;
- generated API contract parity;
- SBOM and fixable high/critical vulnerability enforcement;
- all review conversations resolved on the final unchanged head.

## Safety boundary

This work is source-only. It must not deploy staging or production, execute live migrations, create credentials, alter DNS/Caddy/Kong/Keycloak, call providers, send email or SMS, place calls, publish content, enable Odoo/n8n/VICIdial writes, or change SSH.
