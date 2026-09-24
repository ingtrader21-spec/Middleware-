# One-Codex Cross-Repository Integration and Certification Design

## Status and authority

This is the repository copy of the user-approved mission dated 2026-09-16. It
coordinates Caddy, Kong, Keycloak, Middleware, Odoo, and N8N without granting
production activation, deployment, provider delivery, dialing, email/SMS, or
live Odoo writes. `TEST_SYN` is the only campaign allowed for runtime probes.

## Canonical ownership

- Caddy owns TLS, hostname selection, and first-hop routing to Kong.
- Kong owns exact route/method matching, authentication enforcement, scopes,
  limits, and correlation propagation.
- Keycloak owns service identities, audience `middleware-api`, approved scopes,
  and token issuance.
- Middleware owns cross-system commands, policy, durable idempotency, sagas,
  callbacks, audit, status, and reconciliation.
- Odoo owns `cc.campaign`, desired/effective state, immutable configuration
  versions, business records, and provisioning history.
- N8N owns inactive, credential-free workflow definitions only.

## Contract decision

`Middleware-/deploy/public-api-route-contract.json` is the single canonical
public route contract. It is expanded in place and copied byte-for-byte into
consumer repositories. Its canonical digest is SHA-256 over compact,
key-sorted JSON. Every operation declares `operation_id`, `method`, `path`,
`classification`, `calling_client`, `audience`, `scope`, request/response
schema references, idempotency rules, correlation/echo fields, error statuses,
owner, and upstream.

The contract includes all `/v2/automation/*` operations, the explicitly
required `/platform/v1/*` operations already exposed by the deployed app,
`POST /api/v1/odoo/events`, N8N result submit/read, Odoo campaign and
desired-state reads, Middleware-to-Odoo automation-result delivery, and
campaign actual-state readback. Private Middleware-to-Odoo routes remain
`private_only`; retired command aliases are `denied`.

## Shared invariants

- Shared edge path is Caddy -> Kong -> `middleware-integration-api:8095`.
- Port 8080 is not canonical Middleware routing.
- Missing/invalid identity returns 401; insufficient valid identity returns
  403; hidden or cross-tenant resources return 404; lifecycle/idempotency
  conflicts return 409; invalid authenticated data returns 422.
- N8N and Odoo never call providers directly. Odoo campaign delivery is
  pull-only; Middleware reports provider readback and never chooses desired
  campaign state.
- Exact duplicate intake produces one durable event and one saga execution.
- All workflows, clients, provider writes, live delivery, live dialing, and
  production apply controls remain disabled.

## Verification and verdicts

Certification is rerun at exact final SHAs. Evidence records contract digest,
route/client/scope matrix, test commands and exit codes, local runtime results,
and blockers. Verdicts are separate: `SOURCE_GO`, `LOCAL_INTEGRATION_GO`,
`STAGING_GO`, and `PRODUCTION_GO`. This mission can never issue
`PRODUCTION_GO`.
