# ADR-0001 — Middleware adopts the automation v2 contract

- **Status:** Accepted
- **Decision date:** 2026-08-30
- **Owner:** Ralph L. Appolon
- **Repository:** `appolon1908-hue/Middleware-`
- **Supersedes:** any assumption that n8n will be rewritten to the Middleware v1 API

## Context

Middleware already has a durable v1 integration core: command ledger, idempotency,
inbox, outbox, replay, dead letters, reconciliation, leases, tenant authorization,
and immutable event evidence. The n8n estate was designed against a different v2
automation contract with job leasing, exact client scopes, workflow-family
isolation, approvals, capabilities, reconciliation, and controlled replay.

The mismatch is an integration-contract defect, not permission to weaken either
side's security properties.

## Decision

**Option A is authoritative: Middleware adopts the automation v2 contract.**

The v1 connector, intake, product-control-plane, and webhook APIs remain supported.
The two n8n v1 routes are compatibility aliases only and emit deprecation and
sunset headers. The canonical n8n automation surface is `/v2/automation/*`.

## Non-negotiable invariants

1. Tenant authority comes from a verified token or the durable job record, never
   from a caller-supplied tenant header.
2. Scope resolution is exact. There is no generic execute scope and no implicit
   union of client scopes.
3. A durable inbox record is committed before acknowledgement.
4. A lease is required for step, command, heartbeat, and terminal transitions.
5. Unknown provider outcome requires destination reconciliation before retry.
6. Capabilities are rechecked immediately before an external effect.
7. `ODOO_WRITE`, `live_apply_authorized`, and every external-delivery switch
   remain false through staging certification.
8. Existing correct v1 durability and tenant checks are reused, not rewritten.

## Consequences

- Middleware owns the PostgreSQL automation job and approval state.
- n8n remains the orchestrator and may only act within its declared workflow
  family and command prefix.
- Ten Keycloak machine clients and their exact scopes become part of the
  cross-repository identity contract.
- The conformance gap registry is a strict build artifact: an undocumented
  missing route or a stale waiver fails CI.
- Production activation is outside this ADR and remains separately approved.

## Compatibility and retirement

The legacy n8n endpoints are scheduled for retirement no earlier than
2027-06-30 and only after v2 staging certification and consumer cutover evidence.
`/v1/commands` is not an n8n alias; it remains a separate product/service
control-plane API.
