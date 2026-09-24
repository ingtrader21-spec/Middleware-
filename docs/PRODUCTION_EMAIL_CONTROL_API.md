# Production Email Control API

Date: 2026-09-12

## Purpose

This contract adds the missing fail-closed production authorization layer around the existing email transport. It does **not** create a second email-send API, does not alter protected migration history, and does not move provider authority out of Klyrow.

Canonical path remains:

`Odoo / n8n / product caller -> Middleware -> Klyrow -> Postal -> receiver`

Delivery/read-back remains:

`Postal/Klyrow event -> Middleware -> communications projection -> Odoo/product read-back`

## Existing canonical transport surfaces (preserved)

### Middleware product API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/v1/communications/messages` | Canonical product submission for email/SMS. Email is production-gated before command creation. |
| `GET` | `/v1/communications/messages` | Tenant-scoped message list. |
| `GET` | `/v1/communications/messages/by-idempotency` | Idempotency read-back. |
| `GET` | `/v1/communications/messages/{messageId}` | Durable message state/read-back. |
| `GET` | `/v1/communications/messages/{messageId}/events` | Canonical lifecycle timeline. |
| `POST` | `/v1/communications/messages/{messageId}/cancel` | Cancel a non-terminal message where supported. |

The legacy singular alias `POST /v1/communication/messages` remains compatibility-only. New callers must use `/v1/communications/messages`.

### Middleware -> Klyrow private transport

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | Klyrow `/v1/email/messages` | Authenticated command-bound email submission. |
| `GET` | Klyrow `/v1/email/messages/{command_id}` | Authoritative provider-side read-back after uncertain outcomes. |

The Middleware Klyrow adapter retains command identity `email.message.send.v1`, target `klyrow-email`, and capability `EMAIL_DELIVERY`.

### Klyrow -> Middleware events

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/internal/provider-events/klyrow` | Signed durable ingress for delivery, usage, and supported inbound events. |

Accepted email lifecycle events include accepted, queued, submitted, sent, delivered, deferred, bounced, complained, rejected, failed, cancelled, unknown outcome, opened, clicked, and unsubscribed. Exact replay is deduplicated; changed content under an existing event identity is rejected.

The dedicated mTLS Klyrow callback route projects each durable delivery event
into the same canonical communication message used for submission and read-back.
It resolves Klyrow's provider message ID through the original command
`operation_id`, including after a different Middleware process accepted the
send. The raw callback remains pending and Klyrow receives a retryable failure
until that canonical message exists; a replay after a partial commit is safe.

Odoo uses the dedicated `odoo-email` caller with `odoo.email.command.write` and
`odoo.email.status.read`. Its idempotency read-back is channel-scoped to email,
as `odoo-sms` is scoped to SMS. Odoo can therefore retain one local projection
while Middleware remains the lifecycle authority.

## New production-control surface

Prefix: `/platform/v1/email/production`

These endpoints require a Keycloak machine identity with `azp=production-operator`, audience `middleware-api`, tenant binding, and the configured production-control scopes. Mutations additionally require exactly one `X-Correlation-ID` and `Idempotency-Key`.

| Method | Endpoint | Scope | Purpose |
| --- | --- | --- | --- |
| `GET` | `/platform/v1/email/production/status` | `email.production.read` | Read effective tenant production policy. |
| `GET` | `/platform/v1/email/production/readiness` | `email.production.read` | Return activation blockers; does not mutate provider/runtime state. |
| `GET` | `/platform/v1/email/production/quotas` | `email.production.read` | Read current minute/hour/day usage and limits. |
| `GET` | `/platform/v1/email/production/audit` | `email.production.read` | Read production-control audit history. |
| `POST` | `/platform/v1/email/production/authorize` | `email.production.write` | Record reviewed tenant/domain/sender/recipient/quota authorization. Does not start sending. |
| `POST` | `/platform/v1/email/production/activate` | `email.production.write` | Activate only when all fail-closed readiness gates pass. |
| `POST` | `/platform/v1/email/production/revoke` | `email.production.write` | Revoke authorization, return mode to SAFE, and close the kill switch. |
| `POST` | `/platform/v1/email/production/kill-switch` | `email.production.write` | Open/close new-send permission. Opening requires active authorization. |

## Production modes

- `SAFE`: no production email is authorized.
- `TRANSACTIONAL_CANARY`: explicit recipient allowlist; tight quota; transactional only.
- `TRANSACTIONAL_PRODUCTION`: transactional recipients within an explicit address or recipient-domain allowlist.
- `CAMPAIGN_PRODUCTION`: represented for forward compatibility but rejected by this API until the separate campaign compliance gate is implemented and certified.

Campaign mode is never inferred from transactional activation.

## Authorization model

An authorization records tenant, approved domains/senders, bounded recipient scope, recipient or recipient-domain allowlist, approved transaction categories, minute/hour/day quotas, validity window, change ID, approving and activating actors, production/monitoring/escalation/rollback owners, kill-switch procedure, provider, environment, exact release SHA, authorization/activation timestamps, and requested mode.

The legacy `TRANSACTIONAL_ANY` enum value can still decode historical ledger records, but new authorization rejects it and readiness reports it as unbounded. The active transactional modes never authorize marketing.

`authorize` moves the policy to `AUTHORIZED_NOT_ACTIVE`. It does not open the send path.

`activate` moves it to `ACTIVE` and opens the kill switch only if readiness returns no blockers.

`revoke` closes the path and returns the policy to `SAFE`.

## Readiness / activation blockers

Activation fails closed when any required condition is missing, including:

- production authorization;
- non-SAFE production mode;
- `PRODUCTION_ACTIVATION_ID` deployment binding;
- effective Middleware email-delivery runtime gate;
- valid authorization time window;
- approved domains/senders;
- approved transaction categories and a bounded recipient scope;
- complete production owner/escalation/rollback/kill-switch record;
- `provider=klyrow-postal` and matching deployment environment;
- exact authorized Middleware release SHA matching the running source;
- positive quota limits;
- registered Postal domain;
- Postal DNS check pass;
- DKIM rotation complete;
- post-rotation DNS recheck complete;
- Middleware send eligibility;
- domain production-ready certification.

A previous DNS pass alone is explicitly insufficient.

## Send-path enforcement order

For production email, Middleware applies the gates in this order:

1. original bearer and tenant authorization;
2. production policy active;
3. kill switch open;
4. authorization validity window;
5. approved domain;
6. approved sender;
7. mode/category rule;
8. recipient scope / canary allowlist;
9. database-backed idempotency serialization across API processes;
10. atomic minute/hour/day quota reservation;
11. existing verified sender/domain check;
12. existing suppression and consent pre-check;
13. existing command-policy authorization;
14. durable `email.message.send.v1` command handoff;
15. Klyrow adapter runtime gate and exact Middleware release binding;
16. command-bound production attestation over authenticated private transport;
17. Klyrow sender/domain/suppression/provider policy.

If existing suppression/consent logic suppresses before provider submission, the quota reservation is released. Exact idempotent replay returns the prior logical message and does not consume another reservation. A PostgreSQL advisory lock serializes the same tenant/route/idempotency identity across Middleware processes before any command is created; the durable projection is refreshed while that lock is held.

Each Klyrow command carries one recipient so one platform message has one durable provider lifecycle and one metered send. Middleware injects the production attestation after the caller request digest is calculated, so a caller cannot spoof it and idempotent replay continues to use the caller's original semantic request. The Klyrow adapter adds a binding for command ID, correlation ID, idempotency-key digest, sender, and recipient-list digest before submission.

## Durable persistence without migration-history bypass

Production-control state reuses the already-certified immutable `middleware_event_ledger`; no existing migration is modified and no unapproved numbered SQL file is inserted.

The ledger records three event families:

- `codestra.email.production.policy.changed`
- `codestra.email.production.quota.reserved`
- `codestra.email.production.quota.released`

Policy state is event-sourced from the latest tenant policy event. Control mutations are idempotent through ledger idempotency identity. Every policy event includes previous policy, new policy, actor, reason, request hash, and correlation identity.

Quota reservations and releases are also append-only ledger events. A tenant advisory transaction lock serializes quota decisions with policy mutations. Current minute/hour/day usage is calculated as reservations in the active window minus released reservations. This preserves durable quota evidence without changing the protected production schema head.

The existing event-ledger hash chain remains authoritative for integrity verification.

## Audit and mutation idempotency

Control mutations are idempotent by tenant + action + actor + `Idempotency-Key`. Reusing the same key with different content returns conflict.

Audit read-back is derived from immutable production policy events and exposes actor, reason, correlation ID, previous policy, new policy, and recorded timestamp.

## Ownership boundaries

### Odoo

Business system of record. Odoo can request sends through the canonical communications API and read lifecycle state, but it does not own global production authorization.

### n8n

Workflow orchestrator only. It cannot activate production email and its provider writes remain separately controlled by `N8N_EXTERNAL_PROVIDER_WRITES`.

### Middleware

Owns platform authorization, tenant/sender/domain production policy, production quotas, kill switch, durable command handoff, callback normalization, and canonical read-back.

### Klyrow

Owns provider mail policy, sender/domain provider state, suppression/bounce/complaint handling, DKIM signing, reputation, and Postal integration.

### Postal

Provider transport; applications must not submit directly to Postal.

## Deployment requirement

No new database migration is introduced by this production-control change. The implementation depends on the existing certified event ledger and communications schema already required by Middleware readiness.

The source change does **not** authorize live sending. Production remains blocked until the deployment has a real `production-operator` Keycloak identity/scopes and the domain registry has documented DKIM rotation/post-rotation certification and send eligibility.
