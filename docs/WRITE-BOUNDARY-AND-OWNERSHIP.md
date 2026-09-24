# Sole cross-system write boundary and system ownership

**Status:** Accepted and binding for all Codestra integrations.

## Decision

Codestra Middleware is the only component allowed to authorize and execute a cross-system mutation. Portals, browser clients, n8n workflows, provider services, telephony services, crawlers, and reporting tools may request work or publish events, but they may not bypass Middleware to create an externally meaningful effect.

This decision separates three responsibilities:

- **Middleware owns correctness and security.**
- **n8n owns orchestration.**
- **Odoo 19 owns the business record.**

A successful workflow run is not proof that a business mutation was authorized, unique, durable, or reconciled. Those guarantees belong to Middleware.

## Middleware ownership

Middleware owns:

- service authorization and least-privilege scopes;
- tenant isolation and authoritative tenant mapping;
- request and event contract validation;
- event normalization;
- idempotency and deterministic duplicate outcomes;
- semantic replay detection across different request identifiers;
- correlation and causation identifiers;
- signed webhook verification and durable inbox acceptance;
- transactional outbox creation;
- worker leases, retry, exponential backoff, jitter, and maximum age;
- dead-letter and operational-exception records;
- circuit breakers and dependency health state;
- consent and suppression checks;
- provider adapters and provider-specific reconciliation;
- Odoo external-ID mappings;
- n8n trigger and callback contracts;
- telephony command records;
- immutable audit and reconciliation evidence.

Every mutating integration path must enter through an authenticated Middleware command boundary and carry a stable idempotency key. Equivalent business intent must also produce a stable semantic fingerprint so the same SMS, email, call, social publication, CRM mutation, callback, or crawler action cannot be repeated merely by changing a request ID.

## n8n ownership

n8n may:

- arrange approved Middleware commands into workflows;
- branch, wait, schedule, aggregate, notify, and request human approval;
- call Middleware command, query, and trigger-contract endpoints;
- consume normalized, non-secret results returned by Middleware.

n8n must not:

- hold Odoo or provider write credentials;
- authorize a tenant or service;
- validate the authoritative business contract;
- decide whether a command is a duplicate or replay;
- own retry, reconciliation, or dead-letter state for external effects;
- write directly to Odoo, VICIdial, Asterisk, Telnexa, Klyrow, Postly, Mautic, Postal, Jasmin, a crawler, or another provider;
- connect directly to Odoo PostgreSQL;
- create a generic model-write path around the approved Odoo integration bridge.

An n8n retry may repeat a request to Middleware with the same idempotency key. It may not create a new key to force the external effect to happen again.

Versioned n8n workflow exports may use the generic HTTP Request node only when the URL starts with the exact `{{$env.MIDDLEWARE_BASE_URL}}` expression and an approved Middleware path (`/v1/commands`, `/v1/queries`, or `/v1/triggers`). Hard-coded hosts, caller-built hosts, Odoo/provider URLs, and other dynamic base expressions fail CI.

## Odoo 19 ownership

Odoo 19 is the business system of record for:

- customers and contacts;
- leads and opportunities;
- activities and campaigns;
- call history;
- post-call forms and notes;
- callbacks and appointments;
- consent and communication preferences;
- SMS and email history;
- delivery results;
- agent and supervisor business views;
- business reporting.

Middleware may write Odoo only through an approved, narrow service API or Odoo ORM bridge. No external service may receive Odoo PostgreSQL write credentials or write directly to Odoo tables.

The approved bridge must:

- authenticate a dedicated Middleware service identity;
- enforce least-privilege access controls and record rules;
- resolve the authoritative tenant and company;
- accept versioned, resource-specific commands rather than arbitrary model names;
- store the Middleware command ID and idempotency key in the same Odoo transaction as the business change;
- preserve stable external mappings;
- reject duplicates deterministically;
- return the existing result for an already-applied command;
- record a safe audit trail and correlation ID;
- expose reconciliation queries without exposing unrestricted ORM access.

## Canonical mutation sequence

```text
caller or n8n
  -> Kong/Caddy edge
  -> Middleware authentication and tenant authorization
  -> schema validation
  -> idempotency lookup and semantic replay check
  -> consent/suppression and capability checks
  -> local transaction: command + audit + outbox
  -> asynchronous adapter worker
  -> approved provider API or Odoo service API/ORM bridge
  -> provider/Odoo result reconciliation
  -> delivery/result ledger
  -> normalized result event and business-history update
```

A provider timeout is an unknown outcome. Middleware must reconcile before issuing another externally effective attempt.

## Webhook sequence

```text
provider callback
  -> Middleware raw-body capture
  -> signature and timestamp verification
  -> tenant/provider mapping
  -> durable inbox insert using provider event ID and body digest
  -> success acknowledgement
  -> normalized asynchronous processing
  -> idempotent business update through the same write boundary
```

Operator replay is an audited command. Replay never bypasses signature evidence, tenant authorization, idempotency, semantic duplicate detection, consent, suppression, or capability controls.

## Allowed paths

- Portal -> Middleware query API.
- Portal -> Middleware command API.
- n8n -> Middleware command API using a short-lived service identity.
- Middleware -> Odoo service API or ORM bridge.
- Middleware -> provider adapter.
- Provider -> Middleware signed webhook inbox.
- Middleware -> n8n normalized trigger contract.
- Read-only reporting/exporter access using separate least-privilege identities.

## Forbidden paths

- Portal or browser -> Odoo write API.
- Portal or browser -> provider write API.
- n8n -> Odoo.
- n8n -> provider.
- Any external service -> Odoo PostgreSQL.
- Any application, Compose, Kubernetes, deployment, workflow, or root configuration that supplies Odoo PostgreSQL credentials to Middleware or another external service.
- Any service -> a generic `model + method + values` Odoo endpoint.
- Direct writes to another system's database as a substitute for its approved service contract.
- Retrying a timed-out write with a new idempotency key before reconciliation.
- Replaying a dead-letter item by editing database state manually.

## Required persistence

The Middleware database must retain durable records for:

- command identity, tenant, actor, schema version, and normalized intent;
- idempotency key and original response;
- semantic fingerprint and duplicate relationship;
- correlation and causation IDs;
- consent/suppression decision evidence;
- outbox delivery state and attempt history;
- inbox signature, event ID, body digest, and processing state;
- provider request reference, response reference, and unknown-outcome state;
- dead-letter reason and audited replay command;
- Odoo/provider mappings;
- immutable audit and reconciliation records.

Redis may provide short-lived leases and cache state. It is not the source of truth for command acceptance, inbox, outbox, delivery results, or audit.

## Acceptance gates

A mutating integration is not ready to merge or activate until tests prove:

1. unauthorized services and cross-tenant commands fail closed;
2. malformed and unsupported contracts fail closed;
3. the same idempotency key never repeats an effect;
4. equivalent semantic intent under a different key is detected;
5. concurrent duplicates produce one durable command and one external effect;
6. the command and outbox are committed atomically;
7. webhooks are durably accepted before acknowledgement;
8. stale, unsigned, duplicate, and tenant-conflicting callbacks are rejected or quarantined;
9. timeouts reconcile before retry;
10. retries are bounded and exhausted work becomes an operational exception;
11. replay is audited and cannot bypass policy;
12. Odoo changes are performed only through the approved service API/ORM bridge;
13. no external component has Odoo PostgreSQL write credentials;
14. staging starts with all external effects disabled;
15. the exact protected merged SHA and immutable image digest are observable.

## Repository boundary

This Middleware repository contains application source, contracts, migrations, tests, workers, adapters, and non-secret deployment controls. The Odoo repository contains custom modules, module tests, migrations, and deployment controls.

Neither repository contains production databases, Odoo filestore, queue contents, credentials, certificates, customer payloads, runtime logs, backups, or manual edits copied from running containers.
