# Lead Automation generic n8n workflow V1

This directory contains source-only deployment artifacts for the logical workflow `lead-automation-generic-v1`. The generic ingress is `POST /webhook/v1/events`; Middleware selects it through binding key `n8n.leads.ingest`.

This resynchronized source retains PR #65's original fail-closed boundary: n8n may validate and transform allowlisted metadata and return a signed, idempotent result only; it cannot act as an application or data-access service.

Supported event types are `lead.creation.requested.v1`, `lead.update.requested.v1`, `lead.assignment.requested.v1`, `lead.status_change.requested.v1`, and `lead.callback_requested.v1`. The copied event, result, status, and eight business-unit schemas are byte-identical to Middleware schema source `da215762375614aa617bf838f9e4974ac2ad7c68`; provenance also binds callback authentication head `04fa56f4c8bb8caea3e5281816a2986bcb47ba05` and Odoo head `384d175eb32bc87f34b9c736453db44c2d151b1a`.

## Default-off boundary

The workflow export has `active: false`; every node is disabled; the binding candidate has `enabled: false`; and lead automation is disabled. Import, binding registration, credential assignment, and activation require separate staging authorization. A real n8n workflow ID never appears in application configuration or payloads. The synthetic UUID `00000000-0000-4000-8000-000000000013` exists only because the pinned importer requires a source ID; it is not an instance workflow ID and must never be registered as one.

## Callback and credentials

The only outbound target is the runtime `MIDDLEWARE_INTERNAL_URL` plus `/api/v1/lead-automation/results`. HMAC-V2 signs exactly 11 newline-separated fields without a terminal newline: version, method, path, timestamp, nonce, identity, audience, environment, scope, idempotency key, and exact-body SHA-256. The callback scope is `lead-automation.results.write`. Assign `LEAD_AUTOMATION_CALLBACK_HMAC_SECRET` through the authorized runtime secret mechanism during a separately approved staging import. Never place a value or live credential ID in this export. The n8n Code node requires the pinned built-in `crypto` module allowance.

## Data and node boundary

Ingress and result payloads are strict allowlists. Raw contact details, names, notes, credentials, provider tokens, recording data, filesystem paths, object keys, and arbitrary URLs are rejected recursively. The workflow has no Odoo, database, communication, calendar, appointment, calling, or recording node. It never claims Odoo applied a change.

## Idempotency and retry

Workflow static data retains a bounded digest ledger. Identical event replay returns the original deterministic acknowledgement without another callback. Conflicting replay fails closed. Callback attempts are limited to five, matching the disabled binding candidate. Only network failures and HTTP `429`, `500`, `502`, `503`, and `504` are retryable; authentication, schema, scope, policy, consent, DNC, and idempotency conflicts are permanent.

## Staging import and rollback

For a separately approved staging exercise: verify the image digest in `workflow-manifest-v1.json`, import while inactive, assign a staging-only runtime secret, register an exact business-unit/campaign binding while disabled, run offline acceptance, and obtain activation approval. Until then, do not import or activate. See `ROLLBACK.md` for removal boundaries.
