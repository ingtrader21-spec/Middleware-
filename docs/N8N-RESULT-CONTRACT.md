# n8n result contract

The canonical callback is `POST /api/v1/n8n-runtime/results` with schema
`codestra.n8n.result.v1`. It binds workflow code/version, execution,
correlation, tenant, status, timestamp, and bounded result data.

Required headers bind identity, tenant, workflow, execution, correlation,
timestamp, nonce, exact body SHA-256, and HMAC version 1 signature. The HMAC
secret is read from a protected file. Nonces are recorded durably before the
transaction commits; replay, stale timestamp, modified body, cross-tenant
binding, unknown schema, and unknown fields fail closed.

Results never directly mutate Odoo or VICIdial. They become durable middleware
records for an independently governed adapter/outbox.

## Standard results and Odoo delivery

Standard results are submitted to `POST /api/v1/integrations/n8n/results`
(n8n service JWT, scope `n8n.results.submit`, `202 Accepted`). Accepted
actions are delivered to Odoo through the registry operation
`odoo.automation_results.apply` (`POST /api/v1/integration/automation-results`,
scope `odoo.integration.automation_results.write`, registered by migration
0066). They are never delivered through the retired 0054 `campaign-actions`
route, which 0066 kill-switched; Middleware exposes no `campaign-actions` or
`campaign-commands` route of its own.

## Delivery-state readback

`GET /api/v1/integrations/n8n/results/{event_id}` (n8n service JWT, scope
`n8n.results.read`) returns delivery state only for the submitting n8n
identity:

| Field | Meaning |
| --- | --- |
| `event_id` | The submitted `event_id`. |
| `receipt_id` | Middleware delivery public id. |
| `status` | Delivery status (`PENDING`, `RESERVED`, `RETRY`, `DELIVERED`, `DEAD_LETTER`). |
| `attempts` | Odoo delivery attempts so far. |
| `delivered_at` | ISO-8601 timestamp, or `null` until delivered. |
| `last_error_class` | Last delivery error class, or `null`. |

Missing records and records outside the caller's campaign or business-unit
scope return the identical `404` so the route cannot be used to probe other
campaigns' event ids. Results without actions create no delivery and
therefore read back `404`. The route never returns the result payload or the
Odoo response body.
