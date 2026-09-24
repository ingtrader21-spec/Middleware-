# Step 4 SMS API Contract Matrix

Date: 2026-08-30

| Surface | State | Contract |
|---|---|---|
| `POST /v1/communications/messages` | Implemented | `channel=sms`; exactly one E.164 recipient; approved E.164 or alphanumeric sender; text only; mandatory tenant, correlation, idempotency, bearer scope. |
| `GET /v1/communications/messages` | Implemented | Tenant-scoped list with `channel=sms` and canonical status filtering. |
| `GET /v1/communications/messages/{messageId}` | Implemented | Tenant-scoped command/read-model reconciliation. Unknown submission remains `indeterminate`. |
| `GET /v1/communications/messages/{messageId}/events` | Implemented | Ordered canonical timeline with provider status retained as evidence. |
| `POST /v1/communications/messages/{messageId}/cancel` | Implemented | Idempotently dead-letters a persisted/queued command before provider dispatch; refuses an in-flight command. |
| `GET /v1/communications/usage` | Implemented | Provider-neutral accepted/delivered/failed/suppressed counts split by email and SMS. |
| `GET /v1/communications/providers/health` | Prepared | Returns both Klyrow and Telnexa as disabled until provider bindings are reviewed and activated. |
| `POST /api/v1/telnexa/events` | Implemented (legacy envelope) | OIDC, HMAC, freshness, durable replay control, then canonical DLR/MO/STOP/HELP normalization for the Codestra event envelope. |
| `POST /api/v1/events/telnexa` | Implemented (provider callback) | Exact Telnexa billing-worker envelope; Bearer shared API key plus HMAC over `timestamp\nevent_id\ntelnexa\n` and raw JSON; durable inbox/analytics projection updates the Middleware message Odoo polls. |

## Durable command mapping

An accepted SMS creates exactly one `sms.message.submit.v1` command targeting
`telnexa-sms` with capability `SMS_DELIVERY`. Its payload is validated against
`contracts/telnexa-sms-command.v1.schema.json` and carries normalized sender,
destination, content, encoding, character count, segment count, category,
client reference, schedule, and optional billing/campaign references.

No provider password, Jasmin credential, bearer token, or private key is part of
the command payload.

## Signed Telnexa events

The provider callback at `/api/v1/events/telnexa` is a separate wire contract.
Telnexa sends it over internal mTLS with `Authorization`, `X-Event-Id`,
`X-Timestamp`, `X-Signature`, and `Idempotency-Key`. Its body is defined by
`contracts/telnexa-delivery-event.v1.schema.json`; the endpoint accepts only the
four versioned SMS delivery event types in that schema. It is fail-closed behind
`TELNEXA_EVENT_INGRESS_ENABLED` and the Middleware `SMS_DELIVERY` umbrella gate.
An event is acknowledged only after the inbox, message projection, immutable
timeline, provider-event evidence, and analytics row are durable. If the
original Middleware message is not available, the event is retained for retry
and the endpoint returns 503 so Telnexa does not lose delivery state.

The reviewed event allowlist is:

- `codestra.events.sms_received`
- `codestra.sms.help_requested`
- `codestra.sms.inbound.received`
- `codestra.sms.message.delivered`
- `codestra.sms.message.failed`
- `codestra.sms.recipient.opted_out`

Exact event replays are acknowledged without a second timeline effect. Reusing
an event identity with different content is rejected. A late `sent` event never
downgrades a delivered SMS.
