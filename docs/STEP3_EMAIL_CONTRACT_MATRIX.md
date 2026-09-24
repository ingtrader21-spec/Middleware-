# Step 3 Email Contract Matrix

Date: 2026-08-30

| SDK Contract Surface | Middleware Status | Notes |
| --- | --- | --- |
| `POST /v1/communications/messages` | Implemented | Email only. Requires `X-Tenant-ID`, `X-Correlation-ID`, `Idempotency-Key`, bearer token. |
| `GET /v1/communications/messages` | Implemented | Tenant-scoped list with optional channel/status filters. |
| `GET /v1/communications/messages/{messageId}` | Implemented | Cross-tenant lookups return not found after tenant authorization. |
| `GET /v1/communications/messages/{messageId}/events` | Implemented | Returns canonical status timeline. |
| `POST /v1/communications/messages/{messageId}/cancel` | Implemented | Blocks terminal delivered/failed/suppressed messages. |
| Message idempotency | Implemented | Same key and same payload returns same message; same key and different payload returns conflict. |
| Consent/suppression pre-check | Implemented | Suppressed and denied-consent recipients do not create provider commands. |
| Command ledger handoff | Implemented | Creates `email.message.send.v1` command targeting `klyrow-email`. |
| Unknown provider outcome | Implemented | Exactly one execution attempt; command becomes `reconciliation_required` and message becomes `indeterminate`. |
| Reconciliation read-back | Implemented for source evidence | Separate bounded workflow performs authoritative-read-back fixture attempts and never resubmits the command. Live Klyrow binding remains a staging/production gate. |
| Klyrow event normalization | Implemented | Signed webhook payloads update canonical read model. |
| Callback replay protection | Implemented | Exact replay is deduplicated; changed content under the same event identity is rejected. |
| Provider health | Partial | Safe placeholder adapter returns disabled until live Klyrow adapter wiring is deployed. |
| Usage/reputation read models | Partial | Local runtime aggregates are present; production-grade provider-backed views remain gated. |
| Durable communications read model | Partial | In-memory Step 3 implementation; durable migration required before production. |
