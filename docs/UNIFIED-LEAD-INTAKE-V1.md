# Unified Lead Intake V1

## Purpose

Provide one canonical pipeline for every landing page, website form, chat widget, voice capture flow, or trusted API integration. Every channel creates the same durable lead-submitted event before any downstream write occurs.

## Flow

`site/form/chat/voice -> @codestra/intake-sdk -> same-origin BFF -> Kong -> Middleware -> durable inbox -> routing/dedupe/enrichment -> Odoo CRM -> n8n/comms/analytics`

Middleware remains the only cross-system write authority. The intake endpoint must never write directly to Odoo in the HTTP request path.

## Security boundary

Browser code must not contain Keycloak client secrets or long-lived Middleware bearer tokens. Browser SDK calls terminate at a same-origin BFF. The BFF authenticates to Kong/Middleware using a short-lived service token for the `sdk-intake` client and a narrow `leads.write` scope.

Middleware must verify:

- bearer token and expected client identity;
- `leads.write` scope;
- token tenant membership;
- `X-Tenant-ID` equals the payload tenant;
- stable `Idempotency-Key`;
- correlation ID;
- maximum request size;
- canonical field constraints.

Kong should provide rate limits and abuse protection per tenant/site/client. CAPTCHA or bot scoring belongs at the site/BFF boundary; Middleware should preserve the score as metadata but must not trust browser assertions as authentication.

## Canonical lead fields

Required: `tenantId`, `siteId`, `source`.

Optional: campaign/form IDs, name, email, phone, message, conversation ID/transcript, consent state, UTM/referrer/landing-page attribution, custom fields, and bounded metadata.

## Delivery semantics

The HTTP path only validates/authenticates and inserts the event into the durable inbox. A duplicate idempotency key returns the existing event as duplicate. Workers then perform dedupe, enrichment, CRM upsert, outbox publication, and downstream notifications.

## Next implementation gates

1. Wire `POST /v1/intake/leads` into `app/main.py` behind the `sdk-intake`/`leads.write` authorization contract.
2. Add Keycloak managed client/role configuration and Kong route policy in their authority repos.
3. Add inbox worker mapping from `codestra.events.lead_submitted` to an Odoo lead-upsert command.
4. Add email/phone normalization, duplicate resolution, spam/risk fields, and consent audit history.
5. Add contract, unit, integration, replay, and idempotency tests.
6. Add a same-origin BFF adapter package and drop-in form/chat UI packages to the SDK repo.

No production activation is part of this branch.
