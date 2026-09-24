# Telnexa issue 29 — non-submitting reconciliation

## Implemented transport

This companion to `appolon1908-hue/telnexa#29` consumes the read-only API added
by Telnexa PR #30 (merged source `8c8a8f95556ee4ca9a374abdaf9781ce9469ace6`).
The reviewed X-API-Key, tenant, correlation and idempotency contract remains in
place. Middleware never sends directly to Jasmin or a carrier.

```text
Initial authorized intent -> POST /api/v1/messages
Unknown outcome/read-back -> GET /api/v1/messages/by-idempotency
```

GET sends the original `Idempotency-Key`, `X-Tenant-ID`, `X-Correlation-ID` and
approved secret-injected `X-API-Key`, with no request body. It never falls back to
POST, including when the original submission is absent (404), delivery is now
disabled, a gateway fails, a response is malformed, or an identity mismatch occurs.
A timeout is not proof of failure; unresolved outcomes remain reconciliation-
required through the existing one-attempt command execution workflow.

The GET response must identify `telnexa.sms.readback.v1` and match tenant, key,
normalized request hash, correlation and a nonempty bounded Telnexa message ID.
The hash includes absent `campaign_id` and `client_reference` as null, sorted
compact JSON and default ASCII escaping, matching the Telnexa SendRequest model.
The durable operation reference is `message_id`, never a changing carrier-local
ID and never a fabricated command-ID fallback. Malformed or unknown submission
states do not become matched successes. A matched queued record confirms durable
acceptance, **not carrier delivery** or a certified production canary.

The provider contract bounds idempotency keys to 180 printable ASCII characters,
correlation IDs to 36 and billing-account IDs to 36. Unsupported values fail
before transport rather than failing later in PostgreSQL. This adapter accepts
only a credential-free origin and does not follow redirects with API credentials.
Raw provider error payloads and transport exception details are not included in
durable error messages.

## Validation and rollout boundary

The adapter suite retains submission projection/header, disabled capability,
identity/schema, forbidden secret, pre-connect failure, provider rejection,
configuration and HTTPS tests. Added/updated cases prove POST-then-GET recovery,
GET-only missing-record handling even with delivery disabled, strict response
binding, unknown outcome rejection, redirect denial and canonical Unicode hashing.
HTTP responses are synthetic; no test sends an SMS or contacts a live provider.

This source change does not install credentials, enable any capability or modify
an existing certified source/image lock. The connector catalog remains an
unverified template; its proposed OAuth/mTLS identity is not substituted for the
reviewed API-key transport by this change. Cross-server event intake/authentication,
private network and mTLS binding, actual secret-manager references, callback/DLR/MO
flow, image signatures/provenance and rollback still need a reviewed matched
runtime tuple and isolated staging evidence. Do not claim end-to-end certification
from these adapter tests alone.

Telnexa's new provider ingress requires its API and relay to be deployed together
with v2 source-bound signatures and explicit inbound number ownership. Preserve
receipt/inbox/outbox/unknown-dispatch data across rollbacks. Reverting to old
POST-based reconciliation is not an approved workaround. Keep live SMS/email/
calling disabled until the separately authorized bounded canary and production
gates are satisfied. Issue #29 must remain open until that evidence exists.
