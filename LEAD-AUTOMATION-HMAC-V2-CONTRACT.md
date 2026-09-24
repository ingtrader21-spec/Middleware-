# Lead Automation HMAC-V2 Contract

The n8n result callback uses `HMAC-V2` and the exact scope
`lead-automation.results.write`. Its canonical material is defined by
`app/core/lead_callback_auth.py` and binds, in order, signature version,
uppercase method, canonical path, timestamp, nonce, service identity, service
audience, environment, exact scope, idempotency key, and exact-body SHA-256.

Middleware also signs Odoo apply delivery to
`POST /codestra/api/v1/leads/automation/apply` using the exact scope
`lead-automation.odoo-apply.write` and the same ordered canonical fields.
Registration and terminal
acknowledgement endpoints use their existing JWT-authenticated n8n transport
contract and are not HMAC callers. A result signature cannot authorize those
capabilities because the result scope and path are exact and neither endpoint
accepts this HMAC credential.

Missing or unsupported versions; empty, wildcard, or cross-capability scopes;
unexpected queries; ambiguous paths; expired timestamps; nonce replay; body
changes; and identity, audience, environment, method, or path changes are
rejected before result processing. HMAC-V1 fallback is not implemented.
