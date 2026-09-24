# Security boundary

Threats include forged callbacks, replay, action escalation, cross-campaign or cross-business-unit mutation, prohibited PII disclosure, arbitrary outbound requests, and direct Odoo/database access.

The callback uses `HMAC-V2` and scope `lead-automation.results.write`. Its exact 11-field material binds version, uppercase method, exact path, timestamp, nonce, identity, audience, environment, scope, idempotency key, and the lowercase SHA-256 of exact body bytes with HMAC-SHA256. There is no terminal newline. The secret is runtime-delivered and absent from source. Nonces and the bounded event ledger provide replay evidence; Middleware remains authoritative for durable idempotency and quarantine. HMAC-V1, the former six-line signature, wildcard/cross-capability scope, bearer fallback, and unsigned protected fields fail closed.

The workflow validates event/action correspondence and preserves environment, business unit, campaign, action, policy version, consent, DNC, and the original attribute allowlist. It cannot change consent, DNC, company, or ownership outside the original authorization. Recursive prohibited-data checks reject sensitive keys and recognizable raw contact values.

Only the manifest node allowlist is permitted. Direct Odoo and PostgreSQL access, community nodes, communication nodes, calendar/appointment nodes, calling, recording access, and arbitrary HTTP targets are prohibited. The only outbound HTTP target is the runtime Middleware internal base plus the fixed result path.

Middleware events, results, quarantine records, and Odoo acknowledgements are the authoritative audit boundary. n8n produces a result proposal and deterministic ingress acknowledgement only; it never asserts CRM completion.
