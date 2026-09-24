# Webhooks

`POST /api/v1/social/webhooks/{provider}` is the only bearer-exempt social route. The adapter verifies its native signature and timestamp before JSON normalization. Codestra-controlled callers use timestamp, nonce and HMAC replay protection.

Processing order is verify, replay window, schema validation, normalize, deduplicate on `(provider, provider_event_id)`, persist, and dispatch a canonical event. Raw payloads, credentials and provider stack traces are not dispatched.
