# Lead Automation V1 security boundary

Policy defaults deny. Every mutation and delivery switch defaults off. The middleware is the only component permitted to call the Odoo lead-automation mutation API; n8n has no Odoo or PostgreSQL access and cannot relay a direct Odoo call. This source change does not activate the integration.

## Odoo apply contract

`lead-odoo-apply-v1.json` defines the strict, PII-free request. It carries opaque event, workflow, lead/source, business-unit, campaign, policy, correlation, schema, result, consent and idempotency references plus allowlisted attributes. It rejects extra properties and does not carry personal contact data, free text, credentials, media, storage locations, or signed download locations. `lead-odoo-ack-v1.json` is the strict response contract.

The middleware sends `POST /codestra/api/v1/leads/automation/apply` using the exact canonical JSON bytes that were SHA-256 hashed. It sends service identity `codestra-middleware`, audience `codestra-odoo-lead-automation-api`, timestamp, nonce, content digest, signature, idempotency key, and environment headers. There is no bearer authentication. The HMAC secret is supplied only at runtime and must not appear in source, payloads, logs, or evidence.

The signed bytes are exactly the UTF-8 encoding of these newline-joined values, with no prefix or suffix:

```text
HTTP_METHOD
REQUEST_PATH
TIMESTAMP
NONCE
IDEMPOTENCY_KEY
SHA256_REQUEST_BODY
```

The method is exactly `POST` and the path is exactly `/codestra/api/v1/leads/automation/apply`. Verification binds every listed value, the content bytes, expected identity, audience and environment; it uses constant-time comparisons, a five-minute timestamp window, and one-time nonces.

## Acknowledgement, replay and failure policy

The acknowledgement result is exactly one of `APPLIED`, `NO_CHANGE`, `DENIED`, `CONSENT_BLOCKED`, `DNC_BLOCKED`, `QUARANTINED`, or `FAILED`. All required fields and request bindings must validate before any state can complete. `APPLIED` and `NO_CHANGE` move through `ODOO_APPLIED` to `COMPLETED`. Denial and consent/DNC blocks are terminal without retry. `QUARANTINED` is never automatically retried. `FAILED` is retryable only for the explicit `TEMPORARY_UNAVAILABLE` or `ODOO_TEMPORARY_UNAVAILABLE` result code; all other, unknown, ambiguous, mismatched, malformed, identity, audience, environment, schema, signature, and conflict cases are permanent and quarantinable.

An identical replay uses the original event-bound idempotency key and cached acknowledgement and performs zero duplicate HTTP operations. A different body for the same event/key is rejected and audited as an idempotency conflict. Network timeouts, HTTP 429, 500, 502, 503 and 504, and the two explicit temporary-unavailable codes are retried at most three times by default (hard maximum five). No acknowledgement means no completion.
