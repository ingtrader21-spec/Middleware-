# Phase 2 handoff: Server C self-hosted scraper

Server C (`49.12.145.107`) is not modified by Phase 1. A later independently
approved deployment must send the exact `codestra.sales.lead-candidate.v1`
JSON body to `POST /api/v1/sales/scraper-results` through the approved private
route. It must never contact Odoo, n8n or VICIdial directly.

Required headers are:

```text
Content-Type: application/json
Authorization: Bearer <short-lived Keycloak client-credentials JWT>
Idempotency-Key: stable per tenant/request/payload
X-Codestra-Scraper-ID: assigned service identity
X-Codestra-Key-ID: enrolled trusted-key identifier
X-Codestra-Signature-Version: hmac-sha256-v2
X-Codestra-Timestamp: Unix seconds
X-Codestra-Nonce: cryptographically random one-time value
X-Codestra-Content-SHA256: lowercase SHA-256 of exact transmitted bytes
X-Codestra-Signature: lowercase HMAC-SHA256
X-Correlation-ID: stable request trace
```

The canonical HMAC input is nine newline-separated values:

```text
hmac-sha256-v2
<key-id>
<scraper-id>
<tenant-id>
<campaign-id>
<source.request_id>
<unix-timestamp>
<nonce>
<exact-body-sha256>
```

Server C must preserve exact signed bytes, use UTC timestamps, retry only
explicit retryable dependency errors, reuse the same idempotency key and body
for a transport retry, generate a fresh nonce/signature for each HTTP attempt,
and stop on permanent 4xx responses. Secrets must come from the approved
protected file mechanism and must not appear in logs, workflow exports,
fixtures or error reports.

Before activation Phase 2 needs: approved private connectivity, assigned
Keycloak client with exact JWT audience/role/scope/tenant/campaign claims,
scraper identity, protected rotating HMAC delivery, middleware
and Odoo read-only service health, one synthetic contract test, replay/clock
skew testing, rate and concurrency limits, monitoring, and an independent
governance decision. Production writes, VICIdial publication and outreach
remain out of scope.
