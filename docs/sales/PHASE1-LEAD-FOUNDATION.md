# Phase 1 governed lead intake and verification

## Contracts and endpoints

`codestra.sales.lead-candidate.v1` is a strict JSON contract. Unknown fields,
non-UTC timestamps, nested/unbounded metadata, raw HTML, executable URLs,
credential-bearing URLs, and literal/private/reserved destinations are
rejected before database or provider activity. Requests are limited to 128
KiB, 20 evidence records and 512 characters per evidence snippet.

The API surface is:

- `POST /api/v1/sales/lead-candidates/validate`
- `POST /api/v1/sales/lead-candidates/resolve`
- `POST /api/v1/sales/scraper-results`
- `POST /api/v1/sales/verification-jobs`
- `GET /api/v1/sales/verification-jobs/{job_id}`
- `GET /api/v1/sales/verification-jobs/{job_id}/results`

Resolution returns `codestra.sales.lead-resolution.v1` and one of `NET_NEW`,
`EXACT_EXISTING`, `POSSIBLE_DUPLICATE`, `BLOCKED`, `REJECTED`, or `CONFLICT`.
Every result is `dry_run=true`, carries a correlation ID and policy version,
and exposes stable reason codes without provider or infrastructure details.

## Normalization and identity

Unicode NFKC, whitespace, punctuation and common legal suffixes are normalized
for comparison while originals remain evidence. Domains use IDNA, discard URL
decorations and leading `www`, and conservatively retain country-domain
context. Telephone normalization uses the pinned `phonenumbers` library and
requires sufficient country context; ambiguous numbers fail validation and
extensions remain separate.

Company and contact matching are independent:

| Evidence | Score |
|---|---:|
| registration number + jurisdiction exact | 100 |
| registrable domain exact | 95 |
| legal name + address + country exact | 90 |
| strong company name + corroborated location | 80-89 |
| business email exact | 100 |
| E.164 phone + confirmed company | 95 |
| name + confirmed company + compatible title | 80-89 |

Scores 90-100 link with high confidence, 70-89 create a duplicate review, and
lower scores remain potentially new only after authoritative compliance checks.
Role mailboxes, switchboards, common names, city-only matches, fuzzy names and
AI output never auto-link.

## Odoo read-only boundary

The `OdooReadOnlyPort` supports bounded company/contact/lead/campaign and
compliance projections with a maximum page size of 100 and timeouts. The
disabled adapter fails closed. Test adapters expose create/update/delete
counters, all certified at zero. No fallback query, Odoo mutation method, Odoo
database credential, or unrestricted tenant search exists in this feature.

If Odoo or required compliance state is unavailable, the result is `BLOCKED`
with `DEPENDENCY_UNAVAILABLE`; it is never classified as new.

## Compliance

Precedence is global DNC, internal global suppression, campaign DNC, withdrawn
consent, then unknown-consent review. A score, provider response, scraper claim
or AI output cannot override a block. Phase 1 evaluates channel eligibility but
does not contact anyone.

## Idempotency, persistence and audit

Idempotency is scoped by tenant, operation and a SHA-256 protected key. The
canonical JSON payload hash detects conflicts. A PostgreSQL transaction-scoped
advisory lock and unique constraint make concurrent same-key processing
single-writer. Exact replays return the saved response; changed payloads return
`IDEMPOTENCY_PAYLOAD_CONFLICT` without revealing another tenant.

Migration `0034_sales_lead_foundation` adds candidates, resolutions, duplicate
reviews, verification jobs/results, tenant-scoped idempotency, webhook nonces
and provider-call summaries. Existing `audit_event` remains the append-only
audit sink. Stored audit payloads contain tenant/campaign, reason codes, policy,
protected payload hash and provider label, not raw credentials or tokens.

Audit event names include the mission catalog. Events reached by this phase are
`lead_candidate.received`, `identity_resolution.completed`,
`duplicate_review.created`, `compliance_gate.evaluated`,
`verification_job.created/completed/failed`, `scraper_webhook.accepted/rejected`,
`idempotent_replay.returned`, and `idempotency_conflict.rejected`. Provider
interfaces reserve `provider_call.attempted/completed/failed` for later enabled
sandbox execution.

## Dry-run jobs

Jobs require `dry_run=true`, `write_changes=false`, and
`publish_to_vicidial=false`; any other combination is rejected. Batch size is
1-100. Jobs are idempotent, tenant-isolated, progress-counted and fail closed.
The Phase 1 executor performs one bounded Odoo page and supports a cancellation
state; distributed background scheduling is deferred until an approved Odoo
read endpoint and staging worker deployment exist.

## Provider ports

Provider-neutral operations are defined for Hunter, Apollo, Twilio Lookup,
OpenCorporates and OpenAI. Every production provider flag defaults off. The
disabled adapter returns `DISABLED`; the fake returns only explicitly supplied
fixtures and never fabricates fallback data. No paid or live provider call is
made by this change.

OpenAI is limited to industry/service classification, bounded public-evidence
summaries and non-authoritative fit explanations. It cannot invent contacts,
determine identity/compliance, authorize outreach, or write to another system.

## Scraper authentication

`POST /api/v1/sales/scraper-results` uses HMAC-SHA256 over signature version,
scraper identity, tenant, campaign, request ID, timestamp, nonce and exact-body
SHA-256. The protected secret is loaded from an absolute restricted file.
Identity/tenant/campaign allowlists, a five-minute window, constant-time
comparison, exact JSON content type, request limits, and persistent nonce
uniqueness fail closed. There is no development bypass.

## Feature flags

All default to false: `SALES_LEAD_INTAKE_ENABLED`,
`SALES_IDENTITY_RESOLUTION_ENABLED`, `SALES_ODOO_READ_ONLY_LOOKUP_ENABLED`,
`SALES_VERIFICATION_JOBS_ENABLED`, `SCRAPER_RESULT_INGEST_ENABLED`,
`HUNTER_PROVIDER_ENABLED`, `APOLLO_PROVIDER_ENABLED`,
`TWILIO_LOOKUP_PROVIDER_ENABLED`, `OPENCORPORATES_PROVIDER_ENABLED`,
`OPENAI_LEAD_CLASSIFICATION_ENABLED`, `ODOO_WRITE_ENABLED`,
`VICIDIAL_PUBLICATION_ENABLED`, and `OUTREACH_ENABLED`.

## Safe errors

Errors contain `code`, safe `message`, `correlation_id`, and `retryable` only.
Stable codes include `FEATURE_DISABLED`, `INVALID_LEAD_CANDIDATE`,
`REQUEST_TOO_LARGE`, `INVALID_CONTENT_TYPE`,
`IDEMPOTENCY_PAYLOAD_CONFLICT`, `AUTHORITATIVE_DEPENDENCY_UNAVAILABLE`,
`UNKNOWN_SCRAPER_IDENTITY`, `INVALID_SIGNATURE`, `EXPIRED_TIMESTAMP`,
`MODIFIED_PAYLOAD`, `WRONG_TENANT_BINDING`, and `REPLAYED_NONCE`.

## Rollback and limitations

Disable all sales and scraper flags before rollback. Revert application and
contract artifacts together. In development/staging with no retained mission
data, downgrade from `0034_sales_lead_foundation` to `0033_tts_job_runtime`.
Never drop these records in production without independent approval and a
verified backup.

Known Phase 1 limitations: no live Odoo read endpoint is activated; provider
calls are disabled; verification runs one bounded page synchronously; hostname
evidence is never fetched, so DNS rebinding is avoided rather than followed;
and no production deployment or workflow activation is included.
