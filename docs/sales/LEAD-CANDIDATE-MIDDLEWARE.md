# LeadCandidate middleware verification

## Purpose and boundary

The middleware is the authoritative verification boundary between a controlled
public-web scraper and Codestra business systems. It accepts
`codestra.sales.lead-candidate.v1`, validates and normalizes evidence-backed
observations, performs tenant-scoped identity matching, applies suppression and
consent policy, and returns `codestra.sales.lead-resolution.v1`.

Phase 1 is dry-run only. It sends no outreach and performs no Odoo, VICIdial,
n8n, Postly, or scraper-delivery write. Public availability is an observation,
not consent. Missing values remain null or unknown; the middleware does not
fabricate identities or contact details.

```text
self-hosted scraper
  -> authenticated raw-body HMAC ingestion (disabled by default)
  -> strict LeadCandidate contract
  -> normalization and evidence validation
  -> local and bounded Odoo read-only matching
  -> ordered suppression and consent gates
  -> deterministic LeadResolution + append-only audit evidence
```

## Contract

Requests identify the tenant, campaign, candidate, scraper job, source, company,
contact, evidence, provenance, provider summaries, extraction time, content
hashes, and idempotency metadata. Unknown JSON properties are rejected. URLs
must be public HTTP(S) locations without embedded credentials. Evidence uses a
bounded snippet, SHA-256 content hash, UTC observation time, extraction method,
supported `company.*` or `contact.*` field paths, and one of:

- `VERIFIED_FACT`
- `PUBLIC_OBSERVATION`
- `SYSTEM_INFERENCE`
- `UNKNOWN`

Responses use `ACCEPTED`, `REJECTED`, `EXACT_DUPLICATE`,
`POSSIBLE_DUPLICATE`, `SUPPRESSED`, `MANUAL_REVIEW`, `INVALID_EVIDENCE`, or
`INVALID_PAYLOAD`. They include storage/outreach eligibility, duplicate and
match type, opaque matched references, confidence, gate results, evidence and
provider summaries, rejection/manual-review reasons, audit reference,
idempotency outcome, policy version, and contract version. OpenAPI is generated
from the strict Pydantic models.

## Normalization and matching

Original contract values remain intact. Comparisons use deterministic derived
forms: Unicode NFKC and whitespace normalization; case-folded names and titles;
legal-suffix-stripped company names; IDNA/lowercase/root domains with `www`
removed; syntax-validated lowercase email; and E.164 telephone only when country
context makes the result unambiguous.

Central policy thresholds are 90 for exact and 70 for possible duplicate.
Exact company signals are jurisdiction-bound registration number (100), root
domain (95), and legal name plus address/country (90). Exact contact signals are
non-role business email (100) and E.164 phone confirmed by an exact company
(95). Strong/fuzzy name, location, title, company, shared-phone, and role-email
signals score below 90 and therefore require review. The response retains the
signal reasons and score. Fuzzy matches are never merged automatically.

Matching filters every record by tenant. APIs also bind reads to the caller's
tenant and campaign; opaque external references do not disclose another
tenant's records.

## Odoo read-only lookup

The adapter exposes only bounded `lookup` and `verification_page` operations.
Its registry client invokes the allowlisted `sales.lookup` and
`sales.verification.read` operations with timeouts and sanitized failures. No
generic Odoo method dispatcher is exposed, and create/update/delete counters are
asserted to remain zero in tests. An unavailable or mismatched authoritative
lookup returns `MANUAL_REVIEW` with `ODOO_UNAVAILABLE`; it never silently accepts
the candidate.

## Suppression and consent policy

Evaluation is deterministic and stops at the first active gate:

1. global DNC;
2. tenant DNC;
3. campaign DNC;
4. email suppression;
5. telephone suppression;
6. previous opt-out;
7. legal/jurisdiction restriction;
8. internal suppression;
9. consent;
10. channel eligibility.

Global, tenant, and applicable campaign/channel suppression always make
outreach ineligible. Unknown consent produces manual review; denied or withdrawn
consent suppresses outreach. A scraper's consent assertion is retained as
provenance only and cannot override authoritative policy.

## Idempotency, jobs, and audit

Mutation requests require a tenant-scoped `Idempotency-Key`. The canonical hash
is stable JSON containing the complete request, including explicit nulls, with
sorted keys and no generated timestamp. The database uniqueness scope is tenant,
operation, and key hash. The same payload returns the original result; a changed
payload returns HTTP 409. The repository transaction and process lock prevent
concurrent duplicate decisions. Retention is bounded operationally and must not
be shortened below the scraper retry horizon.

Dry-run verification jobs use the existing durable database/job conventions.
They validate, normalize, perform read-only matching, apply policies, and store
sanitized results. Queued/running jobs may be cancelled. Dependency outages
finish with warnings rather than producing unverified acceptance.

Audit rows contain scoped identifiers, contract/policy versions, payload and
identity hashes, decision/reason summaries, provider/Odoo status, correlation,
actor, timestamps, and idempotency outcome. They exclude credentials, raw
signature material, complete Odoo records, and unnecessary payload data.

## Scraper authentication

Scraper ingestion requires a Keycloak service JWT with exact issuer, audience,
authorized party, role, scope, environment, tenant, and campaign claims, then
verifies HMAC-SHA256 v2 over the exact raw body with timestamp, nonce/event
identity, and signed key identity. It applies a clock-skew window,
constant-time comparison, durable single-use replay protection, key rotation,
scraper/tenant/campaign binding, contract version validation, and request-size
limits. Missing, altered, expired, future, replayed, unknown-key, or cross-scope
requests fail with sanitized codes. The middleware does not fetch evidence URLs,
so synchronous ingestion introduces no new SSRF path.

## Optional providers

Hunter, Apollo, Twilio Lookup, OpenCorporates, and OpenAI implement a common
read-only provider boundary and default to disabled. Calls require bounded
operations, timeouts, retries/rate and cost controls when activated later.
Provider errors are normalized and secret-safe. AI output is untrusted,
evidence-dependent, explicitly classified as inference, and cannot override DNC
or consent. No paid provider is activated in Phase 1.

## Safe configuration

Source defaults are fail-closed:

```dotenv
SCRAPER_RESULT_INGEST_ENABLED=false
SCRAPER_MIDDLEWARE_DELIVERY_ENABLED=false
LEAD_VERIFICATION_DRY_RUN_ONLY=true
LEAD_OUTREACH_ENABLED=false
ODOO_LEAD_WRITE_ENABLED=false
VICIDIAL_LEAD_WRITE_ENABLED=false
N8N_LEAD_DELIVERY_ENABLED=false
POSTLY_LEAD_DELIVERY_ENABLED=false
HUNTER_PROVIDER_ENABLED=false
APOLLO_PROVIDER_ENABLED=false
TWILIO_LOOKUP_PROVIDER_ENABLED=false
OPENCORPORATES_PROVIDER_ENABLED=false
OPENAI_LEAD_CLASSIFICATION_ENABLED=false
```

Safety validation rejects delivery, write, outreach, or non-dry-run activation.
Secrets are supplied through the repository's secret-file mechanism and never
through response models, logs, or audit metadata.

## Monitoring, recovery, and Phase 2 prerequisites

Monitor request/result counts by safe decision code, validation failures,
idempotency conflicts, replay rejection, Odoo/provider availability, job age,
and manual-review backlog. Do not label metrics with contact data, payloads, or
external record IDs. A database outage rejects acceptance before a decision is
committed; an Odoo/provider outage fails to manual review; webhook replay is
rejected durably.

Phase 2 may enable scraper delivery only after the scraper contract is pinned,
machine keys are installed through secret files, tenant/campaign mappings are
approved, durable migrations and retention are operationally reviewed, and
end-to-end staging verifies HMAC rotation, replay handling, idempotency,
authoritative Odoo reads, monitoring, and rollback. Odoo/VICIdial/n8n/Postly
writes and outreach require separate governance and remain outside that phase.
