# MCR V1 Postman / API Certification — 2026-09-25

Branch: mission/mcr-c-completion-safe-20260924

Certification target: local no-provider-effect FastAPI harness using the real MCR router, frozen contracts, policy engine, request validation, auth/tenant boundary, and response schemas.

## Result

- Campaign recycling contract validator: PASS
- Focused MCR/OpenAPI/route regression: 282 passed, 0 failed
- Newman: 18 requests, 18 test scripts, 50 assertions, 0 failures
- git diff --check: PASS
- Production execution: disabled / fail-closed
- Provider effects: disabled
- External Caddy/Kong/Middleware runtime health: not certified by this local harness

## Certified endpoints

- POST /platform/v1/campaign-engine/plan → 200
- POST /platform/v1/campaign-engine/execute → 403 production_not_authorized
- GET /platform/v1/campaign-engine/status → 200
- GET /platform/v1/leads/{lead_id}/journey → 200
- GET /platform/v1/leads/{lead_id}/next-action → 200
- GET /platform/v1/campaigns/{campaign_id}/eligible-leads → 200
- POST /platform/v1/delivery-events → 202
- POST /platform/v1/suppressions → 201 for new suppression

## Negative cases certified

Missing authentication, wrong audience, wrong scope, tenant mismatch, missing tenant header, missing correlation header, raw/non-namespaced campaign ID, invalid delivery signature, missing suppression idempotency, candidate redaction without disclosure scope, and hard-closed execute.

## Design boundary

Canonical path remains:

Caddy -> Kong -> Middleware :8095 -> MCR policy/state/ledger

Keycloak owns scopes. OpenBao owns secret references. Kong owns gateway authentication/routing/rate/request policy. Middleware owns tenant authorization, deterministic eligibility, idempotency, lifecycle/exposure state, normalized delivery evidence, and suppression authority.

This evidence does not authorize production provider effects or a live deployment.
