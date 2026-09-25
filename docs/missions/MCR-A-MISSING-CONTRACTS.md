# MCR-A — Missing Contracts Mission

## Purpose

Add only the missing contract/authority layer required for the Master Lead Lifecycle & Campaign Recycling Engine. Do not reimplement existing campaign registry, campaign design, lead automation, communications transport, Odoo campaign saga, Klyrow delivery inbox, sender identity provisioning, or provider dispatch.

## Existing foundations that must be reused

- docs/operations/campaign-registry/lead-eligibility.md — calling-specific lead identity/dialing eligibility.
- app/core/campaign_identity.py — campaign-scoped identities.
- app/core/lead_automation.py — lead automation state machine and idempotency.
- app/communications.py — current email/SMS/voice runtime channel registry and generic suppression; WhatsApp remains dependency-blocked behind Middleware PR #316.
- app/email_production_control.py — email production authorization and sender identity control.
- migrations/versions/0056_klyrow_delivery_event_inbox.py — durable Klyrow event inbox.
- migrations/versions/0066_reconcile_odoo_campaign_scope.py — Odoo campaign control/readback authority.
- existing campaign-design, provider-adapter, outbox/retry/reconciliation conventions.

## What is missing and must be added

1. Cross-channel lifecycle contract
   - lead lifecycle states: NEW, VALIDATED, ELIGIBLE, ACTIVE_CYCLE, ENGAGED, COOLING, REACTIVATION, CONVERTED, SUPPRESSED.
   - legal transitions and terminal semantics.
   - explicitly separate this from call/dialing eligibility.

2. Lead channel-health contract
   - frozen desired channels: email, sms, whatsapp, voice.
   - per-channel states: unknown, valid, possible, soft_bounce, hard_bounce, complained, unsubscribed, suppressed, invalid.
   - suppression scope and precedence.
   - a bad email must not automatically invalidate unrelated channels.
   - source/reason/occurred_at/evidence fields.

3. Campaign exposure ledger contract
   - durable identity for lead × campaign × campaign-version × channel × touch.
   - status/outcome timestamps.
   - correlation_id, command_id, provider_message_id and idempotency_key.
   - dedupe/concurrency invariant preventing the same planned touch from being issued twice.

4. Frequency/cooldown policy contract
   - global per-channel contact cap.
   - per-campaign cooldown.
   - maximum lifetime/recent-window exposure controls.
   - cooling/reactivation rules.
   - suppression always overrides eligibility.
   - all values configurable; no arbitrary production defaults hidden in code.

5. Next-action decision contract
   - eligible boolean.
   - selected campaign/version/channel/sender identity.
   - next_eligible_at.
   - policy version.
   - deterministic reason codes.
   - considered/rejected candidates and reasons where safe.
   - dry-run / plan semantics with zero provider effects.

6. Unified delivery/engagement event taxonomy
   - accepted, queued/dispatched where needed, delivered, deferred, soft_bounce, hard_bounce, complaint, unsubscribe, open, click, reply, conversion.
   - source/provider/event_id/schema_version/occurred_at/received_at.
   - dedupe/replay semantics.
   - opens documented as weak signals; replies/clicks/conversions stronger.

7. Canonical API contract
   - POST /platform/v1/campaign-engine/plan
   - POST /platform/v1/campaign-engine/execute
   - GET /platform/v1/leads/{lead_id}/journey
   - GET /platform/v1/leads/{lead_id}/next-action
   - GET /platform/v1/campaigns/{campaign_id}/eligible-leads
   - POST /platform/v1/delivery-events
   - POST /platform/v1/suppressions
   - GET /platform/v1/campaign-engine/status
   - auth/scopes, idempotency, pagination, error model, request/correlation IDs, replay protection, dry-run semantics.
   - contract only in MCR-A; do not implement runtime handlers yet.

8. Authority matrix
   - Leads: identity/lifecycle/channel state/read model.
   - Middleware: policy decisioning, command/idempotency, reconciliation.
   - Klyrow: campaigns/versions/templates/sender identities/delivery events.
   - Odoo: CRM/opportunity/human sales.
   - N8N: post-acceptance automation only.
   - Thunderbird: human mail client only.
   - Keycloak/OpenBao/Kong/Caddy/observability boundaries.

9. Sender identity rule
   - legitimate brand/campaign-owned authenticated identity.
   - never rotate domains/identities/formats to evade spam/provider controls.
   - sender identity selection is policy-governed and auditable.

10. Validation
    - machine-readable schemas/config where practical.
    - validator script.
    - focused tests proving schemas parse, state/reason enums match, endpoint set is exact, suppression precedence is explicit, and no production/provider activation is introduced.

## Expected new artifacts

- docs/architecture/MASTER_LEAD_LIFECYCLE_CAMPAIGN_RECYCLING_V1.md
- contracts/campaign-recycling/authority.v1.json
- contracts/campaign-recycling/lifecycle.v1.schema.json
- contracts/campaign-recycling/channel-health.v1.schema.json
- contracts/campaign-recycling/exposure-ledger.v1.schema.json
- contracts/campaign-recycling/next-action.v1.schema.json
- contracts/campaign-recycling/delivery-event.v1.schema.json
- contracts/campaign-recycling/campaign-engine.openapi.yaml
- config/campaign-recycling-policy.v1.json
- scripts/validate_campaign_recycling_contracts.py
- tests/test_campaign_recycling_contracts.py

Small existing-file edits are allowed only if needed to register/validate these contracts and are clearly justified.

## Hard boundaries

- No database migration in MCR-A.
- No runtime endpoint implementation in MCR-A.
- No provider calls.
- No live email/SMS/WhatsApp/calling.
- No production activation.
- No modifications to dirty canonical checkout.
- Work only in /home/codestra/Worktrees/Middleware-/mcr-authority-contracts.
- Preserve current repo conventions and existing authority.
- Fail closed.
- Do not invent secret values.
- Do not add bypass routes.
- Do not duplicate existing contracts when a reference is sufficient.

## Required verification

- JSON parse/JSON Schema validation where applicable.
- OpenAPI YAML parse.
- validator passes.
- focused pytest passes.
- git diff --check passes.
- final worktree status and changed-file list reported.

Do not commit or push. Leave a reviewed working-tree diff for the orchestrator to inspect, test, commit and push through terminal Git.
