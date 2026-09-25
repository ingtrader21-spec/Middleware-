# MCR-C1 — Deterministic Campaign Recycling Decision Engine

## Starting point

- Branch: mission/mcr-core-engine-20260924
- Base: reviewed MCR-A commit b3f44dd4b8ad8976f10394051d2f13cc17443155
- Worktree: /home/codestra/Worktrees/Middleware-/mcr-core-engine
- MCR-A validator PASS and 29 focused tests PASS.

## Goal

Implement the pure, deterministic core that answers: given one lead snapshot, campaign candidates, channel health/suppressions, exposure history, and the frozen policy, what is the next allowed action and why?

## Must build

1. A pure domain module for campaign recycling decisioning.
2. Typed inputs for lead lifecycle state, channel-health state, active suppressions, campaign candidate metadata, exposure history, and current time.
3. Policy loading from config/campaign-recycling-policy.v1.json without hidden production defaults.
4. Deterministic eligibility evaluation with reason-code precedence matching contracts/campaign-recycling/next-action.v1.schema.json.
5. Enforce suppression first.
6. Enforce lifecycle terminal/blocked states.
7. Enforce channel health eligibility.
8. Enforce global per-channel frequency windows.
9. Enforce campaign cooldown / recent-window / lifetime exposure caps.
10. Deterministic candidate ordering/tie-break so the same inputs always produce the same selected campaign.
11. next_eligible_at calculation for temporal blocks.
12. dry-run decision output matching the MCR-A next-action contract shape.
13. Decision evidence: considered candidates + rejection reason codes where allowed by the contract.
14. Unit tests for suppression precedence, bad-email channel independence, cooldown, frequency cap, lifetime cap, no candidates, deterministic selection, reactivation, and stable output hash/decision identity if the contract defines one.

## Reuse; do not duplicate

- app/core/lead_automation.py
- app/core/campaign_identity.py
- app/communications.py suppression conventions
- app/email_production_control.py sender authorization concepts
- app/core/provider_adapters.py command/idempotency conventions
- contracts/campaign-recycling/*
- config/campaign-recycling-policy.v1.json
- scripts/validate_campaign_recycling_contracts.py

## Hard boundaries

- No database migration.
- No FastAPI/HTTP route implementation.
- No provider calls.
- No Klyrow/Odoo/N8N adapter calls.
- No production activation.
- No secrets or credentials.
- No changes to canonical dirty checkout.
- No bypass of suppression/consent policy.
- No sender-domain rotation logic intended to evade deliverability controls.
- Do not weaken MCR-A contracts.

## Suggested implementation shape

- app/core/campaign_recycling.py
- tests/test_campaign_recycling_engine.py
- small config/schema registration edits only if strictly necessary.

## Verification

- existing MCR-A validator stays green
- existing tests/test_campaign_recycling_contracts.py stays green
- new focused decision-engine tests pass
- git diff --check passes
- no runtime route/migration/provider-effect markers introduced

## Git rule

After all checks pass, commit on mission/mcr-core-engine-20260924 and push from this desktop terminal. Read back the remote branch SHA and confirm it equals local HEAD. If Git is blocked, do not bypass; report exact command/error/local SHA/remote state and safe next action.
