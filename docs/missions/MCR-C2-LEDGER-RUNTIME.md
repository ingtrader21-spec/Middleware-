# MCR-C2 — Durable Campaign Recycling Ledger & Repository Runtime

## Starting point

- Worktree: /home/codestra/Worktrees/Middleware-/mcr-ledger-runtime
- Branch: mission/mcr-ledger-runtime-20260925
- Base: reviewed MCR-C1 commit d3926ac891bfc1104002789e33d59cb44a37c54f
- MCR-A validator PASS; MCR-A tests 29 PASS; C1 engine tests 16 PASS.

## Goal

Add the durable, replay-safe persistence layer for campaign recycling decisions and lead journey state so the C1 pure decision engine can be used safely after restarts and concurrent workers.

## Must build

1. Durable storage model/repository for campaign-recycling decision records.
2. Durable exposure reservation/ledger storage matching contracts/campaign-recycling/exposure-ledger.v1.schema.json.
3. Durable lifecycle/channel-health/suppression read-model state needed by the planner.
4. Idempotency identity + request hash enforcement so changed payload under the same idempotency key conflicts.
5. Concurrency-safe reservation semantics so the same lead/campaign/version/channel/touch cannot be reserved twice.
6. Replay-safe upsert/readback for delivery outcomes without double-counting.
7. Repository/service interfaces that the pure C1 engine can consume without importing FastAPI or provider adapters.
8. Transaction boundaries and retry-safe behavior following existing Middleware outbox/ledger conventions.
9. Read methods for: lead journey, active suppressions, exposure history, current lifecycle/channel state, latest decision, next eligible timestamp.
10. Focused migrations only if necessary, additive only, with constraints/indexes that encode the C1 invariants.
11. Focused repository/service tests using the repo's established isolated database/testing patterns.
12. Preserve all MCR-A contracts exactly; validator must remain green.

## Reuse existing foundations

- app/core/campaign_recycling.py
- app/operations.py / command ledger patterns
- app/workers/outbox.py and existing retry/dead-letter conventions
- existing SQLAlchemy/Alembic repository patterns
- existing communication suppression and Klyrow delivery inbox conventions
- contracts/campaign-recycling/*

## Hard boundaries

- No public or FastAPI route exposure in C2.
- No Klyrow/Odoo/N8N/provider calls.
- No live email/SMS/WhatsApp/calling.
- No production activation.
- No secret values.
- No edits outside this worktree.
- Do not weaken existing migrations or delete historical data.
- Additive migration only if required; downgrade must be safe/refuse destructive loss where history exists.
- Fail closed on missing/ambiguous policy state.

## Suggested files

- app/core/campaign_recycling_repository.py or equivalent
- app/db/campaign_recycling_models.py or equivalent
- migrations/versions/<next>_campaign_recycling_ledger.py if needed
- tests/test_campaign_recycling_repository.py
- tests/test_campaign_recycling_migration.py if migration added

## Verification

- scripts/validate_campaign_recycling_contracts.py PASS
- tests/test_campaign_recycling_contracts.py PASS
- tests/test_campaign_recycling_engine.py PASS
- new repository/migration tests PASS
- git diff --check PASS
- worktree clean after commit
- push via desktop terminal
- git ls-remote branch SHA equals local HEAD

## Completion report

Report changed files, migration/constraints added, test commands/results, local SHA, remote SHA, dirty state, and remaining gaps.

If Git is blocked, do not bypass. Report exact command, error, local SHA, remote state and safest next action.

## Completion checkpoint — 2026-09-25

Implementation status: SOURCE COMPLETE / PUSH BLOCKED PENDING OWNER AUTH.

Evidence:
- frozen MCR-A validator: PASS
- contract + C1 engine + C2 repository tests: 96 PASS
- Ruff on changed Python: PASS
- git diff --check: PASS
- Alembic head: 0070_campaign_recycling_decision_ledger
- no FastAPI/public-route files added in C2
- production/provider effects remain disabled

Durable invariants added/reused:
- tenant-bound lifecycle current/event state
- tenant/address-bound channel health
- append-only suppressions
- unique exposure reservation by tenant/lead/campaign/version/channel/touch
- delivery-event replay identity and projection state
- decision request idempotency by tenant + idempotency key + request hash
- append-only frozen next-action decision documents
- tenant/lead-scoped latest-decision readback
- non-destructive downgrade refusal while durable evidence exists

Integration dependency:
The separate production-readiness convergence branch currently owns schema-head/release
authority and is pinned to 0069_campaign_recycling_delivery_events. Final MCR-C convergence
must advance that authority to 0070_campaign_recycling_decision_ledger after this C2 source
is incorporated. C2 does not edit those release/deploy files to avoid overlapping ownership.
