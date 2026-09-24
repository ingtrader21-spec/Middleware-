# Campaign design schema release proposal

This dependency change advances the required source schema from
`0057_platform_service_catalog` to `0058_campaign_design`. It adds immutable
campaign design revisions, current revision pointers, resource reservations,
idempotent event receipts, retry records, and audited approvals.

No database has been migrated by this source change. The existing signed release
observations retain their actual `0057_platform_service_catalog` schema; they do
not attest this candidate. The new signed candidate remains pending and no
production or external-effect authority is granted.

The application integration belongs in the dependent campaign design PR. Review
this schema and forward release tuple separately before merging that integration.
The previous immutable migration history is retained byte for byte, with the new
migration appended and the history digest recomputed from those source bytes.

Validation: the new tables were installed into an isolated PostgreSQL 17 schema.
The dependent integration tests exercised concurrent event replay and allocation,
revision changes, approval scope and idempotency, and rollback after injected
failure. The production database remains unchanged.

Release gates remain required: protected review, exact-main signed image and
schema evidence, backup and isolated restore, rollback rehearsal, and production
read-back. Adding tables does not authorize campaign provisioning or activation.

## Review hardening

PR review found that campaign objects were absent from structural admission,
approval rows could be edited, and an approval hash could diverge from its
referenced revision. The candidate migration now adds a composite revision/hash
foreign key and guards approval updates, deletes, and truncation. The existing
catalog verifier derives all six campaign table names from the source-locked
migration and checks their columns, constraints, indexes, trigger enablement,
and trigger function bodies against signatures from a disposable PostgreSQL
baseline. Existing numbered-SQL table signatures are unchanged.

Real database regressions cover each missing campaign table, damaged columns,
constraints and indexes, disabled revision/approval guards, replaced guard
functions, mismatched approval hashes, and attempted audit mutation. Correct
Alembic/SQL receipts cannot certify these damaged structures.

Validation on 2026-09-10: 28 disposable PostgreSQL regressions passed; the
full local suite passed 2,684 tests (132 environment-gated skips), with 94
subtests passed. Ruff and targeted mypy passed. Catalog generation verified
40 tables, including all six campaign tables, and preserved all 34 existing
numbered-SQL signatures. Production migration and campaign execution were
not run.

## Required CI clock-boundary repair

Required CI run 34433763999 failed in the real-database AI lifecycle test:
the future timestamp used the wall clock plus 301 seconds, and request
processing could cross a second boundary before the verifier checked it.
The deterministic fixture pins only the verifier clock and explicitly tests
both inclusive 300-second boundaries and rejection at 301 seconds.
Certificate validity and durable nonce timing retain the real clock.

The complete AI job platform test file passed all 10 tests against a fresh
PostgreSQL 17.10 database, with no skips. Ruff and targeted mypy passed.
Workflow trust transitions remain tracked separately in PRs #215 and #219;
their required independent reviews are pending.
