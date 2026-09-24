# Production migration certification repair — September 7, 2026

Source baseline: `924d9bd6484806549a2602b672661384fcfef238`.
Addresses the migration-history review on PR #156 and the unapplied-schema review
on PR #157; contributes source repairs to #38, #109, #118 and #134.
It does not close their separate runtime acceptance gates.

## Corrected boundaries

The canonical `migrations/versions/` graph contains 70 Alembic revisions ending at
`0057_platform_service_catalog`. The connector service's separate four-revision
`20260828_*` manifest is not authority for this production database.

`artifactAuthority.requiredMigrationHistorySha256` locks sorted canonical
revision paths, revision IDs, ordered parent mappings and SHA-256 hashes of the
migration file bytes. Merely retaining the last revision name cannot authorize
back-inserting or rewriting migration history. Existing migrations were not
modified by this repair. Future schema changes must append a migration, update
the release tuple and history pin through protected review, and demonstrate both
fresh-database and deployed-predecessor upgrades; never stamp around missing work.

The distroless runtime now packages the authority validator and the root and
automation SQL files. Narrow Docker-ignore exceptions preserve the exclusions
for dumps, backups, credentials and unrelated SQL files. The image CI smoke test
validates the actual packaged bundle with networking disabled.

The runtime migration runner validates source and configured schema identity
before connecting, rejects unknown/corrupt database lineage before executing
DDL, and serializes runner instances with a PostgreSQL advisory try-lock. It
passes the same explicit database target to asyncpg and Alembic; a supplied
connection prevents application settings from silently selecting another target.
Both connections use the public schema. No migration stamp or downgrade is used.

It applies the exact approved Alembic head plus all core and automation SQL,
then verifies actual Alembic state, complete SQL receipts and required platform
catalog tables before emitting success. A verification-only invocation performs
no upgrade or SQL DDL. Driver exception details are not printed because they can
contain credentials or SQL values.

The restricted controller independently reads `public.alembic_version`, core
receipts, automation receipts and all four platform tables before starting the
canary. Its no-effect row-count comparison now also includes platform tables.
A self-reported `/version` schema label is not database evidence.

## Validation and execution boundary

Local dependency-independent regressions cover history insertion/tampering,
corrupt lineage, bundle omissions, target overrides, lock contention, failed
upgrades, incomplete schema and verification-only behavior. The PostgreSQL
integration suite creates unique localhost-only disposable databases and tests
fresh and `0056_klyrow_delivery_events` predecessor upgrades, idempotent reruns,
read-back, lock contention and a deliberately missing table. It requires the
existing disposable-integration acknowledgement and never uses production.

Source tests and CI are not a deployed-runtime certification. The actual protected
execution still needs its exact signed image/source, current environment approval,
verified host/controller identity, backup and isolated restore, rollback, gateway
isolation and authenticated zero-effect evidence under #118. This repair enables
no provider, Odoo, n8n, email, SMS, social, PSTN, payment or trading effects and
executes no production migration or deployment.
