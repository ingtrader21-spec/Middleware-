# SQL-managed schema structural verification

Addresses PR #159 review `discussion_r3953203272` on source
`4dd80b63c0d8f6a8e7463edf23c22cee7b660e07`.

## Defect and correction

Receipt versions and an Alembic head are not proof of actual SQL-managed schema.
A dropped automation column can survive a rerun of `CREATE TABLE IF NOT EXISTS`
and previously pass both verification-only and normal migration certification.

The runner now verifies a committed reference for all 34 SQL-managed public
tables, including the two receipt tables. Logical signatures cover columns,
types, nullability, defaults, collation, identity/generated attributes,
constraints and validation/deferral flags, index definitions and validity,
user/internal trigger enforcement, user trigger function bodies, row-security
flags and policies, and owned sequence definitions. Physical OIDs, ownership,
application data, statistics and current sequence values are excluded.

The catalog reader uses one read-only repeatable-read transaction and a local
`pg_catalog`-only search path. It does not repair objects or inspect business
rows. Any mismatch raises before any schema/migration PASS marker. Existing
Alembic, receipt, platform-table, advisory-lock, TLS and history checks remain.
Missing or stale reference metadata fails before database connection or DDL.

## Reference provenance

- Exact migration source: `4dd80b63c0d8f6a8e7463edf23c22cee7b660e07`.
- Diagnostic source: `cb5a82c17cb09edd410daccc6874ad3b41ef1750`.
- Generation run: `34172211354`, artifact `10036065300`.
- Artifact ZIP SHA-256:
  `3fa6a729d12734664686d88c883ca670d2edda1e8a1d42fa34580ee754b2a5a1`.
- Generation used an initially empty, localhost-only disposable PostgreSQL 17
  database and the source-locked full Alembic/core/automation upgrade. The
  reference was not captured from Server A or any production database.
- The reference binds the existing full migration-history digest
  `sha256:acbbada6ea72fc0f46c3caf7594809309e39a66cfda235529f9a30ba09fbe9af`.

Historical migration bytes and the existing history pin are unchanged. A future
migration requires an explicitly reviewed regenerated reference from a clean
isolated database, plus fresh/predecessor upgrade tests. Never regenerate a
reference from the target to make unexpected drift pass. PostgreSQL major-version
compatibility must be demonstrated by isolated tests; a different deparsed
signature fails closed rather than becoming an automatic version waiver.

## Tests and acceptance

- Selected local dependency-independent suite: 115 passed with
  `pytest --noconftest`. This includes mocked catalog/runner-ordering tests;
  it is not a claim of local PostgreSQL execution.
- Disposable PostgreSQL integration now exercises 12 structural corruptions
  with migration receipts intact, including the original dropped-column case
  through both verification-only and normal rerun. The existing fresh and
  predecessor migration/idempotency/locking tests run the new verifier too.
- Runtime image packages the reader and committed config. No skip/register or
  required-check relaxation is needed; new DB cases remain in the already
  required integration module.
- Full final-head CI and eligible independent review are required before merge.

This source fix is not Server A recovery, independent backup-key evidence,
production restoration, deployment, public cutover or provider activation.
The diagnostic generation workflow is not part of the PR's final source tree.
