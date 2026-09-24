# Staging migration evidence collection

## Purpose

Use `scripts/collect_staging_migration_evidence.sh` to recover provenance for an unknown migration revision without changing the staging database, containers, files inside containers, or network configuration.

The current recovery target is `0053_callback_worker_grants`. The collector does not assume that revision is correct or safe; it searches approved source roots and Git history for evidence that can establish where the revision came from.

## Safety boundary

The collector is read-only with respect to the runtime. It uses Docker inspection/listing commands, hashes compose files, records OCI provenance labels, and searches operator-approved filesystem/Git roots. It does **not**:

- connect to PostgreSQL;
- run Alembic;
- execute commands inside containers;
- copy files into or out of containers;
- restart, stop, recreate, or modify containers;
- dump the complete container environment;
- print matched source lines or secrets;
- alter Git history.

Evidence output is written only to a local `OUTPUT_DIR`, which defaults to `/tmp/codestra-migration-evidence-<UTC timestamp>` with `umask 077`.

## Standard run

Run from the checked-out Middleware repository on the staging host:

```bash
MIGRATION_REVISION=0053_callback_worker_grants \
  ./scripts/collect_staging_migration_evidence.sh
```

The collector automatically includes the Docker Compose project working directory as a search root when that metadata exists.

## Additional approved roots

Add only directories that an operator has reviewed as appropriate source/archive locations. Separate roots with `:`:

```bash
SEARCH_ROOTS='/srv:/opt/codestra:/var/backups/codestra-source' \
MIGRATION_REVISION=0053_callback_worker_grants \
  ./scripts/collect_staging_migration_evidence.sh
```

The filesystem search uses `find -xdev`; it does not cross filesystem boundaries from each approved root. Common dependency/data directories are excluded.

## Deep Git history search

The normal run uses `git log -S` for the exact revision string. If that does not find the historical source and the repository is known to contain a large relevant history, enable the slower read-only object search:

```bash
DEEP_GIT_SEARCH=1 \
MIGRATION_REVISION=0053_callback_worker_grants \
  ./scripts/collect_staging_migration_evidence.sh
```

Deep search walks commits reachable from local refs and records only repository path, commit SHA, and matching Git object path. It does not print the file contents.

## Evidence files

The output directory contains:

- `report.txt`: execution/provenance report;
- `runtime-discovery.txt`: output from the existing safe Middleware runtime discovery script when available;
- `file-hits.tsv`: SHA-256 and path for working-tree files containing the exact revision string;
- `git-history-hits.tsv`: repository, commit SHA, commit time, and subject for `git log -S` hits;
- `deep-git-hits.tsv`: repository, commit SHA, and object path for optional deep-history hits;
- `summary.env`: hit counts and no-effect guarantees.

`RECOVERY_STATE=CANDIDATE_SOURCE_FOUND` means evidence was located; it does **not** authorize a database change. Every candidate must still be reviewed to establish exact `revision`, `down_revision`, provenance, and the complete missing parent chain.

## What to do when a candidate is found

1. Record the candidate repository/path and SHA-256 or commit SHA.
2. Copy the candidate into a separate forensic/recovery workspace outside this collector, preserving original bytes.
3. Verify the migration's `revision` and `down_revision` and walk the complete parent chain.
4. Compare the source provenance with the deployed image/source SHA and known release artifacts.
5. Add recovered historical migration source to a dedicated review branch together with an updated migration-lineage authority manifest.
6. Restore a disposable copy of staging and test the recovered chain there before any staging database operation.

Do not use a candidate hit as justification for `alembic stamp`, manual `alembic_version` edits, or guessed upgrade/downgrade operations.
