# Staging migration lineage gate

## Authority boundary

A database revision is valid only when its exact migration source exists in reviewed Git history. A revision recorded only in a database is not sufficient evidence of migration ancestry.

CI discovers every Alembic revision under the reviewed migration sources and requires that graph to exactly match `config/migration-lineage.v1.json`. The production runtime image already carries `config/`, so the containerized migration runner uses that reviewed manifest as its compact lineage authority instead of packaging the full migration-source tree.

Before applying any root SQL migration, `scripts/migrate_runtime.py` validates the manifest itself and performs a read-only check of `public.alembic_version`. Every recorded `version_num` must be present in the attested manifest. Unknown revisions fail closed before any migration SQL is executed.

## Current staging blocker

The observed staging revision `0053_callback_worker_grants` is not present in the current Middleware repository migration graph or the attested lineage manifest. The reviewed repository currently contains Connector Runtime Alembic revisions `20260828_0001` through `20260828_0004`.

Do not create a synthetic `0053_callback_worker_grants` migration merely to satisfy the version table. Do not run `alembic stamp`, manually rewrite `alembic_version`, or upgrade/downgrade through a guessed ancestry.

## Required recovery evidence

Recover the exact historical migration source from an authoritative artifact before changing the database. Acceptable evidence is one of:

1. the exact Git commit or branch that originally created revision `0053_callback_worker_grants`;
2. an immutable deployment artifact whose source provenance resolves to that migration;
3. a server-side checked-out repository/archive with verifiable commit provenance and the exact revision file;
4. a signed backup/release bundle containing the migration and its parent chain.

The recovered file must identify its exact `revision` and `down_revision`. Continue walking parents until the recovered chain joins a revision already present in reviewed Git history or reaches its original base. Preserve recovered historical migration contents. If repair operations are needed, add them as a new reviewed repair migration rather than rewriting history.

After historical source is recovered, update `config/migration-lineage.v1.json` on the same review branch. CI must prove that the manifest and source graph are identical before the runtime image can accept the revision.

## Operator checks

Read-only database inspection:

```sql
SELECT to_regclass('public.alembic_version');
SELECT version_num FROM public.alembic_version ORDER BY version_num;
```

Repository/offline validation of an observed revision:

```bash
python3 scripts/migration_lineage.py --observed-revision 0053_callback_worker_grants
```

Database validation using the normal runtime database URL:

```bash
DATABASE_URL='postgresql://...' python3 scripts/migration_lineage.py
```

An unknown revision exits non-zero and does not alter the database.

## Recovery sequence

1. Snapshot the staging database and record the current `alembic_version` rows.
2. Record the currently deployed image digest, source SHA, compose/runtime configuration, and container labels.
3. Recover the exact missing revision and all unresolved parents from Git history, deployment artifacts, server checkout, or backups.
4. Put recovered historical migrations and the matching lineage-manifest update on a dedicated review branch without enabling live effects.
5. Prove the complete Alembic graph is acyclic, has no missing parents, and exactly matches the manifest.
6. Restore a disposable copy of the staging database and validate the recovered chain there first.
7. Run upgrade/downgrade/read-back tests on the disposable database.
8. Only after that evidence is green, prepare a separate staging repair/cutover change.

Production, provider delivery, Odoo writes, SMS/email delivery, dialing, crawler execution, provisioning, and social publication remain outside this recovery task and must stay disabled unless separately authorized.
