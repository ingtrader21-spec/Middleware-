# Phase 1 middleware report

Implemented the transactional ingestion core, SQLAlchemy models, Alembic migration, HMAC verification, strict `TEST_SYN` policy, idempotency replay/conflict handling, and an outbox claim primitive.

Migration status: **created but not applied**. No PostgreSQL schema, existing database, Odoo, n8n, VICIdial, Asterisk, Caddy, or firewall state was changed. Applying `migrations/versions/0001_integration_outbox.py` requires a separately approved database change window.

Validation: source files were reviewed; compile checks must run with bytecode directed to a writable temporary directory. The running container was not restarted.

## Repository controls

The directory was not previously a Git repository. A source backup was created before this update at `/opt/codestra/backups/middleware/20260720-172958/source.tgz` with SHA-256 recorded alongside the backup operation. Standard `make` targets were added. No feature branch was created because repository initialization and branch creation require an explicit change-management decision; no commit was made.

The `deploy-internal` target intentionally fails closed. `test-integration` also fails closed until an isolated PostgreSQL/Redis test environment is explicitly provisioned.
