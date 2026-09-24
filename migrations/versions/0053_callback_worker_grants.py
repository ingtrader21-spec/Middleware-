"""Grant callback tables to the bounded callback worker roles.

Revision ID: 0053_callback_worker_grants
Revises: 0052_callback_rls_hardening
"""

from alembic import op

revision = "0053_callback_worker_grants"
down_revision = "0052_callback_rls_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    grants = {
        "mw_scheduler": {
            "callback_record": "SELECT,UPDATE",
            "callback_event": "SELECT,INSERT,UPDATE",
            "callback_delivery": "SELECT,INSERT,UPDATE",
        },
        "mw_notification_worker": {
            # The delivery claim joins CallbackRecord under FOR UPDATE, so
            # PostgreSQL requires UPDATE on both locked relations.
            "callback_record": "SELECT,UPDATE",
            "callback_delivery": "SELECT,UPDATE",
        },
    }
    for role, tables in grants.items():
        for table, privileges in tables.items():
            op.execute(
                f"""DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') THEN
                  GRANT {privileges} ON {table} TO {role};
                END IF;
                END $$"""
            )


def downgrade() -> None:
    tables = {
        "mw_notification_worker": ("callback_delivery", "callback_record"),
        "mw_scheduler": ("callback_delivery", "callback_event", "callback_record"),
    }
    for role, role_tables in tables.items():
        for table in role_tables:
            op.execute(
                f"""DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') THEN
                  REVOKE ALL PRIVILEGES ON {table} FROM {role};
                END IF;
                END $$"""
            )
