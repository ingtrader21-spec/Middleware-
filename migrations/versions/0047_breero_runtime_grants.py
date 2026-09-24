"""Grant least-privilege BREERO runtime access.

Revision identifier: 0047_breero_runtime_grants
Revises: 0046_breero_complete_envelope
"""

from alembic import op

revision = "0047_breero_runtime_grants"
down_revision = "0046_breero_complete_envelope"
branch_labels = None
depends_on = None

RUNTIME_ROLE = "mw_integration_api"

TABLE_GRANTS = {
    "breero_event_receipt": "SELECT, INSERT, UPDATE",
    "breero_odoo_outbox": "SELECT, INSERT, UPDATE",
    "breero_replay_nonce": "SELECT, INSERT",
    "breero_integration_audit": "INSERT",
}


def _when_role_exists(statements: str) -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RUNTIME_ROLE}') THEN
            {statements}
          END IF;
        END $$;
        """
    )


def upgrade() -> None:
    statements = [
        f"GRANT {privileges} ON TABLE {table} TO {RUNTIME_ROLE};"
        for table, privileges in TABLE_GRANTS.items()
    ]
    statements.append(
        "GRANT USAGE, SELECT ON SEQUENCE breero_integration_audit_id_seq "
        f"TO {RUNTIME_ROLE};"
    )
    _when_role_exists("\n".join(statements))


def downgrade() -> None:
    statements = [
        f"REVOKE ALL PRIVILEGES ON TABLE {table} FROM {RUNTIME_ROLE};"
        for table in TABLE_GRANTS
    ]
    statements.append(
        "REVOKE ALL PRIVILEGES ON SEQUENCE breero_integration_audit_id_seq "
        f"FROM {RUNTIME_ROLE};"
    )
    _when_role_exists("\n".join(statements))
