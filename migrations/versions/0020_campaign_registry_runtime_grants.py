"""Grant least-privilege canonical campaign registry access.

Revision identifier: 0020_registry_runtime_grants
Revises: 0019_notification_control_plane
"""

from alembic import op


revision = "0020_registry_runtime_grants"
down_revision = "0019_notification_control_plane"
branch_labels = None
depends_on = None

RUNTIME_ROLE = "middleware_app"

READ_WRITE = (
    "campaign_extension_allocation",
    "campaign_object_identity",
)
READ_INSERT = (
    "campaign_search_alias",
    "campaign_activation_audit",
)
READ_UPDATE = (
    "campaign_registry",
    "campaign_feature_gate",
)


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
        f"GRANT SELECT, INSERT, UPDATE ON TABLE {table} TO {RUNTIME_ROLE};"
        for table in READ_WRITE
    ]
    statements.extend(
        f"GRANT SELECT, INSERT ON TABLE {table} TO {RUNTIME_ROLE};"
        for table in READ_INSERT
    )
    statements.extend(
        f"GRANT SELECT, UPDATE ON TABLE {table} TO {RUNTIME_ROLE};"
        for table in READ_UPDATE
    )
    statements.append(
        "GRANT USAGE, SELECT ON SEQUENCE campaign_identity_global_seq "
        f"TO {RUNTIME_ROLE};"
    )
    _when_role_exists("\n".join(statements))


def downgrade() -> None:
    tables = READ_WRITE + READ_INSERT + READ_UPDATE
    statements = [
        f"REVOKE ALL PRIVILEGES ON TABLE {table} FROM {RUNTIME_ROLE};"
        for table in tables
    ]
    statements.append(
        "REVOKE ALL PRIVILEGES ON SEQUENCE campaign_identity_global_seq "
        f"FROM {RUNTIME_ROLE};"
    )
    _when_role_exists("\n".join(statements))
