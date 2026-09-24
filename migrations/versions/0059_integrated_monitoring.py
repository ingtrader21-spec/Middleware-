"""Durable monitoring projections, replay records and resumable events.

Revision ID: 0059_integrated_monitoring
Revises: 0058_campaign_design
"""

from alembic import op
import sqlalchemy as sa

revision = "0059_integrated_monitoring"
down_revision = "0058_campaign_design"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "monitoring_resources",
        sa.Column("tenant", sa.String(128), primary_key=True),
        sa.Column("kind", sa.String(32), primary_key=True),
        sa.Column("resource_key", sa.String(512), primary_key=True),
        sa.Column("service_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("campaign_id", sa.String(128)),
        sa.Column("source_deployment", sa.String(128), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_monitoring_resource_scope",
        "monitoring_resources",
        ["tenant", "kind", "service_id", "environment"],
    )
    op.create_table(
        "monitoring_operations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("operation", sa.String(256), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.UniqueConstraint(
            "tenant",
            "actor",
            "operation",
            "idempotency_key",
            name="uq_monitoring_operation_replay",
        ),
    )
    op.create_table(
        "monitoring_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant", sa.String(128), nullable=False),
        sa.Column("topic", sa.String(64), nullable=False),
        sa.Column("campaign_id", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_monitoring_event_scope", "monitoring_events", ["tenant", "id"])


def downgrade():
    connection = op.get_bind()
    # Support the existing disposable migration rehearsal without ever dropping
    # collected evidence. Lock out concurrent writers before testing emptiness.
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text(
                "LOCK TABLE monitoring_resources, monitoring_operations, monitoring_events IN ACCESS EXCLUSIVE MODE"
            )
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    else:
        raise RuntimeError("Monitoring downgrade requires a verified locking dialect")
    for table in ("monitoring_events", "monitoring_operations", "monitoring_resources"):
        if connection.execute(sa.text("SELECT 1 FROM " + table + " LIMIT 1")).first():
            raise RuntimeError(
                "Monitoring evidence is nonempty; preserve tables and use the reviewed export/restore procedure"
            )
    for table in ("monitoring_events", "monitoring_operations", "monitoring_resources"):
        op.drop_table(table)
