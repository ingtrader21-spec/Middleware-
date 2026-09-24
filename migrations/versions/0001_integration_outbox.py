"""integration outbox core

Revision ID: 0001_integration_outbox
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_integration_outbox"
down_revision = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    js = postgresql.JSONB(astext_type=sa.Text())
    op.create_table(
        "integration_event",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("source_system", sa.String(50), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("payload_json", js, nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_integration_event_payload_hash", "integration_event", ["payload_hash"]
    )
    op.create_table(
        "integration_delivery",
        sa.Column("id", uuid, primary_key=True),
        sa.Column(
            "event_id",
            sa.BigInteger,
            sa.ForeignKey("integration_event.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target", sa.String(32), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("last_error", sa.Text),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("locked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("event_id", "target", name="uq_delivery_event_target"),
    )
    op.create_table(
        "idempotency_record",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("scope", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response", js, nullable=False),
        sa.Column("status_code", sa.Integer, nullable=False),
        sa.Column("event_id", sa.BigInteger, sa.ForeignKey("integration_event.id")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("scope", "key_hash", name="uq_idempotency_scope_key"),
    )


def downgrade() -> None:
    op.drop_table("idempotency_record")
    op.drop_table("integration_delivery")
    op.drop_index("ix_integration_event_payload_hash", table_name="integration_event")
    op.drop_table("integration_event")
