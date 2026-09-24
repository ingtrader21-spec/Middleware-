"""Create endpoint registry authority tables.

Revision ID: 0025_endpoint_registry
Revises: 0024_merge_control_heads
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0025_endpoint_registry"
down_revision = "0024_merge_control_heads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    op.create_table(
        "integration_credential_reference",
        sa.Column("credential_reference_id", uuid, primary_key=True),
        sa.Column("reference_key", sa.String(255), nullable=False, unique=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "integration_service",
        sa.Column("service_id", uuid, primary_key=True),
        sa.Column("service_key", sa.String(64), nullable=False, unique=True),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "integration_endpoint",
        sa.Column("endpoint_id", uuid, primary_key=True),
        sa.Column(
            "service_id",
            uuid,
            sa.ForeignKey("integration_service.service_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("endpoint_key", sa.String(96), nullable=False),
        sa.Column("api_version", sa.String(16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "service_id", "endpoint_key", "api_version", name="uq_endpoint_identity"
        ),
    )
    op.create_table(
        "integration_endpoint_version",
        sa.Column("endpoint_version_id", uuid, primary_key=True),
        sa.Column(
            "endpoint_id",
            uuid,
            sa.ForeignKey("integration_endpoint.endpoint_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("configuration_version", sa.Integer(), nullable=False),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("path_template", sa.String(512), nullable=False),
        sa.Column("http_method", sa.String(10), nullable=False),
        sa.Column("content_type", sa.String(64), nullable=False),
        sa.Column("authentication_mode", sa.String(64), nullable=False),
        sa.Column("required_audience", sa.String(128), nullable=False),
        sa.Column(
            "required_scopes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("credential_reference_id", sa.String(255), nullable=False),
        sa.Column("tls_profile_id", sa.String(128), nullable=False),
        sa.Column("timeout_ms", sa.Integer(), nullable=False),
        sa.Column("connection_timeout_ms", sa.Integer(), nullable=False),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False),
        sa.Column("concurrency_limit", sa.Integer(), nullable=False),
        sa.Column("idempotency_required", sa.Boolean(), nullable=False),
        sa.Column("retry_class", sa.String(32), nullable=False),
        sa.Column("retry_limit", sa.Integer(), nullable=False),
        sa.Column("redirects_allowed", sa.Boolean(), nullable=False),
        sa.Column("target_attestation_required", sa.Boolean(), nullable=False),
        sa.Column("stale_read_safe", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "kill_switch", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("configuration_checksum", sa.String(71), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("approved_by", sa.String(128)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "endpoint_id",
            "configuration_version",
            name="uq_endpoint_configuration_version",
        ),
        sa.CheckConstraint("configuration_version >= 1", name="ck_endpoint_version"),
        sa.CheckConstraint("timeout_ms > 0", name="ck_endpoint_timeout"),
        sa.CheckConstraint(
            "connection_timeout_ms > 0", name="ck_endpoint_connection_timeout"
        ),
        sa.CheckConstraint("retry_limit >= 0", name="ck_endpoint_retry_limit"),
        sa.CheckConstraint(
            "retry_class IN ('NO_RETRY','BOUNDED_TRANSIENT_RETRY','MANUAL_REPLAY_ONLY')",
            name="ck_endpoint_retry_class",
        ),
    )
    op.create_table(
        "integration_route_binding",
        sa.Column("binding_id", uuid, primary_key=True),
        sa.Column(
            "endpoint_version_id",
            uuid,
            sa.ForeignKey("integration_endpoint_version.endpoint_version_id"),
            nullable=False,
        ),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column(
            "organization_scope", sa.String(128), nullable=False, server_default=""
        ),
        sa.Column(
            "business_unit_scope", sa.String(128), nullable=False, server_default=""
        ),
        sa.Column("campaign_scope", sa.String(128), nullable=False, server_default=""),
        sa.Column("workflow_scope", sa.String(128), nullable=False, server_default=""),
        sa.Column(
            "event_type_scope", sa.String(128), nullable=False, server_default=""
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "environment",
            "endpoint_version_id",
            "organization_scope",
            "business_unit_scope",
            "campaign_scope",
            "workflow_scope",
            "event_type_scope",
            name="uq_route_binding_scope",
        ),
    )
    op.create_index(
        "ix_route_binding_lookup",
        "integration_route_binding",
        [
            "environment",
            "organization_scope",
            "business_unit_scope",
            "campaign_scope",
        ],
    )
    op.create_table(
        "integration_schema_version",
        sa.Column("schema_version_id", uuid, primary_key=True),
        sa.Column("service_key", sa.String(64), nullable=False),
        sa.Column("endpoint_key", sa.String(96), nullable=False),
        sa.Column("api_version", sa.String(16), nullable=False),
        sa.Column("schema_reference", sa.String(512), nullable=False),
        sa.Column("checksum", sa.String(71), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint(
            "service_key",
            "endpoint_key",
            "api_version",
            name="uq_integration_schema_key",
        ),
    )
    op.create_table(
        "integration_endpoint_audit",
        sa.Column("audit_id", uuid, primary_key=True),
        sa.Column("endpoint_id", uuid, nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("previous_checksum", sa.String(71)),
        sa.Column("new_checksum", sa.String(71), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "integration_registry_generation",
        sa.Column("environment", sa.String(32), primary_key=True),
        sa.Column("generation", sa.BigInteger(), nullable=False),
        sa.Column("configuration_checksum", sa.String(71), nullable=False),
        sa.Column(
            "published_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("published_by", sa.String(128), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("integration_endpoint_audit")
    op.drop_table("integration_schema_version")
    op.drop_table("integration_registry_generation")
    op.drop_index("ix_route_binding_lookup", table_name="integration_route_binding")
    op.drop_table("integration_route_binding")
    op.drop_table("integration_endpoint_version")
    op.drop_table("integration_endpoint")
    op.drop_table("integration_service")
    op.drop_table("integration_credential_reference")
