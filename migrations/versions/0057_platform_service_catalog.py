"""Canonical platform service catalog and provisioning state machine.

Revision ID: 0057_platform_service_catalog
Revises: 0056_klyrow_delivery_events
"""

from alembic import op

revision = "0057_platform_service_catalog"
down_revision = "0056_klyrow_delivery_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE platform_services (
      id uuid PRIMARY KEY, service_id text NOT NULL UNIQUE, owner text NOT NULL,
      tenant_mode text NOT NULL, service_type text NOT NULL, repository text NOT NULL UNIQUE,
      environments jsonb NOT NULL, health_path text NOT NULL, metrics_path text NOT NULL,
      openapi_path text NOT NULL, dependencies jsonb NOT NULL DEFAULT '[]'::jsonb,
      data_classification text NOT NULL, slo_profile text NOT NULL, alert_profile text NOT NULL,
      state text NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
      CONSTRAINT ck_platform_service_state CHECK (state IN ('registered','active','decommissioned')),
      CONSTRAINT ck_platform_tenant_mode CHECK (tenant_mode IN ('single-tenant','multi-tenant','platform'))
    )""")
    op.execute("""CREATE TABLE platform_service_environments (
      id uuid PRIMARY KEY, service_id uuid NOT NULL REFERENCES platform_services(id) ON DELETE RESTRICT,
      environment text NOT NULL, region text NOT NULL, state text NOT NULL, created_at timestamptz NOT NULL,
      UNIQUE(service_id,environment,region)
    )""")
    op.execute("""CREATE TABLE platform_provisioning_requests (
      id uuid PRIMARY KEY, service_id uuid NOT NULL REFERENCES platform_services(id) ON DELETE RESTRICT,
      environment text NOT NULL, state text NOT NULL, request_json jsonb NOT NULL,
      manifest_sha256 text NOT NULL, git_sha char(40) NOT NULL, correlation_id text NOT NULL,
      requested_by text NOT NULL, validation_json jsonb, approved_by text,
      created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
      CONSTRAINT ck_platform_provisioning_state CHECK (state IN ('requested','validated','approved','apply_requested','applied','rollback_requested','rolled_back','failed'))
    )""")
    op.execute("""CREATE TABLE platform_provisioning_audit (
      id uuid PRIMARY KEY, request_id uuid NOT NULL REFERENCES platform_provisioning_requests(id) ON DELETE RESTRICT,
      from_state text NOT NULL, to_state text NOT NULL, actor_role text NOT NULL,
      reason text NOT NULL, record_hash char(64) NOT NULL UNIQUE, created_at timestamptz NOT NULL
    )""")
    op.execute("CREATE INDEX ix_platform_provisioning_state ON platform_provisioning_requests(state,created_at)")


def downgrade() -> None:
    op.execute("DROP TABLE platform_provisioning_audit")
    op.execute("DROP TABLE platform_provisioning_requests")
    op.execute("DROP TABLE platform_service_environments")
    op.execute("DROP TABLE platform_services")
