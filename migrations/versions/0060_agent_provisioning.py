"""Agent provisioning orchestrator saga (Mission 3).

Revision ID: 0060_agent_provisioning
Revises: 0059_integrated_monitoring
"""

from alembic import op

revision = "0060_agent_provisioning"
down_revision = "0059_integrated_monitoring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE agent_provisioning_request (
      id uuid PRIMARY KEY, request_id text NOT NULL UNIQUE, tenant_id text NOT NULL,
      employee_id text NOT NULL, primary_email text NOT NULL,
      campaigns_json jsonb NOT NULL DEFAULT '[]'::jsonb,
      channels_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      telephony_json jsonb NOT NULL DEFAULT '{}'::jsonb,
      state text NOT NULL DEFAULT 'REQUESTED', keycloak_subject text,
      policy_revision text NOT NULL, idempotency_hash text NOT NULL UNIQUE,
      request_hash text NOT NULL, correlation_id text NOT NULL,
      requested_by text NOT NULL, last_error_code text, last_error_summary text,
      version integer NOT NULL DEFAULT 1,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT ck_agent_provisioning_state CHECK (state IN (
        'REQUESTED','VALIDATING','IDENTITY','ENTITLEMENTS','CHANNEL_PROVISIONING',
        'READBACK','EFFECTIVE','PARTIAL','FAILED','RECONCILING','SUSPENDED','REVOKED')),
      CONSTRAINT ck_agent_provisioning_version CHECK (version >= 1)
    )""")
    op.execute(
        "CREATE INDEX ix_agent_provisioning_tenant_state "
        "ON agent_provisioning_request(tenant_id, state)"
    )
    op.execute(
        "CREATE INDEX ix_agent_provisioning_request_employee "
        "ON agent_provisioning_request(employee_id)"
    )
    op.execute(
        "CREATE INDEX ix_agent_provisioning_request_correlation "
        "ON agent_provisioning_request(correlation_id)"
    )
    op.execute("""CREATE TABLE agent_provisioning_step (
      id uuid PRIMARY KEY,
      request_id uuid NOT NULL REFERENCES agent_provisioning_request(id) ON DELETE RESTRICT,
      system text NOT NULL, operation text NOT NULL, attempt integer NOT NULL DEFAULT 1,
      state text NOT NULL DEFAULT 'pending', external_reference text,
      started_at timestamptz, completed_at timestamptz, readback_state text,
      error_code text, error_summary text,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT ck_agent_provisioning_step_system CHECK (
        system IN ('keycloak','vicidial','klyrow','telnexa','odoo'))
    )""")
    op.execute(
        "CREATE INDEX ix_agent_provisioning_step_request "
        "ON agent_provisioning_step(request_id, system, attempt)"
    )
    op.execute("""CREATE TABLE agent_provisioning_audit (
      id uuid PRIMARY KEY,
      request_id uuid NOT NULL REFERENCES agent_provisioning_request(id) ON DELETE RESTRICT,
      from_state text NOT NULL, to_state text NOT NULL, action text NOT NULL,
      actor_subject text NOT NULL, correlation_id text NOT NULL,
      record_hash char(64) NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute(
        "CREATE INDEX ix_agent_provisioning_audit_request "
        "ON agent_provisioning_audit(request_id, created_at)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE agent_provisioning_audit")
    op.execute("DROP TABLE agent_provisioning_step")
    op.execute("DROP TABLE agent_provisioning_request")
