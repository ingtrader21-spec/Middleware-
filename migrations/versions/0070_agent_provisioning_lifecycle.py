"""Converged Agent Provisioning lifecycle on governed tenant authority.

Revision ID: 0070_agent_provisioning_lifecycle
Revises: 0069_progressive_tenant_rls
"""
from alembic import op

revision = "0070_agent_provisioning_lifecycle"
down_revision = "0069_progressive_tenant_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE agent_provisioning_repair_intent (
          id uuid PRIMARY KEY,
          tenant_id text NOT NULL,
          request_id uuid NOT NULL,
          drift_class text NOT NULL,
          proposed_action text NOT NULL,
          state text NOT NULL DEFAULT 'PROPOSED',
          effect_class text NOT NULL DEFAULT 'provider_mutation',
          authorized_by text,
          result_code text,
          created_at timestamptz NOT NULL DEFAULT now(),
          executed_at timestamptz,
          CONSTRAINT ck_agent_repair_state CHECK (
            state IN ('PROPOSED','AUTHORIZED','EXECUTING','SUCCEEDED','FAILED','CANCELLED')
          ),
          CONSTRAINT fk_agent_repair_tenant_request
            FOREIGN KEY (tenant_id, request_id)
            REFERENCES agent_provisioning_request(tenant_id, id)
            ON DELETE RESTRICT
        )"""
    )
    op.execute(
        "CREATE INDEX ix_agent_repair_tenant_request "
        "ON agent_provisioning_repair_intent(tenant_id, request_id, created_at DESC)"
    )

    op.execute(
        """CREATE TABLE agent_webrtc_session (
          id uuid PRIMARY KEY,
          tenant_id text NOT NULL,
          request_id uuid NOT NULL,
          employee_id text NOT NULL,
          campaign_id text NOT NULL,
          extension text NOT NULL,
          provider_reference text,
          state text NOT NULL DEFAULT 'ISSUED',
          issued_at timestamptz NOT NULL DEFAULT now(),
          expires_at timestamptz NOT NULL,
          revoked_at timestamptz,
          correlation_id text NOT NULL,
          CONSTRAINT ck_agent_webrtc_state CHECK (
            state IN ('ISSUED','REGISTERING','REGISTERED','EXPIRED','REVOKED','FAILED')
          ),
          CONSTRAINT fk_agent_webrtc_tenant_request
            FOREIGN KEY (tenant_id, request_id)
            REFERENCES agent_provisioning_request(tenant_id, id)
            ON DELETE RESTRICT
        )"""
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_agent_webrtc_active_device "
        "ON agent_webrtc_session(tenant_id, employee_id) "
        "WHERE state IN ('ISSUED','REGISTERING','REGISTERED')"
    )
    op.execute(
        "CREATE INDEX ix_agent_webrtc_tenant_request "
        "ON agent_webrtc_session(tenant_id, request_id)"
    )

    tenant_policy = (
        "tenant_id = NULLIF(current_setting('app.tenant_id', true), '')"
    )
    for table in ("agent_provisioning_repair_intent", "agent_webrtc_session"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""CREATE POLICY codestra_tenant_isolation ON {table}
            USING ({tenant_policy})
            WITH CHECK ({tenant_policy})"""
        )


def downgrade() -> None:
    for table in ("agent_webrtc_session", "agent_provisioning_repair_intent"):
        op.execute(f"DROP POLICY IF EXISTS codestra_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TABLE agent_webrtc_session")
    op.execute("DROP TABLE agent_provisioning_repair_intent")
