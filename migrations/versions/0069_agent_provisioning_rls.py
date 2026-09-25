"""Tenant isolation authority for Agent Provisioning Section 6.

Revision ID: 0069_agent_provisioning_rls
Revises: 0068_agent_provisioning_lifecycle

The provisioning client may be authorized for more than one tenant. The API
sets app.tenant_ids transaction-locally from the verified token and these
policies admit only rows whose tenant belongs to that explicit set. Missing or
empty context matches no tenant.

Child tables inherit tenant ownership through agent_provisioning_request.
The integration role is rejected if it can bypass RLS.
"""
from alembic import op

revision = "0069_agent_provisioning_rls"
down_revision = "0068_agent_provisioning_lifecycle"
branch_labels = None
depends_on = None

TABLES = (
    "agent_provisioning_request",
    "agent_provisioning_step",
    "agent_provisioning_audit",
    "agent_provisioning_repair_intent",
    "agent_webrtc_session",
)


def upgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    tenant_scope = (
        "COALESCE(NULLIF(current_setting('app.tenant_ids', true), '')::jsonb "
        "? tenant_id, false)"
    )
    op.execute(
        f"""CREATE POLICY agent_provisioning_request_tenant
        ON agent_provisioning_request
        USING ({tenant_scope})
        WITH CHECK ({tenant_scope})"""
    )
    for table, policy in (
        ("agent_provisioning_step", "agent_provisioning_step_tenant"),
        ("agent_provisioning_audit", "agent_provisioning_audit_tenant"),
        ("agent_provisioning_repair_intent", "agent_provisioning_repair_intent_tenant"),
    ):
        request_scope = (
            "EXISTS (SELECT 1 FROM agent_provisioning_request r "
            f"WHERE r.id = {table}.request_id AND "
            "COALESCE(NULLIF(current_setting('app.tenant_ids', true), '')::jsonb "
            "? r.tenant_id, false))"
        )
        op.execute(
            f"""CREATE POLICY {policy}
            ON {table}
            USING ({request_scope})
            WITH CHECK ({request_scope})"""
        )
    op.execute(
        f"""CREATE POLICY agent_webrtc_session_tenant
        ON agent_webrtc_session
        USING ({tenant_scope})
        WITH CHECK ({tenant_scope})"""
    )

    op.execute(
        """DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mw_integration_api') THEN
          IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE rolname='mw_integration_api' AND rolbypassrls
          ) THEN
            RAISE EXCEPTION
              'mw_integration_api must be NOBYPASSRLS before agent provisioning RLS migration';
          END IF;
          GRANT SELECT, INSERT, UPDATE
            ON agent_provisioning_request,
               agent_provisioning_step,
               agent_provisioning_audit,
               agent_provisioning_repair_intent,
               agent_webrtc_session
            TO mw_integration_api;
        END IF;
        END $$"""
    )


def downgrade() -> None:
    op.execute("DROP POLICY agent_webrtc_session_tenant ON agent_webrtc_session")
    op.execute(
        "DROP POLICY agent_provisioning_repair_intent_tenant "
        "ON agent_provisioning_repair_intent"
    )
    op.execute("DROP POLICY agent_provisioning_audit_tenant ON agent_provisioning_audit")
    op.execute("DROP POLICY agent_provisioning_step_tenant ON agent_provisioning_step")
    op.execute(
        "DROP POLICY agent_provisioning_request_tenant ON agent_provisioning_request"
    )
    for table in reversed(TABLES):
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
