"""Enable progressive tenant RLS on canonical tenant-owned tables.

Revision ID: 0069_progressive_tenant_rls
Revises: 0068_explicit_tenant_child_columns

Runtime roles are grant-only and have no BYPASSRLS (PAS-83).  We therefore
ENABLE RLS here without FORCE so the protected migration/table owner retains
an explicit maintenance path.  Application roles remain subject to policy.
"""

from alembic import op

revision = "0069_progressive_tenant_rls"
down_revision = "0068_explicit_tenant_child_columns"
branch_labels = None
depends_on = None


# Callback tables are intentionally excluded: migration 0052 already applies
# stronger tenant + campaign/role policies to that family. SQL-managed core
# and automation tables are owned by migrations/0012_tenant_rls.sql and
# migrations/automation/0002_tenant_rls.sql respectively.
RLS_TABLES = (
    "agent_call_event",
    "agent_call_state",
    "agent_provisioning_audit",
    "agent_provisioning_request",
    "agent_provisioning_step",
    "klyrow_delivery_analytics",
    "klyrow_delivery_event_inbox",
    "klyrow_mail_inbound",
    "social_accounts",
    "social_audit_events",
    "social_campaigns",
    "social_idempotency_records",
    "social_media_assets",
    "social_posts",
    "social_provider_events",
    "social_publish_jobs",
    "telnexa_delivery_analytics",
    "telnexa_delivery_event_inbox",
)


UUID_TENANT_TABLES = frozenset({
    "social_accounts",
    "social_audit_events",
    "social_campaigns",
    "social_idempotency_records",
    "social_media_assets",
    "social_posts",
    "social_provider_events",
    "social_publish_jobs",
})


def _tenant_expression(table: str) -> str:
    setting = "NULLIF(current_setting('app.tenant_id', true), '')"
    if table in UUID_TENANT_TABLES:
        return f"{setting}::uuid"
    return setting


def _policy_sql(table: str) -> str:
    tenant = _tenant_expression(table)
    return f"""CREATE POLICY codestra_tenant_isolation ON {table}
    USING (tenant_id = {tenant})
    WITH CHECK (tenant_id = {tenant})"""


def upgrade() -> None:
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS codestra_tenant_isolation ON {table}")
        op.execute(_policy_sql(table))


def downgrade() -> None:
    for table in reversed(RLS_TABLES):
        op.execute(f"DROP POLICY IF EXISTS codestra_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
