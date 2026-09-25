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
# stronger tenant + campaign/role policies to that family.
RLS_TABLES = (
    "agent_call_event",
    "agent_call_state",
    "agent_provisioning_audit",
    "agent_provisioning_request",
    "agent_provisioning_step",
    "klyrow_delivery_analytics",
    "klyrow_delivery_event_inbox",
    "klyrow_mail_inbound",
    "middleware_automation_approvals",
    "middleware_automation_audit",
    "middleware_automation_dead_letters",
    "middleware_automation_dispatch_outbox",
    "middleware_automation_job_steps",
    "middleware_automation_jobs",
    "middleware_automation_reconciliation_runs",
    "middleware_automation_replay_requests",
    "middleware_command_attempts",
    "middleware_command_audit",
    "middleware_commands",
    "middleware_communication_cancellations",
    "middleware_communication_events",
    "middleware_communication_idempotency",
    "middleware_communication_messages",
    "middleware_communication_provider_events",
    "middleware_communication_suppressions",
    "middleware_control_audit",
    "middleware_control_mutations",
    "middleware_event_ledger",
    "middleware_inbox",
    "middleware_observability_incident_audit",
    "middleware_observability_incident_events",
    "middleware_observability_incident_mutations",
    "middleware_observability_incidents",
    "middleware_observability_notification_intents",
    "middleware_operation_mutations",
    "middleware_outbox",
    "middleware_outbox_attempt_events",
    "middleware_realtime_events",
    "middleware_realtime_tickets",
    "middleware_reconciliation_audit",
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


def _policy_sql(table: str) -> str:
    return f"""CREATE POLICY codestra_tenant_isolation ON {table}
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))"""


def upgrade() -> None:
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS codestra_tenant_isolation ON {table}")
        op.execute(_policy_sql(table))


def downgrade() -> None:
    for table in reversed(RLS_TABLES):
        op.execute(f"DROP POLICY IF EXISTS codestra_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
