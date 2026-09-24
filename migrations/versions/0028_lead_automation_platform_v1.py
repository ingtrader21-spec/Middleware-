"""Lead Automation Platform V1, default-off and isolated from recording."""

from alembic import op


revision = "0028_lead_automation_v1"
down_revision = "0027_telephony_command_journal"
branch_labels = None
depends_on = None


TABLES = (
    "lead_automation_events",
    "lead_automation_event_payloads",
    "lead_automation_policies",
    "lead_automation_policy_versions",
    "lead_automation_bindings",
    "lead_automation_outbox",
    "lead_automation_delivery_attempts",
    "lead_automation_results",
    "lead_automation_odoo_acknowledgements",
    "lead_automation_quarantine",
    "lead_automation_reconciliation_runs",
    "lead_automation_audit",
)


def upgrade() -> None:
    op.execute("CREATE TYPE lead_automation_state AS ENUM ('RECEIVED','SCHEMA_VALIDATED','POLICY_EVALUATING','POLICY_ALLOWED','POLICY_DENIED','CONSENT_BLOCKED','DNC_BLOCKED','OUTBOX_PENDING','DISPATCH_RESERVED','DISPATCHED','N8N_ACKNOWLEDGED','RESULT_RECEIVED','RESULT_VALIDATED','ODOO_APPLY_PENDING','ODOO_APPLIED','COMPLETED','RETRY_PENDING','QUARANTINED','FAILED_TERMINAL')")
    op.execute("""CREATE TABLE lead_automation_events (id uuid PRIMARY KEY, automation_event_id text NOT NULL UNIQUE, environment text NOT NULL, event_id text NOT NULL, idempotency_key text NOT NULL, state lead_automation_state NOT NULL DEFAULT 'RECEIVED', policy_version text NOT NULL, consent_snapshot jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(environment,idempotency_key), UNIQUE(environment,event_id))""")
    op.execute("CREATE TABLE lead_automation_event_payloads (id uuid PRIMARY KEY, event_id uuid NOT NULL REFERENCES lead_automation_events(id), payload jsonb NOT NULL, payload_sha256 char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now())")
    op.execute("CREATE TABLE lead_automation_policies (id uuid PRIMARY KEY, environment text NOT NULL, business_unit_key text NOT NULL, campaign_key text NOT NULL, event_type text NOT NULL, automation_action text NOT NULL, enabled boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now())")
    op.execute("CREATE TABLE lead_automation_policy_versions (id uuid PRIMARY KEY, policy_id uuid NOT NULL REFERENCES lead_automation_policies(id), policy_version text NOT NULL, policy jsonb NOT NULL, effective_from timestamptz NOT NULL, effective_until timestamptz, approved_by text NOT NULL, approval_reference text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), superseded_at timestamptz, UNIQUE(policy_id,policy_version))")
    op.execute("CREATE TABLE lead_automation_bindings (id uuid PRIMARY KEY, binding_key text NOT NULL, environment text NOT NULL, business_unit_key text NOT NULL, campaign_key text NOT NULL, event_type text NOT NULL, workflow_reference text NOT NULL, enabled boolean NOT NULL DEFAULT false, effective_from timestamptz NOT NULL, effective_until timestamptz, maximum_concurrency integer NOT NULL DEFAULT 1, rate_limit_per_minute integer NOT NULL DEFAULT 1, timeout_seconds integer NOT NULL DEFAULT 30, maximum_attempts integer NOT NULL DEFAULT 5, policy_version text NOT NULL, UNIQUE(binding_key,environment,business_unit_key,campaign_key,event_type))")
    op.execute("CREATE TABLE lead_automation_outbox (id uuid PRIMARY KEY, event_id uuid NOT NULL UNIQUE REFERENCES lead_automation_events(id), binding_id uuid NOT NULL REFERENCES lead_automation_bindings(id), status text NOT NULL DEFAULT 'pending', lease_token uuid, lease_expires_at timestamptz, attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz, created_at timestamptz NOT NULL DEFAULT now())")
    op.execute("CREATE TABLE lead_automation_delivery_attempts (id uuid PRIMARY KEY, outbox_id uuid NOT NULL REFERENCES lead_automation_outbox(id), attempt_number integer NOT NULL, status text NOT NULL, safe_error_code text, occurred_at timestamptz NOT NULL DEFAULT now(), UNIQUE(outbox_id,attempt_number))")
    op.execute("CREATE TABLE lead_automation_results (id uuid PRIMARY KEY, event_id uuid NOT NULL REFERENCES lead_automation_events(id), environment text NOT NULL, workflow_execution_id text NOT NULL, idempotency_key text NOT NULL, payload jsonb NOT NULL, payload_sha256 char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(environment,workflow_execution_id), UNIQUE(environment,idempotency_key))")
    op.execute("CREATE TABLE lead_automation_odoo_acknowledgements (id uuid PRIMARY KEY, event_id uuid NOT NULL REFERENCES lead_automation_events(id), environment text NOT NULL, odoo_acknowledgement_id text NOT NULL, acknowledgement jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(environment,odoo_acknowledgement_id))")
    op.execute("CREATE TABLE lead_automation_quarantine (id uuid PRIMARY KEY, event_id uuid REFERENCES lead_automation_events(id), reason_code text NOT NULL, safe_details jsonb NOT NULL DEFAULT '{}'::jsonb, disposition text, created_at timestamptz NOT NULL DEFAULT now(), disposed_at timestamptz)")
    op.execute("CREATE TABLE lead_automation_reconciliation_runs (id uuid PRIMARY KEY, environment text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz, gap_count integer NOT NULL DEFAULT 0, evidence jsonb NOT NULL DEFAULT '{}'::jsonb)")
    op.execute("CREATE TABLE lead_automation_audit (id uuid PRIMARY KEY, event_id uuid REFERENCES lead_automation_events(id), state lead_automation_state NOT NULL, result_code text, correlation_id uuid NOT NULL, business_unit_key text NOT NULL, campaign_key text NOT NULL, policy_version text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now())")
    op.execute("""CREATE FUNCTION deny_lead_automation_append_only_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append-only lead automation evidence'; END $$""")
    for table in ("lead_automation_event_payloads", "lead_automation_delivery_attempts", "lead_automation_results", "lead_automation_odoo_acknowledgements", "lead_automation_audit"):
        op.execute(f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION deny_lead_automation_append_only_mutation()")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE {table} CASCADE")
    op.execute("DROP FUNCTION deny_lead_automation_append_only_mutation()")
    op.execute("DROP TYPE lead_automation_state")
