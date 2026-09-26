BEGIN;

-- Forward tenant-isolation authority for SQL-managed runtime tables.
-- Runtime roles must not hold BYPASSRLS. The migration owner retains maintenance access.

ALTER TABLE middleware_command_attempts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_command_attempts;
CREATE POLICY codestra_tenant_isolation ON middleware_command_attempts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_command_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_command_audit;
CREATE POLICY codestra_tenant_isolation ON middleware_command_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_commands ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_commands;
CREATE POLICY codestra_tenant_isolation ON middleware_commands
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_communication_cancellations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_communication_cancellations;
CREATE POLICY codestra_tenant_isolation ON middleware_communication_cancellations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_communication_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_communication_events;
CREATE POLICY codestra_tenant_isolation ON middleware_communication_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_communication_idempotency ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_communication_idempotency;
CREATE POLICY codestra_tenant_isolation ON middleware_communication_idempotency
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_communication_messages ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_communication_messages;
CREATE POLICY codestra_tenant_isolation ON middleware_communication_messages
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_communication_provider_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_communication_provider_events;
CREATE POLICY codestra_tenant_isolation ON middleware_communication_provider_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_communication_suppressions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_communication_suppressions;
CREATE POLICY codestra_tenant_isolation ON middleware_communication_suppressions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_control_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_control_audit;
CREATE POLICY codestra_tenant_isolation ON middleware_control_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_control_mutations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_control_mutations;
CREATE POLICY codestra_tenant_isolation ON middleware_control_mutations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_event_ledger ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_event_ledger;
CREATE POLICY codestra_tenant_isolation ON middleware_event_ledger
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_inbox ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_inbox;
CREATE POLICY codestra_tenant_isolation ON middleware_inbox
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_observability_incident_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_observability_incident_audit;
CREATE POLICY codestra_tenant_isolation ON middleware_observability_incident_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_observability_incident_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_observability_incident_events;
CREATE POLICY codestra_tenant_isolation ON middleware_observability_incident_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_observability_incident_mutations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_observability_incident_mutations;
CREATE POLICY codestra_tenant_isolation ON middleware_observability_incident_mutations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_observability_incidents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_observability_incidents;
CREATE POLICY codestra_tenant_isolation ON middleware_observability_incidents
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_observability_notification_intents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_observability_notification_intents;
CREATE POLICY codestra_tenant_isolation ON middleware_observability_notification_intents
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_operation_mutations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_operation_mutations;
CREATE POLICY codestra_tenant_isolation ON middleware_operation_mutations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_outbox ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_outbox;
CREATE POLICY codestra_tenant_isolation ON middleware_outbox
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_outbox_attempt_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_outbox_attempt_events;
CREATE POLICY codestra_tenant_isolation ON middleware_outbox_attempt_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_realtime_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_realtime_events;
CREATE POLICY codestra_tenant_isolation ON middleware_realtime_events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_realtime_tickets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_realtime_tickets;
CREATE POLICY codestra_tenant_isolation ON middleware_realtime_tickets
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_reconciliation_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_reconciliation_audit;
CREATE POLICY codestra_tenant_isolation ON middleware_reconciliation_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

INSERT INTO middleware_schema_migrations(version,name)
VALUES (12,'tenant_rls') ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
