BEGIN;

-- Forward tenant-isolation authority for SQL-managed runtime tables.
-- Runtime roles must not hold BYPASSRLS. The migration owner retains maintenance access.

ALTER TABLE middleware_automation_approvals ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_approvals;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_approvals
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_automation_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_audit;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_automation_dead_letters ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_dead_letters;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_dead_letters
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_automation_dispatch_outbox ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_dispatch_outbox;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_dispatch_outbox
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_automation_job_steps ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_job_steps;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_job_steps
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_automation_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_jobs;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_jobs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_automation_reconciliation_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_reconciliation_runs;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_reconciliation_runs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

ALTER TABLE middleware_automation_replay_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS codestra_tenant_isolation ON middleware_automation_replay_requests;
CREATE POLICY codestra_tenant_isolation ON middleware_automation_replay_requests
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

INSERT INTO middleware_automation_schema_migrations(version,name)
VALUES (2,'tenant_rls') ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
