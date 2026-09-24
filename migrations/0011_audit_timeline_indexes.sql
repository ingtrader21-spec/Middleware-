BEGIN;

-- The audit API traverses both authorities as one reverse-chronological stream.
-- Keep the tenant and cursor tuple as the leading index columns so PostgreSQL
-- can seek directly to the next page instead of sorting a tenant's full history.
CREATE INDEX IF NOT EXISTS middleware_control_audit_timeline_idx
  ON middleware_control_audit (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS middleware_command_audit_timeline_idx
  ON middleware_command_audit (tenant_id, created_at DESC, id DESC);

INSERT INTO middleware_schema_migrations(version,name)
VALUES (11,'audit_timeline_indexes') ON CONFLICT (version) DO NOTHING;

COMMIT;
