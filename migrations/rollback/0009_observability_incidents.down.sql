-- OFFLINE ROLLBACK ONLY. Stop the observability-alert API and workers first.
-- Export and checksum all five incident tables before an approved rollback.
BEGIN;
DROP TABLE IF EXISTS middleware_observability_incident_mutations;
DROP TABLE IF EXISTS middleware_observability_notification_intents;
DROP TABLE IF EXISTS middleware_observability_incident_audit;
DROP TABLE IF EXISTS middleware_observability_incident_events;
DROP TABLE IF EXISTS middleware_observability_incidents;
DELETE FROM middleware_schema_migrations WHERE version=9;
COMMIT;
