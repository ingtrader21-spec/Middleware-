BEGIN;

DROP TABLE IF EXISTS middleware_realtime_events;
DROP TABLE IF EXISTS middleware_realtime_tickets;
DELETE FROM middleware_schema_migrations WHERE version = 10;

COMMIT;
