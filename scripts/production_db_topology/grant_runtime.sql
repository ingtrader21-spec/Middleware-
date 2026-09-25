-- PAS-95 disposable production-shaped topology: post-migration runtime grants.
-- Certification input only; issued by the schema owner, never by a runtime
-- role. Runtime roles receive DML only: no ownership, no DDL, no TRUNCATE,
-- no REFERENCES/TRIGGER, so they cannot disable the append-only triggers or
-- FORCE ROW LEVEL SECURITY (PAS-78 F-04).

\set ON_ERROR_STOP on
\connect codestra_production
SET ROLE middleware_migration;
GRANT USAGE ON SCHEMA public TO middleware_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
  TO middleware_runtime;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public
  TO middleware_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO middleware_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE middleware_migration IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO middleware_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE middleware_migration IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO middleware_runtime;
RESET ROLE;
