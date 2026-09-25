-- PAS-95 disposable production-shaped topology: pre-migration role layout.
-- Certification input only. It runs as the local bootstrap superuser of a
-- throwaway container and is not a production role-provisioning authority
-- (the repository still has none; PAS-78 F-04/F-05, PAS-180 F-04).
--
-- The certification harness prepends one `\set pw_<role> '<hex>'` line per
-- login role on stdin, so no password is written here or passed in argv.

\set ON_ERROR_STOP on

-- DDL owner. Owns the database and therefore the public schema (PG15+
-- pg_database_owner). Never mounted into a runtime unit.
CREATE ROLE middleware_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD :'pw_middleware_migration';

-- DML grant role for every runtime unit; granted after migration.
CREATE ROLE middleware_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;

-- Grant roles named by the canonical migrations (0020, 0047, 0048,
-- 0051-0053). They exist before migration so the migrations' IF EXISTS
-- least-privilege grants take effect instead of being silent no-ops.
CREATE ROLE middleware_app NOLOGIN NOBYPASSRLS;
CREATE ROLE mw_integration_api NOLOGIN NOBYPASSRLS;
CREATE ROLE mw_scheduler NOLOGIN NOBYPASSRLS;
CREATE ROLE mw_notification_worker NOLOGIN NOBYPASSRLS;

-- Runtime login roles. middleware_production is the username locked by the
-- codestra-middleware-production-v1 runtime profile.
CREATE ROLE middleware_production LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD :'pw_middleware_production'
  IN ROLE middleware_runtime, middleware_app, mw_integration_api;
CREATE ROLE middleware_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD :'pw_middleware_worker'
  IN ROLE middleware_runtime, mw_notification_worker;
CREATE ROLE middleware_scheduler LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD :'pw_middleware_scheduler'
  IN ROLE middleware_runtime, mw_scheduler;
CREATE ROLE middleware_reconciler LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD :'pw_middleware_reconciler'
  IN ROLE middleware_runtime;

-- Read-only backup identity and metrics identity.
CREATE ROLE middleware_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD :'pw_middleware_backup'
  IN ROLE pg_read_all_data;
CREATE ROLE postgres_exporter LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS PASSWORD :'pw_postgres_exporter'
  IN ROLE pg_monitor;

CREATE DATABASE codestra_production OWNER middleware_migration
  TEMPLATE template0 ENCODING 'UTF8';
REVOKE ALL ON DATABASE codestra_production FROM PUBLIC;
GRANT CONNECT ON DATABASE codestra_production
  TO middleware_runtime, middleware_backup, postgres_exporter;

\connect codestra_production
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
