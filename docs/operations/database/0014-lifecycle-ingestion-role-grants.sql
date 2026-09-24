\set ON_ERROR_STOP on

\if :{?ingestion_role}
\else
  \echo 'required psql variable ingestion_role is missing'
  DO $failure$ BEGIN
    RAISE EXCEPTION 'required psql variable ingestion_role is missing';
  END $failure$;
\endif

SELECT
  (:'ingestion_role' ~ '^[a-z_][a-z0-9_]{0,62}$'
   AND EXISTS (
     SELECT 1 FROM pg_roles
      WHERE rolname = :'ingestion_role'
        AND NOT rolsuper
        AND NOT rolcreatedb
        AND NOT rolcreaterole
        AND NOT rolbypassrls
   )) AS role_is_valid
\gset

\if :role_is_valid
\else
  \echo 'ingestion_role failed validation or is privileged'
  DO $failure$ BEGIN
    RAISE EXCEPTION 'ingestion_role failed validation or is privileged';
  END $failure$;
\endif

GRANT USAGE ON SCHEMA public TO :"ingestion_role";
GRANT SELECT, INSERT, UPDATE
  ON TABLE public.telephony_call_lifecycle
  TO :"ingestion_role";
-- SQLAlchemy uses INSERT ... RETURNING recorded_at, which PostgreSQL checks
-- against SELECT privilege on the returned column/table.
GRANT SELECT, INSERT
  ON TABLE public.telephony_call_lifecycle_event
  TO :"ingestion_role";
