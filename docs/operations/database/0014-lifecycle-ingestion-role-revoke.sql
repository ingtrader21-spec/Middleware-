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
   ))
  AS role_is_valid
\gset

\if :role_is_valid
\else
  \echo 'ingestion_role failed validation or is privileged'
  DO $failure$ BEGIN
    RAISE EXCEPTION 'ingestion_role failed validation or is privileged';
  END $failure$;
\endif

REVOKE SELECT, INSERT, UPDATE
  ON TABLE public.telephony_call_lifecycle
  FROM :"ingestion_role";
REVOKE SELECT, INSERT
  ON TABLE public.telephony_call_lifecycle_event
  FROM :"ingestion_role";

-- USAGE on public predates migration 0014 and is intentionally retained.
