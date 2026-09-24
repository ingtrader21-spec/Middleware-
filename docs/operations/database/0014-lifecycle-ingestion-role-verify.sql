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

SELECT (
  has_schema_privilege(:'ingestion_role', 'public', 'USAGE')
  AND NOT has_schema_privilege(:'ingestion_role', 'public', 'CREATE')
  AND has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle', 'SELECT'
  )
  AND has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle', 'INSERT'
  )
  AND has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle', 'UPDATE'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle', 'DELETE'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle', 'TRUNCATE'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle', 'REFERENCES'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle', 'TRIGGER'
  )
  AND has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle_event', 'SELECT'
  )
  AND has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle_event', 'INSERT'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle_event', 'UPDATE'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle_event', 'DELETE'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle_event', 'TRUNCATE'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle_event', 'REFERENCES'
  )
  AND NOT has_table_privilege(
    :'ingestion_role', 'public.telephony_call_lifecycle_event', 'TRIGGER'
  )
) AS acl_is_exact
\gset

\if :acl_is_exact
  \echo 'lifecycle ingestion ACL is exact'
\else
  \echo 'lifecycle ingestion ACL is missing required grants or is overbroad'
  DO $failure$ BEGIN
    RAISE EXCEPTION
      'lifecycle ingestion ACL is missing required grants or is overbroad';
  END $failure$;
\endif
