\set ON_ERROR_STOP on

-- Required psql variables are identical to correlation-query.sql.
-- This read-only query rejects an ambiguous selection by reporting the count.

WITH authorized_calls AS (
    SELECT c.id
    FROM telephony_call_lifecycle AS c
    JOIN telephony_call_lifecycle_event AS e ON e.call_id = c.id
    WHERE c.linked_id = :'linked_id'
      AND (c.primary_unique_id = :'unique_id' OR e.unique_id = :'unique_id')
      AND c.source_extension = :'source_extension'
      AND c.destination = :'destination'
      AND c.dialplan_context = :'dialplan_context'
      AND e.occurred_at BETWEEN
          :'window_start'::timestamptz AND :'window_end'::timestamptz
    GROUP BY c.id
    HAVING count(DISTINCT e.original_event_id) = 3
       AND array_agg(DISTINCT e.original_event_id)
           @> ARRAY[
               :'started_event_id',
               :'connected_event_id',
               :'ended_event_id'
           ]::text[]
)
SELECT
    (SELECT count(*) FROM authorized_calls) AS matched_logical_calls,
    (SELECT count(*)
       FROM telephony_call_lifecycle_event
      WHERE call_id IN (SELECT id FROM authorized_calls))
        AS lifecycle_history_rows,
    (SELECT count(*)
       FROM integration_event
      WHERE original_event_id IN (
          :'started_event_id',
          :'connected_event_id',
          :'ended_event_id'
      ))
        AS unique_integration_events;
