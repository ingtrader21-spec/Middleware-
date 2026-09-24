\set ON_ERROR_STOP on

-- Required psql variables:
-- linked_id, unique_id, started_event_id, connected_event_id, ended_event_id,
-- source_extension, destination, dialplan_context, window_start, window_end
--
-- psql's :'name' form quotes values as SQL literals. Callers must provide
-- values with --set rather than constructing SQL text.

SELECT
    c.id,
    c.correlation_id,
    c.linked_id,
    c.primary_unique_id,
    c.lifecycle_state,
    c.started_at,
    c.connected_at,
    c.ended_at,
    c.source_extension,
    c.destination,
    c.dialplan_context,
    array_agg(e.original_event_id ORDER BY e.occurred_at, e.original_event_id)
        AS lifecycle_event_ids,
    array_agg(DISTINCT e.unique_id) AS associated_unique_ids
FROM telephony_call_lifecycle AS c
JOIN telephony_call_lifecycle_event AS e ON e.call_id = c.id
WHERE c.linked_id = :'linked_id'
  AND (c.primary_unique_id = :'unique_id' OR e.unique_id = :'unique_id')
  AND c.source_extension = :'source_extension'
  AND c.destination = :'destination'
  AND c.dialplan_context = :'dialplan_context'
  AND e.occurred_at >= :'window_start'::timestamptz
  AND e.occurred_at <= :'window_end'::timestamptz
GROUP BY c.id
HAVING array_agg(DISTINCT e.original_event_id)
       @> ARRAY[
           :'started_event_id',
           :'connected_event_id',
           :'ended_event_id'
       ]::text[]
   AND count(DISTINCT e.original_event_id) = 3;
