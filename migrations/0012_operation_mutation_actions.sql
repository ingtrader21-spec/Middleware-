BEGIN;

ALTER TABLE middleware_operation_mutations
    DROP CONSTRAINT IF EXISTS middleware_operation_mutations_action_check;
ALTER TABLE middleware_operation_mutations
    ADD CONSTRAINT middleware_operation_mutations_action_check
    CHECK (action IN ('cancel', 'reconcile', 'retry', 'resolve_reconciliation'));

INSERT INTO middleware_schema_migrations (version, name)
VALUES (12, '0012_operation_mutation_actions')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
