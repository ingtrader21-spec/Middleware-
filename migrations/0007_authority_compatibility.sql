BEGIN;

ALTER TABLE middleware_inbox
    ADD COLUMN IF NOT EXISTS discarded_at timestamptz,
    ADD COLUMN IF NOT EXISTS discard_reason text;

ALTER TABLE middleware_operation_mutations
    DROP CONSTRAINT IF EXISTS middleware_operation_mutations_action_check;
ALTER TABLE middleware_operation_mutations
    ADD CONSTRAINT middleware_operation_mutations_action_check
    CHECK (action IN ('cancel', 'reconcile', 'retry'));

INSERT INTO middleware_schema_migrations (version, name)
VALUES (7, '0007_authority_compatibility')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
