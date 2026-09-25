BEGIN;
ALTER TABLE middleware_commands ADD COLUMN IF NOT EXISTS request_sha256 char(64);
ALTER TABLE middleware_commands ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz;
ALTER TABLE middleware_commands ADD COLUMN IF NOT EXISTS max_attempts integer NOT NULL DEFAULT 5;
ALTER TABLE middleware_commands ADD COLUMN IF NOT EXISTS dead_lettered_at timestamptz;
ALTER TABLE middleware_commands ADD COLUMN IF NOT EXISTS dead_letter_reason text;
ALTER TABLE middleware_commands ADD COLUMN IF NOT EXISTS redrive_count integer NOT NULL DEFAULT 0;
ALTER TABLE middleware_commands ADD COLUMN IF NOT EXISTS redrive_blocked boolean NOT NULL DEFAULT false;
ALTER TABLE middleware_commands ADD CONSTRAINT middleware_commands_request_sha256_check CHECK (request_sha256 IS NULL OR request_sha256 ~ '^[a-f0-9]{64}$');
ALTER TABLE middleware_commands ADD CONSTRAINT middleware_commands_max_attempts_check CHECK (max_attempts > 0);
CREATE INDEX IF NOT EXISTS middleware_commands_retry_idx ON middleware_commands (state,next_attempt_at,tenant_id);
CREATE INDEX IF NOT EXISTS middleware_commands_dlq_idx ON middleware_commands (tenant_id,dead_lettered_at DESC) WHERE state='dead_lettered';
CREATE TABLE IF NOT EXISTS middleware_command_dead_letters (
 id bigserial PRIMARY KEY, tenant_id text NOT NULL, command_id text NOT NULL,
 attempt_number integer NOT NULL, error_code text NOT NULL, reason text NOT NULL,
 safe_error_detail text, request_sha256 char(64), dead_lettered_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz, redriven_command_id text,
 UNIQUE(tenant_id,command_id),
 FOREIGN KEY(tenant_id,command_id) REFERENCES middleware_commands(tenant_id,command_id) ON DELETE RESTRICT,
 CHECK(attempt_number > 0), CHECK(request_sha256 IS NULL OR request_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE INDEX IF NOT EXISTS middleware_command_dead_letters_readback_idx ON middleware_command_dead_letters(tenant_id,dead_lettered_at DESC,id DESC);
INSERT INTO middleware_schema_migrations(version,name) VALUES (8,'0008_command_idempotency_retry_dlq') ON CONFLICT(version) DO UPDATE SET name=EXCLUDED.name;
COMMIT;
