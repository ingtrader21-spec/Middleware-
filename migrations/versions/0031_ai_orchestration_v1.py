"""Expand the durable AI job platform for versioned orchestration.

Revision ID: 0031_ai_orchestration_v1
Revises: 0030_ai_job_platform
"""

from alembic import op

revision = "0031_ai_orchestration_v1"
down_revision = "0030_ai_job_platform"
branch_labels = None
depends_on = None


def upgrade() -> None:
    statements = (
        "ALTER TABLE ai_generation_jobs ALTER COLUMN conversation_id DROP NOT NULL",
        "ALTER TABLE ai_generation_jobs ALTER COLUMN request_message_id DROP NOT NULL",
        "ALTER TABLE ai_generation_jobs DROP CONSTRAINT ck_ai_job_state",
        """ALTER TABLE ai_generation_jobs ADD CONSTRAINT ck_ai_job_state CHECK
        (state IN ('queued','available','leased','running','retry_wait','completed',
        'failed','cancel_requested','cancelled','expired','dead_letter',
        'approval_required','approved','rejected'))""",
        """ALTER TABLE ai_generation_jobs
        ADD COLUMN command_type text,
        ADD COLUMN schema_version text NOT NULL DEFAULT '1.0',
        ADD COLUMN actor_id text,
        ADD COLUMN actor_type text,
        ADD COLUMN correlation_id text,
        ADD COLUMN priority smallint NOT NULL DEFAULT 5,
        ADD COLUMN deadline_at timestamptz,
        ADD COLUMN command_payload jsonb,
        ADD COLUMN model_profile text,
        ADD COLUMN resource_limits jsonb NOT NULL DEFAULT '{}'::jsonb,
        ADD COLUMN data_classification text NOT NULL DEFAULT 'internal',
        ADD COLUMN approval_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
        ADD COLUMN callback_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
        ADD COLUMN command_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
        ADD COLUMN version bigint NOT NULL DEFAULT 1""",
        """ALTER TABLE ai_generation_jobs ADD CONSTRAINT ck_ai_command_type CHECK
        (command_type IS NULL OR command_type IN
        ('ai.chat.v1','ai.coding.v1','ai.crm.v1','ai.voice.v1','ai.embeddings.v1'))""",
        "ALTER TABLE ai_generation_jobs ADD CONSTRAINT ck_ai_priority CHECK (priority BETWEEN 0 AND 9)",
        """ALTER TABLE ai_generation_jobs ADD CONSTRAINT ck_ai_classification CHECK
        (data_classification IN ('public','internal','confidential','synthetic'))""",
        "CREATE INDEX ix_ai_job_tenant_state_priority ON ai_generation_jobs(organization_id,workspace_id,state,priority,created_at)",
        """CREATE TABLE ai_job_results (
          job_id uuid PRIMARY KEY REFERENCES ai_generation_jobs(id) ON DELETE RESTRICT,
          organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
          result_schema_version text NOT NULL, model_used text NOT NULL,
          provider_used text NOT NULL, started_at timestamptz NOT NULL,
          completed_at timestamptz NOT NULL, latency_ms bigint NOT NULL,
          token_usage jsonb NOT NULL DEFAULT '{}'::jsonb,
          resource_usage jsonb NOT NULL DEFAULT '{}'::jsonb,
          output jsonb NOT NULL, structured_artifacts jsonb NOT NULL DEFAULT '[]'::jsonb,
          warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
          policy_decisions jsonb NOT NULL DEFAULT '[]'::jsonb,
          error jsonb, retryability text NOT NULL DEFAULT 'none',
          audit_reference text NOT NULL, output_sha256 char(64) NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
        )""",
        """CREATE TABLE ai_job_events (
          id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES ai_generation_jobs(id) ON DELETE RESTRICT,
          organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
          event_type text NOT NULL, state text NOT NULL, sequence bigint NOT NULL,
          safe_details jsonb NOT NULL DEFAULT '{}'::jsonb,
          correlation_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE(job_id,sequence)
        )""",
        """CREATE TABLE ai_job_dead_letters (
          job_id uuid PRIMARY KEY REFERENCES ai_generation_jobs(id) ON DELETE RESTRICT,
          organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
          safe_error_code text NOT NULL, attempt_count integer NOT NULL,
          payload_sha256 char(64) NOT NULL, recovery_status text NOT NULL DEFAULT 'pending',
          created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
        )""",
        """CREATE TABLE ai_job_approvals (
          id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES ai_generation_jobs(id) ON DELETE RESTRICT,
          organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
          action_type text NOT NULL, proposal jsonb NOT NULL, proposal_sha256 char(64) NOT NULL,
          state text NOT NULL DEFAULT 'pending', requested_by text NOT NULL,
          decided_by_fingerprint char(64), decision_reason text,
          created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
          decided_at timestamptz,
          UNIQUE(job_id),
          CONSTRAINT ck_ai_approval_state CHECK (state IN ('pending','approved','rejected'))
        )""",
        """CREATE TABLE ai_tenant_quotas (
          organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
          max_queued integer NOT NULL DEFAULT 100, max_running integer NOT NULL DEFAULT 5,
          daily_tokens bigint NOT NULL DEFAULT 100000, daily_compute_units bigint NOT NULL DEFAULT 10000,
          max_payload_bytes integer NOT NULL DEFAULT 131072,
          max_output_bytes integer NOT NULL DEFAULT 1048576,
          max_runtime_seconds integer NOT NULL DEFAULT 600,
          updated_at timestamptz NOT NULL DEFAULT now(), version bigint NOT NULL DEFAULT 1,
          PRIMARY KEY(organization_id,workspace_id)
        )""",
        """CREATE TABLE ai_usage_ledger (
          id uuid PRIMARY KEY, job_id uuid NOT NULL REFERENCES ai_generation_jobs(id) ON DELETE RESTRICT,
          organization_id uuid NOT NULL, workspace_id uuid NOT NULL,
          usage_date date NOT NULL DEFAULT CURRENT_DATE, tokens bigint NOT NULL DEFAULT 0,
          compute_units bigint NOT NULL DEFAULT 0, model_profile text NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(job_id)
        )""",
        """CREATE TABLE ai_worker_registrations (
          worker_id text PRIMARY KEY, service_id text NOT NULL, capability_digest char(64) NOT NULL,
          capabilities jsonb NOT NULL, max_concurrency integer NOT NULL,
          enabled boolean NOT NULL DEFAULT false, registered_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(), version bigint NOT NULL DEFAULT 1
        )""",
        """CREATE TABLE ai_model_capabilities (
          profile text PRIMARY KEY, command_types text[] NOT NULL, logical_model text NOT NULL,
          provider text NOT NULL, enabled boolean NOT NULL DEFAULT false,
          max_input_tokens integer NOT NULL, max_output_tokens integer NOT NULL,
          configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
          created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
        )""",
        """INSERT INTO ai_model_capabilities(profile,command_types,logical_model,provider,enabled,max_input_tokens,max_output_tokens)
        VALUES
        ('fast-chat',ARRAY['ai.chat.v1'],'qwen-small','litellm',false,8192,2048),
        ('quality-chat',ARRAY['ai.chat.v1'],'qwen-quality','litellm',false,32768,4096),
        ('coding-default',ARRAY['ai.coding.v1'],'qwen-coder','ollama',false,32768,8192),
        ('coding-large',ARRAY['ai.coding.v1'],'qwen-coder-large','ollama',false,65536,8192),
        ('crm-analysis',ARRAY['ai.crm.v1'],'qwen-reasoning','litellm',false,16384,4096),
        ('voice-summary',ARRAY['ai.voice.v1'],'qwen-small','litellm',false,16384,4096),
        ('embedding-default',ARRAY['ai.embeddings.v1'],'qwen-embedding','ollama',false,8192,1024)
        """,
    )
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP TABLE ai_model_capabilities",
        "DROP TABLE ai_worker_registrations",
        "DROP TABLE ai_usage_ledger",
        "DROP TABLE ai_tenant_quotas",
        "DROP TABLE ai_job_approvals",
        "DROP TABLE ai_job_dead_letters",
        "DROP TABLE ai_job_events",
        "DROP TABLE ai_job_results",
        "DROP INDEX ix_ai_job_tenant_state_priority",
        """INSERT INTO ai_conversations
        (id,organization_id,workspace_id,created_by,title,status,created_at,updated_at)
        SELECT md5('ai-orchestration-rollback-conversation:' || id::text)::uuid,
        organization_id,workspace_id,requested_by,'Orchestration rollback record',
        'archived',created_at,updated_at
        FROM ai_generation_jobs WHERE conversation_id IS NULL
        ON CONFLICT (id) DO NOTHING""",
        """INSERT INTO ai_messages
        (id,conversation_id,organization_id,workspace_id,role,content,content_sha256,created_at)
        SELECT md5('ai-orchestration-rollback-message:' || id::text)::uuid,
        md5('ai-orchestration-rollback-conversation:' || id::text)::uuid,
        organization_id,workspace_id,'system','[orchestration rollback record]',
        'cc224ecac5f0dad29750d44dd520a3e8d659b776ee920db04e52831d9973aa75',created_at
        FROM ai_generation_jobs WHERE request_message_id IS NULL
        ON CONFLICT (id) DO NOTHING""",
        """UPDATE ai_generation_jobs SET
        conversation_id = COALESCE(conversation_id,
          md5('ai-orchestration-rollback-conversation:' || id::text)::uuid),
        request_message_id = COALESCE(request_message_id,
          md5('ai-orchestration-rollback-message:' || id::text)::uuid)
        WHERE conversation_id IS NULL OR request_message_id IS NULL""",
        """UPDATE ai_generation_jobs SET state = CASE
        WHEN state IN ('queued','available') THEN 'queued'
        WHEN state IN ('leased','running') THEN 'leased'
        WHEN state = 'retry_wait' THEN 'retry_wait'
        WHEN state IN ('completed','approved') THEN 'completed'
        WHEN state = 'failed' THEN 'failed'
        WHEN state IN ('cancel_requested','cancelled') THEN 'cancelled'
        ELSE 'dead_letter' END""",
        "ALTER TABLE ai_generation_jobs DROP CONSTRAINT ck_ai_classification",
        "ALTER TABLE ai_generation_jobs DROP CONSTRAINT ck_ai_priority",
        "ALTER TABLE ai_generation_jobs DROP CONSTRAINT ck_ai_command_type",
        """ALTER TABLE ai_generation_jobs DROP COLUMN command_type, DROP COLUMN schema_version,
        DROP COLUMN actor_id, DROP COLUMN actor_type, DROP COLUMN correlation_id,
        DROP COLUMN priority, DROP COLUMN deadline_at, DROP COLUMN command_payload,
        DROP COLUMN model_profile, DROP COLUMN resource_limits, DROP COLUMN data_classification,
        DROP COLUMN approval_policy, DROP COLUMN callback_policy, DROP COLUMN command_metadata,
        DROP COLUMN version""",
        "ALTER TABLE ai_generation_jobs DROP CONSTRAINT ck_ai_job_state",
        """ALTER TABLE ai_generation_jobs ADD CONSTRAINT ck_ai_job_state CHECK
        (state IN ('queued','leased','retry_wait','completed','failed','cancelled','dead_letter'))""",
        "ALTER TABLE ai_generation_jobs ALTER COLUMN request_message_id SET NOT NULL",
        "ALTER TABLE ai_generation_jobs ALTER COLUMN conversation_id SET NOT NULL",
    ):
        op.execute(statement)
