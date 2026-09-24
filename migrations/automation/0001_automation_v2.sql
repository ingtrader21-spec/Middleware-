BEGIN;

CREATE TABLE IF NOT EXISTS middleware_automation_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS middleware_automation_jobs (
    tenant_id TEXT NOT NULL,
    job_id UUID NOT NULL,
    event_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    causation_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    workflow_key TEXT NOT NULL,
    workflow_family TEXT NOT NULL,
    workflow_version INTEGER NOT NULL CHECK (workflow_version > 0),
    expected_client_id TEXT NOT NULL,
    actor_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    safe_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    state TEXT NOT NULL CHECK (state IN (
        'PENDING','DISPATCHING','CLAIMED','RUNNING','WAITING_APPROVAL',
        'WAITING_TIMER','WAITING_COMMAND','RETRY_SCHEDULED','COMPLETED',
        'FAILED_TERMINAL','DEAD_LETTER','CANCELLED'
    )),
    delivery_token_sha256 CHAR(64) NOT NULL,
    delivery_token_used_at TIMESTAMPTZ,
    lease_token_sha256 CHAR(64),
    lease_client_id TEXT,
    execution_id UUID,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    result_code TEXT,
    error_code TEXT,
    safe_terminal_result JSONB,
    terminal_idempotency_key TEXT,
    terminal_request_sha256 CHAR(64),
    resource_version BIGINT NOT NULL DEFAULT 1 CHECK (resource_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, job_id),
    UNIQUE (tenant_id, event_id, workflow_key, workflow_version),
    CHECK (
        (lease_token_sha256 IS NULL AND lease_expires_at IS NULL)
        OR (lease_token_sha256 IS NOT NULL AND lease_expires_at IS NOT NULL
            AND lease_client_id IS NOT NULL AND execution_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS middleware_automation_jobs_claim_idx
    ON middleware_automation_jobs (tenant_id, expected_client_id, state, created_at)
    WHERE state IN ('PENDING','RETRY_SCHEDULED');
CREATE INDEX IF NOT EXISTS middleware_automation_jobs_lease_idx
    ON middleware_automation_jobs (lease_expires_at)
    WHERE lease_expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS middleware_automation_jobs_event_idx
    ON middleware_automation_jobs (tenant_id, event_id);

CREATE TABLE IF NOT EXISTS middleware_automation_dispatch_outbox (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    job_id UUID NOT NULL,
    dispatch_generation INTEGER NOT NULL DEFAULT 1 CHECK (dispatch_generation > 0),
    workflow_key TEXT NOT NULL,
    workflow_version INTEGER NOT NULL CHECK (workflow_version > 0),
    correlation_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING','CLAIMED','COMPLETED','CANCELLED','DEAD_LETTER')),
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, job_id, dispatch_generation),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES middleware_automation_jobs (tenant_id, job_id)
        ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS middleware_automation_dispatch_ready_idx
    ON middleware_automation_dispatch_outbox (next_attempt_at, id)
    WHERE state='PENDING';

CREATE TABLE IF NOT EXISTS middleware_automation_job_steps (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    job_id UUID NOT NULL,
    execution_id UUID NOT NULL,
    step_key TEXT NOT NULL,
    step_state TEXT NOT NULL CHECK (step_state IN ('STARTED','COMPLETED','FAILED','WAITING')),
    idempotency_key TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    safe_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, job_id, idempotency_key),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES middleware_automation_jobs (tenant_id, job_id)
        ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS middleware_automation_steps_job_idx
    ON middleware_automation_job_steps (tenant_id, job_id, recorded_at, id);

CREATE TABLE IF NOT EXISTS middleware_automation_approvals (
    tenant_id TEXT NOT NULL,
    approval_id UUID NOT NULL,
    job_id UUID NOT NULL,
    approval_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','APPROVED','REJECTED','EXPIRED')),
    requested_by TEXT NOT NULL,
    decided_by TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    decision_reason TEXT,
    resource_version BIGINT NOT NULL DEFAULT 1 CHECK (resource_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, approval_id),
    UNIQUE (tenant_id, job_id, idempotency_key),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES middleware_automation_jobs (tenant_id, job_id)
        ON DELETE RESTRICT,
    CHECK (decided_by IS NULL OR decided_by <> requested_by)
);
CREATE INDEX IF NOT EXISTS middleware_automation_approvals_pending_idx
    ON middleware_automation_approvals (expires_at)
    WHERE state='PENDING';

CREATE TABLE IF NOT EXISTS middleware_automation_dead_letters (
    tenant_id TEXT NOT NULL,
    dead_letter_id UUID NOT NULL,
    job_id UUID NOT NULL,
    workflow_key TEXT NOT NULL,
    workflow_family TEXT NOT NULL,
    original_effect_fingerprint CHAR(64) NOT NULL,
    safe_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    state TEXT NOT NULL CHECK (state IN ('OPEN','REPLAY_REQUESTED','REPLAYED','CLOSED')),
    resource_version BIGINT NOT NULL DEFAULT 1 CHECK (resource_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, dead_letter_id),
    UNIQUE (tenant_id, job_id),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES middleware_automation_jobs (tenant_id, job_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS middleware_automation_replay_requests (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    dead_letter_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    response_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, dead_letter_id, idempotency_key),
    FOREIGN KEY (tenant_id, dead_letter_id)
        REFERENCES middleware_automation_dead_letters (tenant_id, dead_letter_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS middleware_automation_reconciliation_runs (
    tenant_id TEXT NOT NULL,
    reconciliation_id UUID NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('READ','PLAN')),
    requested_by TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    result_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, reconciliation_id),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS middleware_automation_audit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    job_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    previous_state TEXT,
    new_state TEXT,
    actor_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    safe_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES middleware_automation_jobs (tenant_id, job_id)
        ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS middleware_automation_audit_job_idx
    ON middleware_automation_audit (tenant_id, job_id, created_at, id);

CREATE OR REPLACE FUNCTION middleware_reject_automation_evidence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'automation evidence rows are immutable';
END;
$$;

DROP TRIGGER IF EXISTS middleware_automation_steps_immutable ON middleware_automation_job_steps;
CREATE TRIGGER middleware_automation_steps_immutable
BEFORE UPDATE OR DELETE ON middleware_automation_job_steps
FOR EACH ROW EXECUTE FUNCTION middleware_reject_automation_evidence_mutation();

DROP TRIGGER IF EXISTS middleware_automation_audit_immutable ON middleware_automation_audit;
CREATE TRIGGER middleware_automation_audit_immutable
BEFORE UPDATE OR DELETE ON middleware_automation_audit
FOR EACH ROW EXECUTE FUNCTION middleware_reject_automation_evidence_mutation();

DROP TRIGGER IF EXISTS middleware_automation_replay_requests_immutable ON middleware_automation_replay_requests;
CREATE TRIGGER middleware_automation_replay_requests_immutable
BEFORE UPDATE OR DELETE ON middleware_automation_replay_requests
FOR EACH ROW EXECUTE FUNCTION middleware_reject_automation_evidence_mutation();

DROP TRIGGER IF EXISTS middleware_automation_reconciliation_runs_immutable ON middleware_automation_reconciliation_runs;
CREATE TRIGGER middleware_automation_reconciliation_runs_immutable
BEFORE UPDATE OR DELETE ON middleware_automation_reconciliation_runs
FOR EACH ROW EXECUTE FUNCTION middleware_reject_automation_evidence_mutation();

INSERT INTO middleware_automation_schema_migrations (version,name)
VALUES (1,'automation_control_plane_v2')
ON CONFLICT (version) DO UPDATE SET name=EXCLUDED.name;

COMMIT;
