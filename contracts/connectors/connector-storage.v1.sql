-- Codestra Connector SDK v1 PostgreSQL storage contract.
-- Source-only migration contract: do not apply outside a reviewed migration.
-- PostgreSQL 15+ is required for UNIQUE NULLS NOT DISTINCT.
-- Secret values are never stored in these tables; only external references.

CREATE SCHEMA IF NOT EXISTS connector_sdk;

CREATE TABLE IF NOT EXISTS connector_sdk.connector_manifests (
    connector_id text NOT NULL,
    version text NOT NULL,
    manifest_digest text NOT NULL,
    manifest jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by_subject text NOT NULL,
    PRIMARY KEY (connector_id, version),
    UNIQUE (connector_id, manifest_digest),
    UNIQUE (connector_id, version, manifest_digest),
    CHECK (connector_id ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
    CHECK (version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'),
    CHECK (manifest_digest ~ '^sha256:[a-f0-9]{64}$'),
    CHECK (jsonb_typeof(manifest) = 'object'),
    CHECK ((manifest ->> 'enabled_by_default')::boolean IS FALSE),
    CHECK ((manifest ->> 'direct_n8n_access')::boolean IS FALSE)
);

CREATE TABLE IF NOT EXISTS connector_sdk.connector_installations (
    installation_id uuid PRIMARY KEY,
    connector_id text NOT NULL,
    environment text NOT NULL,
    cell text NOT NULL,
    current_version text NOT NULL,
    current_manifest_digest text NOT NULL,
    state text NOT NULL,
    resource_version bigint NOT NULL DEFAULT 1,
    activated_at timestamptz,
    suspended_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (connector_id, environment),
    FOREIGN KEY (
        connector_id,
        current_version,
        current_manifest_digest
    ) REFERENCES connector_sdk.connector_manifests (
        connector_id,
        version,
        manifest_digest
    ),
    CHECK (environment IN ('development', 'staging', 'production')),
    CHECK (cell IN ('core-communications', 'beyvra-financial', 'telephony-private')),
    CHECK (
        state IN (
            'DECLARED',
            'VALIDATED',
            'INSTALLED_DISABLED',
            'ACTIVE',
            'SUSPENDED',
            'FAILED'
        )
    ),
    CHECK (current_manifest_digest ~ '^sha256:[a-f0-9]{64}$'),
    CHECK (resource_version > 0)
);

CREATE TABLE IF NOT EXISTS connector_sdk.connector_connections (
    connection_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    installation_id uuid NOT NULL
        REFERENCES connector_sdk.connector_installations (installation_id),
    external_account_reference text,
    configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_references jsonb NOT NULL DEFAULT '[]'::jsonb,
    state text NOT NULL,
    resource_version bigint NOT NULL DEFAULT 1,
    last_tested_at timestamptz,
    last_test_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (
        tenant_id,
        installation_id,
        external_account_reference
    ),
    UNIQUE (tenant_id, connection_id),
    CHECK (jsonb_typeof(configuration) = 'object'),
    CHECK (jsonb_typeof(secret_references) = 'array'),
    CHECK (state IN ('PENDING', 'READY', 'DEGRADED', 'DISABLED', 'FAILED')),
    CHECK (resource_version > 0)
);

CREATE TABLE IF NOT EXISTS connector_sdk.connector_webhook_endpoints (
    webhook_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    endpoint_key text NOT NULL,
    route_path text NOT NULL,
    tenant_resolution text NOT NULL DEFAULT 'provider-account-mapping',
    provider_account_reference text,
    secret_reference_current text NOT NULL,
    secret_reference_previous text,
    previous_secret_valid_until timestamptz,
    state text NOT NULL,
    resource_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (connection_id, endpoint_key),
    UNIQUE (tenant_id, webhook_id),
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES connector_sdk.connector_connections
            (tenant_id, connection_id),
    CHECK (endpoint_key ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
    CHECK (
        route_path LIKE '/v1/webhooks/%'
        OR route_path LIKE '/internal/v1/adapters/%'
    ),
    CHECK (
        tenant_resolution IN (
            'endpoint-bound',
            'provider-account-mapping',
            'signed-claim'
        )
    ),
    CHECK (state IN ('DISABLED', 'ACTIVE', 'SUSPENDED', 'FAILED')),
    CHECK (resource_version > 0)
);

CREATE TABLE IF NOT EXISTS connector_sdk.connector_webhook_event_keys (
    tenant_id uuid NOT NULL,
    webhook_id uuid NOT NULL,
    event_id text NOT NULL,
    body_sha256 text NOT NULL,
    first_received_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (webhook_id, event_id),
    FOREIGN KEY (tenant_id, webhook_id)
        REFERENCES connector_sdk.connector_webhook_endpoints
            (tenant_id, webhook_id),
    CHECK (body_sha256 ~ '^[a-f0-9]{64}$'),
    CHECK (expires_at > first_received_at)
);

CREATE TABLE IF NOT EXISTS connector_sdk.connector_webhook_inbox (
    inbox_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    webhook_id uuid NOT NULL,
    connector_id text NOT NULL,
    endpoint_key text NOT NULL,
    event_id text NOT NULL,
    body_sha256 text NOT NULL,
    encrypted_body_reference text NOT NULL,
    signature_version text NOT NULL,
    verification_state text NOT NULL,
    processing_state text NOT NULL,
    cloud_event jsonb,
    correlation_id uuid NOT NULL,
    traceparent text,
    tracestate text,
    received_at timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz,
    processed_at timestamptz,
    error_code text,
    UNIQUE (webhook_id, event_id),
    FOREIGN KEY (tenant_id, webhook_id)
        REFERENCES connector_sdk.connector_webhook_endpoints
            (tenant_id, webhook_id),
    CHECK (body_sha256 ~ '^[a-f0-9]{64}$'),
    CHECK (
        verification_state IN (
            'PENDING',
            'VERIFIED',
            'REJECTED',
            'SEMANTIC_CONFLICT'
        )
    ),
    CHECK (
        processing_state IN (
            'PENDING',
            'NORMALIZED',
            'OUTBOXED',
            'COMPLETED',
            'FAILED',
            'DEAD_LETTER'
        )
    ),
    CHECK (cloud_event IS NULL OR jsonb_typeof(cloud_event) = 'object')
);

CREATE TABLE IF NOT EXISTS connector_sdk.connector_operations (
    operation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    command_id uuid NOT NULL,
    command_type text NOT NULL,
    idempotency_key text NOT NULL,
    request_sha256 text NOT NULL,
    capability text NOT NULL,
    state text NOT NULL,
    provider_reference text,
    resource_version bigint NOT NULL DEFAULT 1,
    safe_result jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_code text,
    traceparent text,
    tracestate text,
    submitted_at timestamptz,
    reconciled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, connection_id, idempotency_key),
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES connector_sdk.connector_connections
            (tenant_id, connection_id),
    CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    CHECK (
        state IN (
            'ACCEPTED',
            'BLOCKED',
            'SUBMITTED',
            'UNKNOWN',
            'COMPLETED',
            'FAILED',
            'CANCELLED'
        )
    ),
    CHECK (resource_version > 0),
    CHECK (jsonb_typeof(safe_result) = 'object')
);

CREATE TABLE IF NOT EXISTS connector_sdk.connector_outbox (
    outbox_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL,
    event_version integer NOT NULL,
    cloud_event jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id text NOT NULL,
    traceparent text,
    tracestate text,
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    lease_expires_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0,
    delivered_at timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (event_version > 0),
    CHECK (attempt_count >= 0),
    CHECK (jsonb_typeof(cloud_event) = 'object'),
    CHECK (cloud_event ->> 'specversion' = '1.0')
);

CREATE INDEX IF NOT EXISTS connector_connections_tenant_state_idx
    ON connector_sdk.connector_connections (tenant_id, state);
CREATE INDEX IF NOT EXISTS connector_webhook_routes_idx
    ON connector_sdk.connector_webhook_endpoints (
        route_path,
        endpoint_key,
        state
    );
CREATE INDEX IF NOT EXISTS connector_webhook_event_expiry_idx
    ON connector_sdk.connector_webhook_event_keys (expires_at);
CREATE INDEX IF NOT EXISTS connector_webhook_inbox_pending_idx
    ON connector_sdk.connector_webhook_inbox (
        processing_state,
        received_at
    )
    WHERE processing_state IN ('PENDING', 'FAILED');
CREATE INDEX IF NOT EXISTS connector_operations_tenant_state_idx
    ON connector_sdk.connector_operations (
        tenant_id,
        state,
        created_at
    );
CREATE INDEX IF NOT EXISTS connector_outbox_available_idx
    ON connector_sdk.connector_outbox (
        available_at,
        created_at
    )
    WHERE delivered_at IS NULL;

ALTER TABLE connector_sdk.connector_connections
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_connections
    FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_endpoints
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_endpoints
    FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_event_keys
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_event_keys
    FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_inbox
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_webhook_inbox
    FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_operations
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_operations
    FORCE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_outbox
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_sdk.connector_outbox
    FORCE ROW LEVEL SECURITY;

CREATE POLICY connector_connections_tenant_policy
    ON connector_sdk.connector_connections
    USING (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    );

CREATE POLICY connector_webhook_endpoints_tenant_policy
    ON connector_sdk.connector_webhook_endpoints
    USING (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    );

CREATE POLICY connector_webhook_event_keys_tenant_policy
    ON connector_sdk.connector_webhook_event_keys
    USING (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    );

CREATE POLICY connector_webhook_inbox_tenant_policy
    ON connector_sdk.connector_webhook_inbox
    USING (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    );

CREATE POLICY connector_operations_tenant_policy
    ON connector_sdk.connector_operations
    USING (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    );

CREATE POLICY connector_outbox_tenant_policy
    ON connector_sdk.connector_outbox
    USING (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(
            current_setting('codestra.tenant_id', true),
            ''
        )::uuid
    );
