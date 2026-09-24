"""Recording API, append-only audit, storage objects and retention metadata.

Revision ID: 0028_recording_api
Revises: 0027_telephony_command_journal
"""

from alembic import op

revision = "0028_recording_api"
down_revision = "0027_telephony_command_journal"
branch_labels = None
depends_on = None


def upgrade() -> None:
    statements = (
        """
        CREATE TABLE recordings (
          id uuid PRIMARY KEY,
          recording_uid varchar(144) NOT NULL UNIQUE,
          environment varchar(16) NOT NULL,
          campaign_key varchar(128) NOT NULL,
          call_uid varchar(144) NOT NULL,
          idempotency_key varchar(255) NOT NULL,
          state varchar(32) NOT NULL,
          retention_class varchar(32) NOT NULL,
          legal_hold boolean NOT NULL DEFAULT false,
          created_at timestamptz NOT NULL DEFAULT now(),
          CONSTRAINT uq_recording_environment_idempotency
            UNIQUE(environment, idempotency_key),
          CONSTRAINT ck_recording_canonical_state CHECK (state IN (
            'RESERVATION_CREATED', 'UPLOADING', 'UPLOADED', 'SERVER_VERIFIED',
            'ODOO_LINKED', 'QUARANTINED', 'FAILED'
          ))
        )
        """,
        """
        CREATE TABLE recording_upload_reservations (
          id uuid PRIMARY KEY, recording_id uuid NOT NULL REFERENCES recordings(id),
          opaque_object_identifier varchar(255) NOT NULL,
          expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE recording_objects (
          id uuid PRIMARY KEY, recording_id uuid NOT NULL REFERENCES recordings(id),
          object_version_id varchar(255), checksum_sha256 varchar(64) NOT NULL,
          file_size_bytes bigint NOT NULL, content_type varchar(128) NOT NULL,
          verified_at timestamptz
        )
        """,
        """
        CREATE UNIQUE INDEX uq_recording_object_version_not_null
          ON recording_objects(object_version_id)
          WHERE object_version_id IS NOT NULL
        """,
        """
        CREATE TABLE recording_delivery_attempts (
          id uuid PRIMARY KEY, recording_id uuid NOT NULL REFERENCES recordings(id),
          destination varchar(32) NOT NULL, attempt integer NOT NULL,
          status varchar(32) NOT NULL, response_summary jsonb NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE recording_retention_policies (
          policy_class varchar(32) PRIMARY KEY, retention_days integer,
          version varchar(32) NOT NULL
        )
        """,
        """
        INSERT INTO recording_retention_policies VALUES
          ('synthetic_test', 7, '1.0'), ('standard', 365, '1.0'),
          ('high_compliance', 1825, '1.0'), ('legal_hold', NULL, '1.0')
        """,
        """
        CREATE TABLE recording_retention_decisions (
          id uuid PRIMARY KEY, recording_id uuid NOT NULL REFERENCES recordings(id),
          eligible boolean NOT NULL, reason varchar(64) NOT NULL,
          eligible_at timestamptz, delete_executed boolean NOT NULL DEFAULT false,
          decided_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE recording_playback_audit (
          id uuid PRIMARY KEY, recording_id uuid NOT NULL REFERENCES recordings(id),
          service_identity varchar(144) NOT NULL, scope_hash varchar(64) NOT NULL,
          authorized boolean NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE recording_outbox (
          id uuid PRIMARY KEY, recording_id uuid NOT NULL REFERENCES recordings(id),
          event_type varchar(96) NOT NULL, payload jsonb NOT NULL,
          binding_enabled boolean NOT NULL DEFAULT false,
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE recording_state_audit (
          id uuid PRIMARY KEY, recording_id uuid NOT NULL REFERENCES recordings(id),
          sequence integer NOT NULL, from_state varchar(32), to_state varchar(32) NOT NULL,
          reason varchar(255) NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now(),
          CONSTRAINT uq_recording_state_sequence UNIQUE(recording_id, sequence)
        )
        """,
        """
        CREATE OR REPLACE FUNCTION recording_audit_immutable() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'recording audit history is append-only'; END;
        $$ LANGUAGE plpgsql
        """,
        """
        CREATE TRIGGER recording_state_audit_no_update
          BEFORE UPDATE OR DELETE ON recording_state_audit
          FOR EACH ROW EXECUTE FUNCTION recording_audit_immutable()
        """,
        """
        CREATE TRIGGER recording_playback_audit_no_update
          BEFORE UPDATE OR DELETE ON recording_playback_audit
          FOR EACH ROW EXECUTE FUNCTION recording_audit_immutable()
        """,
    )
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE recording_state_audit, recording_outbox, recording_playback_audit,
          recording_retention_decisions, recording_retention_policies,
          recording_delivery_attempts, recording_objects,
          recording_upload_reservations, recordings CASCADE
        """
    )
    op.execute("DROP FUNCTION recording_audit_immutable()")
