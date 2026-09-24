"""Authenticated invalid-event quarantine and bounded security rejections."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012_invalid_event_quarantine"
down_revision = "0011_publisher_ack"
branch_labels = None
depends_on = None

STATES = (
    "PENDING_REVIEW",
    "UNDER_REVIEW",
    "CORRECTABLE",
    "REPLAY_APPROVED",
    "REPLAYING",
    "REPLAYED",
    "RESOLVED_NO_REPLAY",
    "EXPIRED",
    "REJECTED",
)


def upgrade():
    op.create_table(
        "security_rejection",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("claimed_publisher", sa.String(128)),
        sa.Column(
            "authentication_state",
            sa.String(16),
            nullable=False,
            server_default="UNVERIFIED",
        ),
        sa.Column("key_id", sa.String(64)),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("payload_fingerprint", sa.String(64), nullable=False),
        sa.Column("source_ip_classification", sa.String(16), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "reason_code IN ('missing_authentication','unknown_key','invalid_signature',"
            "'altered_body','invalid_timestamp','expired_timestamp','future_timestamp',"
            "'replayed_nonce','rate_limited')",
            name="ck_security_rejection_reason",
        ),
        sa.CheckConstraint(
            "source_ip_classification IN ('loopback','private','public','unknown')",
            name="ck_security_rejection_source_class",
        ),
        sa.CheckConstraint(
            "authentication_state = 'UNVERIFIED'",
            name="ck_security_rejection_unverified",
        ),
    )
    op.create_index(
        "ix_security_rejection_correlation", "security_rejection", ["correlation_id"]
    )
    op.create_table(
        "invalid_event_quarantine",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("server_correlation_id", sa.String(128), nullable=False),
        sa.Column("client_correlation_id", sa.String(128)),
        sa.Column("claimed_source", sa.String(64)),
        sa.Column("claimed_publisher_identity", sa.String(128)),
        sa.Column("authenticated_publisher_id", sa.String(128), nullable=False),
        sa.Column("authentication_state", sa.String(24), nullable=False),
        sa.Column("authentication_key_id", sa.String(64)),
        sa.Column("original_signature_verification", sa.String(24), nullable=False),
        sa.Column("payload_fingerprint", sa.String(64), nullable=False),
        sa.Column("encrypted_payload", sa.LargeBinary()),
        sa.Column("encryption_nonce", sa.LargeBinary()),
        sa.Column("encryption_key_version", sa.String(32)),
        sa.Column("sanitized_preview", postgresql.JSONB(), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("business_unit", sa.String(16)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("review_owner", sa.String(128)),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_by", sa.String(128)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column(
            "replayed_event_id", sa.BigInteger(), sa.ForeignKey("integration_event.id")
        ),
        sa.Column("replay_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("retention_policy_version", sa.String(32), nullable=False),
        sa.Column("retention_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("replay_count >= 0", name="ck_quarantine_replay_count"),
        sa.CheckConstraint(
            "occurrence_count >= 1", name="ck_quarantine_occurrence_count"
        ),
        sa.CheckConstraint(
            "retention_deadline > received_at", name="ck_quarantine_retention"
        ),
        sa.CheckConstraint("record_version >= 1", name="ck_quarantine_record_version"),
        sa.CheckConstraint(
            "(review_owner IS NULL) = (reviewed_at IS NULL)",
            name="ck_quarantine_review_consistency",
        ),
        sa.CheckConstraint(
            "(resolved_by IS NULL) = (resolved_at IS NULL)",
            name="ck_quarantine_resolution_consistency",
        ),
        sa.CheckConstraint(
            "status IN (" + ",".join(f"'{state}'" for state in STATES) + ")",
            name="ck_quarantine_state",
        ),
        sa.CheckConstraint(
            "authentication_state = 'VERIFIED' AND original_signature_verification = 'VERIFIED'",
            name="ck_quarantine_verified_auth",
        ),
        sa.CheckConstraint(
            "(encrypted_payload IS NULL AND encryption_nonce IS NULL AND encryption_key_version IS NULL) OR "
            "(encrypted_payload IS NOT NULL AND encryption_nonce IS NOT NULL AND encryption_key_version IS NOT NULL)",
            name="ck_quarantine_encryption_fields",
        ),
        sa.CheckConstraint(
            "replayed_event_id IS NULL OR (authentication_state='VERIFIED' AND status='REPLAYED' AND resolved_at IS NOT NULL)",
            name="ck_quarantine_replay_eligibility",
        ),
    )
    op.create_index(
        "ix_quarantine_status_received",
        "invalid_event_quarantine",
        ["status", "received_at"],
    )
    op.create_index(
        "ix_quarantine_publisher_received",
        "invalid_event_quarantine",
        ["authenticated_publisher_id", "received_at"],
    )
    op.create_index(
        "ix_quarantine_correlation",
        "invalid_event_quarantine",
        ["server_correlation_id"],
    )
    op.create_index(
        "ix_quarantine_fingerprint", "invalid_event_quarantine", ["payload_fingerprint"]
    )
    op.create_index(
        "ix_quarantine_retention_active",
        "invalid_event_quarantine",
        ["retention_deadline"],
        postgresql_where=sa.text("legal_hold = false"),
    )
    op.create_table(
        "quarantine_correction",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "quarantine_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("invalid_event_quarantine.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("correction_version", sa.Integer(), nullable=False),
        sa.Column("correction_reason", sa.String(512), nullable=False),
        sa.Column("reviewer", sa.String(128), nullable=False),
        sa.Column("derived_correlation_id", sa.String(128), nullable=False),
        sa.Column("payload_fingerprint", sa.String(64), nullable=False),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("encryption_key_version", sa.String(32), nullable=False),
        sa.Column("sanitized_diff", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "correction_version >= 1", name="ck_quarantine_correction_version"
        ),
        sa.UniqueConstraint(
            "quarantine_id",
            "correction_version",
            name="uq_quarantine_correction_version",
        ),
    )
    op.execute(
        """
        CREATE FUNCTION guard_quarantine_transition() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.status = OLD.status THEN
            RETURN NEW;
          END IF;
          IF NOT (
            (OLD.status='PENDING_REVIEW' AND NEW.status IN ('UNDER_REVIEW','EXPIRED','REJECTED')) OR
            (OLD.status='UNDER_REVIEW' AND NEW.status IN ('CORRECTABLE','REPLAY_APPROVED','RESOLVED_NO_REPLAY','REJECTED')) OR
            (OLD.status='CORRECTABLE' AND NEW.status IN ('REPLAY_APPROVED','RESOLVED_NO_REPLAY','REJECTED')) OR
            (OLD.status='REPLAY_APPROVED' AND NEW.status IN ('REPLAYING','RESOLVED_NO_REPLAY')) OR
            (OLD.status='REPLAYING' AND NEW.status IN ('REPLAYED','REPLAY_APPROVED','REJECTED'))
          ) THEN
            RAISE EXCEPTION 'invalid quarantine state transition: % -> %', OLD.status, NEW.status
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_quarantine_transition
        BEFORE UPDATE OF status ON invalid_event_quarantine
        FOR EACH ROW EXECUTE FUNCTION guard_quarantine_transition()
        """
    )


def downgrade():
    op.execute("DROP TRIGGER trg_quarantine_transition ON invalid_event_quarantine")
    op.execute("DROP FUNCTION guard_quarantine_transition()")
    op.drop_table("quarantine_correction")
    op.drop_table("invalid_event_quarantine")
    op.drop_table("security_rejection")
