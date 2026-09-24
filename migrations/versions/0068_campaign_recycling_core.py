"""MCR Milestone 10 durable lifecycle, suppression and exposure state.

Revision ID: 0068_campaign_recycling_core
Revises: 0067_service_catalog_monitoring_state

This migration creates the durable state required by the frozen MCR-A
contracts. It does not enable any provider capability or register public
routes. The command kernel tables are owned by the separate runtime SQL chain
(migrations/0001_runtime.sql ...); this Alembic migration therefore does not
declare a cross-chain foreign key. The application commits an exposure
reservation and its canonical command/outbox intent in one database transaction.
"""

from alembic import op

revision = "0068_campaign_recycling_core"
down_revision = "0067_service_catalog_monitoring_state"
branch_labels = None
depends_on = None


LIFECYCLE_STATES = (
    "NEW",
    "VALIDATED",
    "ELIGIBLE",
    "ACTIVE_CYCLE",
    "ENGAGED",
    "COOLING",
    "REACTIVATION",
    "CONVERTED",
    "SUPPRESSED",
)
CHANNELS = ("email", "sms", "whatsapp", "voice")
HEALTH_STATES = (
    "unknown",
    "valid",
    "possible",
    "soft_bounce",
    "hard_bounce",
    "complained",
    "unsubscribed",
    "suppressed",
    "invalid",
)
SUPPRESSION_SCOPES = ("global", "channel", "campaign", "campaign_channel")
SUPPRESSION_REASONS = (
    "legal_hold",
    "data_subject_request",
    "do_not_contact_request",
    "complaint",
    "unsubscribe",
    "consent_revoked",
    "dialing_do_not_call",
    "operator_block",
)
EXPOSURE_STATUSES = (
    "reserved",
    "accepted",
    "queued",
    "dispatched",
    "delivered",
    "failed",
    "cancelled",
    "suppressed",
    "expired",
    "indeterminate",
)
ENGAGEMENT_OUTCOMES = ("none", "open", "read", "click", "reply", "conversion")
NEGATIVE_OUTCOMES = ("none", "soft_bounce", "hard_bounce", "unsubscribe", "complaint")


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


def upgrade() -> None:
    op.execute(
        f"""CREATE TABLE mcr_lead_lifecycle_current (
          tenant_id text NOT NULL,
          lead_id text NOT NULL,
          state text NOT NULL CHECK (state IN ({_quoted(LIFECYCLE_STATES)})),
          version bigint NOT NULL CHECK (version >= 1),
          updated_at timestamptz NOT NULL,
          PRIMARY KEY (tenant_id, lead_id)
        )"""
    )
    op.execute(
        f"""CREATE TABLE mcr_lead_lifecycle_events (
          event_id bigserial PRIMARY KEY,
          tenant_id text NOT NULL,
          lead_id text NOT NULL,
          version bigint NOT NULL CHECK (version >= 1),
          from_state text CHECK (from_state IS NULL OR from_state IN ({_quoted(LIFECYCLE_STATES)})),
          to_state text NOT NULL CHECK (to_state IN ({_quoted(LIFECYCLE_STATES)})),
          reason_code text NOT NULL,
          source text NOT NULL,
          occurred_at timestamptz NOT NULL,
          recorded_at timestamptz NOT NULL DEFAULT now(),
          correlation_id text NOT NULL,
          evidence_hash char(64) NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{{64}}$'),
          evidence_ref text,
          UNIQUE (tenant_id, lead_id, version),
          FOREIGN KEY (tenant_id, lead_id)
            REFERENCES mcr_lead_lifecycle_current(tenant_id, lead_id)
            ON DELETE RESTRICT
        )"""
    )
    op.execute(
        f"""CREATE TABLE mcr_channel_health (
          tenant_id text NOT NULL,
          lead_id text NOT NULL,
          channel text NOT NULL CHECK (channel IN ({_quoted(CHANNELS)})),
          address_ref text NOT NULL,
          state text NOT NULL CHECK (state IN ({_quoted(HEALTH_STATES)})),
          previous_state text CHECK (previous_state IS NULL OR previous_state IN ({_quoted(HEALTH_STATES)})),
          source text NOT NULL,
          reason_code text NOT NULL,
          occurred_at timestamptz NOT NULL,
          recorded_at timestamptz NOT NULL DEFAULT now(),
          evidence_hash char(64) NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{{64}}$'),
          health_version bigint NOT NULL CHECK (health_version >= 1),
          correlation_id text NOT NULL,
          updated_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (tenant_id, lead_id, channel, address_ref)
        )"""
    )
    op.execute(
        f"""CREATE TABLE mcr_suppressions (
          tenant_id text NOT NULL,
          suppression_id uuid NOT NULL,
          lead_id text NOT NULL,
          scope text NOT NULL CHECK (scope IN ({_quoted(SUPPRESSION_SCOPES)})),
          channel text CHECK (channel IS NULL OR channel IN ({_quoted(CHANNELS)})),
          campaign_id text,
          reason text NOT NULL CHECK (reason IN ({_quoted(SUPPRESSION_REASONS)})),
          source text NOT NULL,
          occurred_at timestamptz NOT NULL,
          evidence_hash char(64) NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{{64}}$'),
          requested_by text NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (tenant_id, suppression_id),
          CHECK (
            (scope='global' AND channel IS NULL AND campaign_id IS NULL)
            OR (scope='channel' AND channel IS NOT NULL AND campaign_id IS NULL)
            OR (scope='campaign' AND channel IS NULL AND campaign_id IS NOT NULL)
            OR (scope='campaign_channel' AND channel IS NOT NULL AND campaign_id IS NOT NULL)
          ),
          CHECK (
            campaign_id IS NULL
            OR campaign_id ~ '^(klyrow|whatsapp):[A-Za-z0-9][A-Za-z0-9._-]{{0,199}}$'
          )
        )"""
    )
    op.execute(
        f"""CREATE TABLE mcr_exposures (
          exposure_id uuid NOT NULL,
          tenant_id text NOT NULL,
          lead_id text NOT NULL,
          campaign_id text NOT NULL
            CHECK (campaign_id ~ '^(klyrow|whatsapp):[A-Za-z0-9][A-Za-z0-9._-]{{0,199}}$'),
          campaign_version integer NOT NULL CHECK (campaign_version >= 1),
          channel text NOT NULL CHECK (channel IN ({_quoted(CHANNELS)})),
          touch_index integer NOT NULL CHECK (touch_index >= 1),
          idempotency_key text NOT NULL,
          command_id uuid NOT NULL,
          decision_id uuid NOT NULL,
          policy_version text NOT NULL,
          sender_identity_id uuid,
          status text NOT NULL CHECK (status IN ({_quoted(EXPOSURE_STATUSES)})),
          engagement_outcome text NOT NULL DEFAULT 'none'
            CHECK (engagement_outcome IN ({_quoted(ENGAGEMENT_OUTCOMES)})),
          negative_outcome text NOT NULL DEFAULT 'none'
            CHECK (negative_outcome IN ({_quoted(NEGATIVE_OUTCOMES)})),
          message_id text,
          provider_message_id text,
          reserved_at timestamptz NOT NULL,
          dispatched_at timestamptz,
          accepted_at timestamptz,
          delivered_at timestamptz,
          status_at timestamptz NOT NULL,
          engagement_outcome_at timestamptz,
          negative_outcome_at timestamptz,
          updated_at timestamptz NOT NULL,
          PRIMARY KEY (tenant_id, exposure_id),
          UNIQUE (tenant_id, lead_id, campaign_id, campaign_version, channel, touch_index),
          UNIQUE (tenant_id, idempotency_key),
          UNIQUE (tenant_id, command_id),
          CHECK (channel='voice' OR sender_identity_id IS NOT NULL)
        )"""
    )

    op.execute(
        "CREATE INDEX ix_mcr_lifecycle_events_journey "
        "ON mcr_lead_lifecycle_events(tenant_id, lead_id, occurred_at, event_id)"
    )
    op.execute(
        "CREATE INDEX ix_mcr_channel_health_lead "
        "ON mcr_channel_health(tenant_id, lead_id, channel)"
    )
    op.execute(
        "CREATE INDEX ix_mcr_suppressions_match "
        "ON mcr_suppressions(tenant_id, lead_id, scope, channel, campaign_id, occurred_at)"
    )
    op.execute(
        "CREATE INDEX ix_mcr_exposures_lead_time "
        "ON mcr_exposures(tenant_id, lead_id, reserved_at DESC)"
    )
    op.execute(
        "CREATE INDEX ix_mcr_exposures_campaign_time "
        "ON mcr_exposures(tenant_id, lead_id, campaign_id, reserved_at DESC)"
    )

    op.execute(
        """CREATE FUNCTION mcr_reject_append_only_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'MCR append-only evidence cannot be updated or deleted';
        END;
        $$"""
    )
    op.execute(
        """CREATE TRIGGER mcr_lifecycle_events_append_only
        BEFORE UPDATE OR DELETE ON mcr_lead_lifecycle_events
        FOR EACH ROW EXECUTE FUNCTION mcr_reject_append_only_mutation()"""
    )
    op.execute(
        """CREATE TRIGGER mcr_suppressions_append_only
        BEFORE UPDATE OR DELETE ON mcr_suppressions
        FOR EACH ROW EXECUTE FUNCTION mcr_reject_append_only_mutation()"""
    )


def downgrade() -> None:
    op.execute(
        """DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM mcr_lead_lifecycle_current)
             OR EXISTS (SELECT 1 FROM mcr_lead_lifecycle_events)
             OR EXISTS (SELECT 1 FROM mcr_channel_health)
             OR EXISTS (SELECT 1 FROM mcr_suppressions)
             OR EXISTS (SELECT 1 FROM mcr_exposures) THEN
            RAISE EXCEPTION 'MCR core tables contain durable evidence; downgrade refused';
          END IF;
        END $$"""
    )
    op.execute("DROP TRIGGER IF EXISTS mcr_suppressions_append_only ON mcr_suppressions")
    op.execute(
        "DROP TRIGGER IF EXISTS mcr_lifecycle_events_append_only "
        "ON mcr_lead_lifecycle_events"
    )
    op.execute("DROP FUNCTION IF EXISTS mcr_reject_append_only_mutation()")
    op.execute("DROP TABLE mcr_exposures")
    op.execute("DROP TABLE mcr_suppressions")
    op.execute("DROP TABLE mcr_channel_health")
    op.execute("DROP TABLE mcr_lead_lifecycle_events")
    op.execute("DROP TABLE mcr_lead_lifecycle_current")
