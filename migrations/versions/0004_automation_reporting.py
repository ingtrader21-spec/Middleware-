"""Automation gateway and reporting star schema.

Revision ID: 0004_automation_reporting
Revises: 0003_phase1_compat
"""

from alembic import op

revision = "0004_automation_reporting"
down_revision = "0003_phase1_compat"
branch_labels = None
depends_on = None

DIMENSIONS = ("date", "campaign", "agent", "disposition", "list")
FACTS = (
    "call",
    "agent_session",
    "agent_state",
    "callback",
    "lead",
    "sale",
    "qa",
    "automation_execution",
)


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS reporting")
    for name in DIMENSIONS:
        op.execute(
            f"CREATE TABLE reporting.dim_{name} (id bigserial PRIMARY KEY, natural_key text NOT NULL UNIQUE, attributes jsonb NOT NULL DEFAULT '{{}}'::jsonb, valid_from timestamptz NOT NULL DEFAULT now(), valid_to timestamptz)"
        )
    for name in FACTS:
        op.execute(
            f"CREATE TABLE reporting.fact_{name} (id bigserial PRIMARY KEY, occurred_at timestamptz NOT NULL, campaign_key text, agent_key text, measures jsonb NOT NULL DEFAULT '{{}}'::jsonb, dimensions jsonb NOT NULL DEFAULT '{{}}'::jsonb)"
        )
        op.execute(
            f"CREATE INDEX ix_fact_{name}_occurred_at ON reporting.fact_{name} (occurred_at)"
        )


def downgrade() -> None:
    for name in reversed(FACTS):
        op.execute(f"DROP TABLE IF EXISTS reporting.fact_{name}")
    for name in reversed(DIMENSIONS):
        op.execute(f"DROP TABLE IF EXISTS reporting.dim_{name}")
    op.execute("DROP SCHEMA IF EXISTS reporting")
