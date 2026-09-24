"""Reserve the eight permanent disabled campaign identities and ranges.

Revision ID: 0017_campaign_registry_seed
Revises: 0016_campaign_registry_ids
"""

from uuid import UUID

from alembic import op
import sqlalchemy as sa


revision = "0017_campaign_registry_seed"
down_revision = "0016_campaign_registry_ids"
branch_labels = None
depends_on = None

POLICY_HASH = "13b6e2b3afc77d1d50c6f951312497a5d11b314fda5b2b7fb32a3a29125976c9"
SOURCE_CHANGE = "campaign-registry-v1"
CAMPAIGNS = (
    (
        100,
        "RLP International Real Estate",
        "RLP",
        "RLP100",
        7100,
        7199,
        "RLP100_AGENTS",
        "cs-prod-rlp100",
        None,
    ),
    (
        200,
        "TradeX",
        "TRD",
        "TRD200",
        7200,
        7299,
        "TRD200_AGENTS",
        "cs-prod-trd200",
        None,
    ),
    (
        300,
        "Moy Logistics",
        "MOY",
        "MOY300",
        7300,
        7399,
        "MOY300_AGENTS",
        "cs-prod-moy300",
        None,
    ),
    (
        400,
        "Codestra",
        "COD",
        "COD400",
        7400,
        7499,
        "COD400_AGENTS",
        "cs-prod-cod400",
        None,
    ),
    (
        500,
        "Senior Citizen Products",
        "SCP",
        "SCP500",
        7500,
        7599,
        "SCP500_AGENTS",
        "cs-prod-scp500",
        None,
    ),
    (
        600,
        "MoneyBee Business Loans",
        "MBL",
        "MBL600",
        7600,
        7699,
        "MBL600_AGENTS",
        "cs-prod-mbl600",
        None,
    ),
    (
        700,
        "For the People",
        "FTP",
        "FTP700",
        7700,
        7799,
        "FTP700_AGENTS",
        "cs-prod-ftp700",
        None,
    ),
    (
        800,
        "Calderon Farm",
        "CAL",
        "CAL800",
        7800,
        7899,
        "CAL800_AGENTS",
        "cs-prod-cal800",
        300,
    ),
)
FEATURES = (
    "VICIDIAL_WRITES",
    "CALLBACKS",
    "TRANSFERS",
    "WEBRTC",
    "N8N",
    "EMAIL",
    "SMS",
    "LIFECYCLE_DELIVERY",
)


def _uuid(number: int, suffix: int) -> UUID:
    return UUID(f"00000000-0000-{number:04d}-0000-{suffix:012d}")


def upgrade():
    allocation = sa.table(
        "campaign_extension_allocation",
        sa.column("id"),
        sa.column("campaign_id"),
        sa.column("campaign_number"),
        sa.column("allocation_public_id"),
        sa.column("extension_start"),
        sa.column("extension_end"),
        sa.column("allocation_status"),
        sa.column("created_by"),
        sa.column("policy_hash"),
        sa.column("source_change_id"),
    )
    registry = sa.table(
        "campaign_registry",
        sa.column("id"),
        sa.column("campaign_number"),
        sa.column("campaign_code"),
        sa.column("campaign_public_id"),
        sa.column("name"),
        sa.column("vicidial_campaign_id"),
        sa.column("agent_group"),
        sa.column("dialplan_context"),
        sa.column("parent_campaign_number"),
        sa.column("extension_allocation_id"),
        sa.column("registry_status"),
        sa.column("policy_hash"),
        sa.column("source_change_id"),
    )
    gates = sa.table(
        "campaign_feature_gate",
        sa.column("campaign_number"),
        sa.column("feature_name"),
        sa.column("status"),
        sa.column("policy_hash"),
    )
    op.bulk_insert(
        allocation,
        [
            {
                "id": _uuid(number, 1),
                "campaign_id": f"CMP-{number}-{code}",
                "campaign_number": number,
                "allocation_public_id": f"CMP-{number}-{code}-RANGE",
                "extension_start": start,
                "extension_end": end,
                "allocation_status": "PROPOSED",
                "created_by": "migration-0017",
                "policy_hash": POLICY_HASH,
                "source_change_id": SOURCE_CHANGE,
            }
            for number, _, code, _, start, end, _, _, _ in CAMPAIGNS
        ],
    )
    # Parents must exist before children.
    op.bulk_insert(
        registry,
        [
            {
                "id": _uuid(number, 2),
                "campaign_number": number,
                "campaign_code": code,
                "campaign_public_id": f"CMP-{number}-{code}",
                "name": name,
                "vicidial_campaign_id": vicidial,
                "agent_group": group,
                "dialplan_context": context,
                "parent_campaign_number": parent,
                "extension_allocation_id": _uuid(number, 1),
                "registry_status": "PROPOSED_DISABLED",
                "policy_hash": POLICY_HASH,
                "source_change_id": SOURCE_CHANGE,
            }
            for number, name, code, vicidial, _, _, group, context, parent in CAMPAIGNS
        ],
    )
    op.bulk_insert(
        gates,
        [
            {
                "campaign_number": number,
                "feature_name": feature,
                "status": "DISABLED",
                "policy_hash": POLICY_HASH,
            }
            for number, *_ in CAMPAIGNS
            for feature in FEATURES
        ],
    )


def downgrade():
    raise RuntimeError(
        "campaign-registry-v1 identities are permanent and cannot be downgraded"
    )
