"""Database-authoritative telephony pools, reservations and saga state."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0013_telephony_allocation"
down_revision = "0012_invalid_event_quarantine"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "telephony_extension_pool",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("business_unit", sa.String(64), nullable=False),
        sa.Column("role_class", sa.String(32), nullable=False),
        sa.Column("range_start", sa.Integer(), nullable=False),
        sa.Column("range_end", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.CheckConstraint("range_start >= 6100", name="ck_telephony_pool_start"),
        sa.CheckConstraint("range_end <= 6999", name="ck_telephony_pool_end"),
        sa.CheckConstraint("range_start <= range_end", name="ck_telephony_pool_order"),
    )
    op.create_index(
        "ix_telephony_pool_business_unit", "telephony_extension_pool", ["business_unit"]
    )
    op.create_table(
        "telephony_extension_reservation",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("extension", sa.Integer(), nullable=False),
        sa.Column("employee_id", sa.String(128), nullable=False),
        sa.Column("request_id", sa.String(128), nullable=False),
        sa.Column(
            "pool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("telephony_extension_pool.id"),
            nullable=False,
        ),
        sa.Column("state", sa.String(24), nullable=False, server_default="RESERVED"),
        sa.Column("idempotency_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column(
            "reserved_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.Column("cooldown_until", sa.DateTime(timezone=True)),
        sa.CheckConstraint("extension <> 6101", name="ck_telephony_reservation_6101"),
        sa.CheckConstraint("extension <> 1001", name="ck_telephony_reservation_1001"),
        sa.CheckConstraint(
            "state IN ('RESERVED','DISABLED_READY','ACTIVE','SUSPENDED','RELEASED','EXPIRED','COOLDOWN')",
            name="ck_telephony_reservation_state",
        ),
    )
    op.create_index(
        "ix_telephony_reservation_extension",
        "telephony_extension_reservation",
        ["extension"],
    )
    op.create_index(
        "ix_telephony_reservation_employee",
        "telephony_extension_reservation",
        ["employee_id"],
    )
    op.create_index(
        "uq_telephony_active_extension",
        "telephony_extension_reservation",
        ["extension"],
        unique=True,
        postgresql_where=sa.text(
            "state IN ('RESERVED','DISABLED_READY','ACTIVE','SUSPENDED','COOLDOWN')"
        ),
    )
    op.create_index(
        "uq_telephony_active_employee",
        "telephony_extension_reservation",
        ["employee_id"],
        unique=True,
        postgresql_where=sa.text(
            "state IN ('RESERVED','DISABLED_READY','ACTIVE','SUSPENDED')"
        ),
    )
    op.create_table(
        "telephony_provisioning_saga",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("request_id", sa.String(128), nullable=False, unique=True),
        sa.Column("employee_id", sa.String(128), nullable=False),
        sa.Column("business_unit", sa.String(64), nullable=False),
        sa.Column("campaign", sa.String(64), nullable=False),
        sa.Column("role", sa.String(64), nullable=False),
        sa.Column("extension", sa.Integer()),
        sa.Column("state", sa.String(32), nullable=False, server_default="DRAFT"),
        sa.Column("idempotency_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("correlation_id", sa.String(128), nullable=False, unique=True),
        sa.Column(
            "approved_odoo_request",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("credential_reference", sa.String(255)),
        sa.Column(
            "completed_steps", postgresql.JSONB(), nullable=False, server_default="[]"
        ),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("version >= 1", name="ck_telephony_saga_version"),
        sa.CheckConstraint(
            "state IN ('DRAFT','PENDING_APPROVAL','APPROVED','INVENTORY_CHECK','RESERVED','PROVISIONING','DISABLED_READY','ACTIVATION_PENDING','ACTIVE','FAILED','ROLLED_BACK','SUSPENDING','SUSPENDED','DEPROVISIONING','COOLDOWN')",
            name="ck_telephony_saga_state",
        ),
    )
    op.create_index(
        "ix_telephony_saga_employee", "telephony_provisioning_saga", ["employee_id"]
    )
    pools = [
        ("transportation-system", "Transportation", "system", 6100, 6109),
        ("transportation-intro-sales", "Transportation", "intro_sales", 6110, 6159),
        ("transportation-closers", "Transportation", "closer", 6160, 6169),
        ("transportation-retention", "Transportation", "retention", 6170, 6179),
        ("transportation-support", "Transportation", "support", 6180, 6189),
        ("transportation-overflow", "Transportation", "overflow", 6190, 6199),
    ]
    units = [
        ("moneybee-loans", "Moneybee Loans", 6200),
        ("web-ai-services", "Web and AI Services", 6300),
        ("senior-citizen-products", "Senior Citizen Products", 6400),
        ("student-repayment", "Student Repayment", 6500),
    ]
    for slug, unit, base in units:
        for suffix, role, low, high in (
            ("system", "system", 0, 9),
            ("intro-sales", "intro_sales", 10, 59),
            ("closers", "closer", 60, 69),
            ("retention", "retention", 70, 79),
            ("support", "support", 80, 89),
            ("overflow", "overflow", 90, 99),
        ):
            pools.append((f"{slug}-{suffix}", unit, role, base + low, base + high))
    pools.extend(
        [
            ("supervisors", "Supervisors and QA", "supervisor", 6900, 6929),
            ("quality-assurance", "Supervisors and QA", "qa", 6930, 6949),
            ("trainers-workforce", "Supervisors and QA", "trainer", 6950, 6964),
            ("operations-management", "Supervisors and QA", "operations", 6965, 6974),
            ("synthetic-training", "Supervisors and QA", "synthetic", 6975, 6989),
            ("supervisor-reserved", "Supervisors and QA", "reserved", 6990, 6999),
        ]
    )
    table = sa.table(
        "telephony_extension_pool",
        sa.column("id"),
        sa.column("code"),
        sa.column("business_unit"),
        sa.column("role_class"),
        sa.column("range_start"),
        sa.column("range_end"),
        sa.column("active"),
    )
    import uuid

    op.bulk_insert(
        table,
        [
            {
                "id": uuid.uuid4(),
                "code": c,
                "business_unit": u,
                "role_class": r,
                "range_start": a,
                "range_end": b,
                "active": True,
            }
            for c, u, r, a, b in pools
        ],
    )


def downgrade():
    op.drop_table("telephony_provisioning_saga")
    op.drop_table("telephony_extension_reservation")
    op.drop_table("telephony_extension_pool")
