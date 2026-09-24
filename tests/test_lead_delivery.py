from datetime import UTC, datetime

from app.lead_delivery import build_odoo_lead_upsert_command
from app.lead_intake import LeadSubmission, build_lead_submitted_event


SUBMITTED_AT = datetime(2026, 8, 29, 19, 45, tzinfo=UTC)


def test_lead_event_maps_to_idempotent_odoo_command() -> None:
    submission = LeadSubmission(
        tenantId="tenant-1",
        siteId="site-1",
        submittedAt=SUBMITTED_AT,
        source="landing_page",
        campaignId="campaign-1",
        name="Ada Example",
        email="ada@example.com",
    )
    event = build_lead_submitted_event(
        submission,
        idempotency_key="intake-idempotency-123",
        correlation_id="correlation-123",
    )

    first = build_odoo_lead_upsert_command(event)
    second = build_odoo_lead_upsert_command(event)

    assert first == second
    assert first.command_type == "crm.lead.intake.upsert.v1"
    assert first.target == "odoo-19"
    assert first.capability == "ODOO_WRITE"
    assert first.tenant_id == "tenant-1"
    assert first.payload["model"] == "crm.lead"
    assert first.payload["method"] == "codestra_upsert_intake_lead"
    assert first.payload["source_event_id"] == event.event_id


def test_odoo_mapping_rejects_unrelated_events() -> None:
    submission = LeadSubmission(
        tenantId="tenant-1",
        siteId="site-1",
        submittedAt=SUBMITTED_AT,
        source="form",
    )
    event = build_lead_submitted_event(
        submission,
        idempotency_key="intake-idempotency-456",
        correlation_id="correlation-456",
    ).model_copy(update={"event_type": "codestra.events.sms_received"})

    try:
        build_odoo_lead_upsert_command(event)
    except ValueError as exc:
        assert "not a lead submission" in str(exc)
    else:
        raise AssertionError("unrelated event must be rejected")
