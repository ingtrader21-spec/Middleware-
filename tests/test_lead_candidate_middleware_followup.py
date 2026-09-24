from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.sales.compliance import ComplianceSnapshot, evaluate
from app.sales.contracts import Decision, LeadCandidate
from app.sales.odoo import FakeOdooReadOnlyAdapter, OdooLookup
from app.sales.service import SalesLeadService
from tests.test_sales_lead_foundation import candidate


def run(value):
    return asyncio.run(value)


def test_extended_contract_preserves_unknowns_and_provenance():
    value = candidate(
        candidate_id="scraper-candidate-1",
        scraper_job_id="scrape-job-1",
        provenance=["PUBLIC_OBSERVATION", "UNKNOWN"],
        provider_results={"hunter": "DISABLED"},
        extraction_timestamp="2026-08-08T12:00:00Z",
        content_hashes=["sha256:" + "b" * 64],
        idempotency_metadata={"source_sequence": 1},
    )
    assert value.contact.company_association is None
    assert value.company.tax_identifier is None
    assert value.provenance[-1] == "UNKNOWN"


def test_evidence_rejects_unsupported_field_reference_and_bad_hash():
    document = candidate().model_dump(mode="json")
    document["evidence"][0]["field_paths"] = ["internal.secret"]
    with pytest.raises(ValidationError):
        LeadCandidate.model_validate(document)
    document = candidate().model_dump(mode="json")
    document["content_hashes"] = ["not-a-hash"]
    with pytest.raises(ValidationError):
        LeadCandidate.model_validate(document)


def test_public_source_consent_claim_never_grants_outreach():
    value = candidate()
    lookup = OdooLookup(
        compliance=ComplianceSnapshot(
            "tenant-a", "campaign-a", consent="UNKNOWN", channel_eligible=True
        )
    )
    result, _ = run(
        SalesLeadService(FakeOdooReadOnlyAdapter(lookup)).resolve(
            value, "followup-idempotency-1", "corr"
        )
    )
    assert value.source_claims.consent_claimed is True
    assert result.decision == Decision.MANUAL_REVIEW
    assert result.eligible_for_outreach is False
    assert result.consent_results == ["CONSENT_UNKNOWN"]


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"global_dnc": True}, "GLOBAL_DNC"),
        ({"tenant_dnc": True}, "TENANT_DNC"),
        ({"campaign_dnc": True}, "CAMPAIGN_DNC"),
        ({"email_suppressed": True}, "EMAIL_SUPPRESSED"),
        ({"phone_suppressed": True}, "PHONE_SUPPRESSED"),
        ({"opted_out": True}, "OPTED_OUT"),
    ],
)
def test_ordered_suppression_gates(updates, reason):
    snapshot = ComplianceSnapshot("tenant-a", "campaign-a", **updates)
    result = evaluate(snapshot, "tenant-a", "campaign-a")
    assert result.blocked is True
    assert result.reasons == (reason,)


def test_exact_replay_returns_original_rich_response():
    lookup = OdooLookup(
        compliance=ComplianceSnapshot(
            "tenant-a", "campaign-a", consent="GRANTED", channel_eligible=True
        )
    )
    service = SalesLeadService(FakeOdooReadOnlyAdapter(lookup))
    first, first_replay = run(
        service.resolve(candidate(), "followup-idempotency-2", "corr")
    )
    second, second_replay = run(
        service.resolve(candidate(), "followup-idempotency-2", "different")
    )
    assert first.decision == Decision.ACCEPTED
    assert first.eligible_for_storage is True
    assert first.eligible_for_outreach is True
    assert first_replay is False and second_replay is True
    assert second.candidate_id == first.candidate_id


def test_required_phase_one_switches_fail_closed():
    settings = Settings()
    assert settings.scraper_result_ingest_enabled is False
    assert settings.scraper_middleware_delivery_enabled is False
    assert settings.lead_verification_dry_run_only is True
    assert settings.odoo_lead_write_enabled is False
    assert settings.vicidial_lead_write_enabled is False
    assert settings.n8n_lead_delivery_enabled is False
    assert settings.postly_lead_delivery_enabled is False
    with pytest.raises(ValueError):
        Settings(scraper_middleware_delivery_enabled=True).validate_safety()
