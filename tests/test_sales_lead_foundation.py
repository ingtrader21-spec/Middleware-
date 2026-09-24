from __future__ import annotations

import asyncio
import hashlib
import json

import pytest
import httpx
from pydantic import ValidationError

from app.sales.auth import (
    NonceLedger,
    ScraperAuthenticationError,
    ScraperIdentity,
    signature,
    verify,
)
from app.sales.compliance import ComplianceSnapshot, ComplianceStatus, evaluate
from app.sales.contracts import LeadCandidate, VerificationJobRequest
from app.sales.identity import (
    Match,
    OdooCompany,
    OdooContact,
    company_match,
    contact_match,
)
from app.sales.normalization import (
    normalized_company_name,
    normalized_domain,
    normalized_phone,
    registrable_domain,
)
from app.sales.odoo import (
    FakeOdooReadOnlyAdapter,
    OdooLookup,
    RegistryOdooReadOnlyAdapter,
)
from app.sales.providers import (
    DisabledProvider,
    FakeProvider,
    ProviderResult,
    ProviderState,
)
from app.sales.service import SalesConflict, SalesLeadService


def candidate(**updates):
    value = {
        "schema_version": "codestra.sales.lead-candidate.v1",
        "tenant_id": "tenant-a",
        "campaign_id": "campaign-a",
        "source": {
            "provider": "self_hosted_scraper",
            "job_id": "job-1",
            "request_id": "request-1",
            "collected_at": "2026-08-08T12:00:00Z",
        },
        "company": {
            "name": "Acme, Inc.",
            "domain": "www.example.com",
            "website_url": "https://example.com/contact",
            "country_code": "US",
            "address": {
                "line1": "1 Main St",
                "city": "Miami",
                "region": "FL",
                "country_code": "US",
            },
        },
        "contact": {
            "full_name": "Jane Doe",
            "title": "Director",
            "business_email": "jane@example.com",
            "business_phone": "+13055550123",
            "country_code": "US",
        },
        "evidence": [
            {
                "field": "company.domain",
                "source_url": "https://example.com/contact",
                "page_title": "Contact",
                "snippet": "Public business contact evidence",
                "content_hash": "a" * 64,
                "observed_at": "2026-08-08T12:00:00Z",
                "field_paths": [
                    "company.name",
                    "company.domain",
                    "company.website_url",
                    "company.registration_number",
                    "company.address.line1",
                    "company.address.city",
                    "company.address.region",
                    "contact.full_name",
                    "contact.title",
                    "contact.business_email",
                    "contact.business_phone",
                ],
            }
        ],
        "source_claims": {
            "consent_claimed": True,
            "consent_source": "provider",
            "consent_timestamp": "2026-08-08T12:00:00Z",
        },
        "metadata": {"batch": "synthetic"},
    }
    value.update(updates)
    return LeadCandidate.model_validate(value)


def eligible_lookup(*, companies=None, contacts=None, consent="GRANTED", **gates):
    return OdooLookup(
        companies or [],
        contacts or [],
        ComplianceSnapshot(
            "tenant-a", "campaign-a", consent=consent, channel_eligible=True, **gates
        ),
    )


def run(value):
    return asyncio.run(value)


def test_valid_minimum_and_fully_populated_contract():
    minimum = candidate(contact={}, source_claims={}, metadata={})
    full = candidate()
    assert minimum.tenant_id == full.tenant_id == "tenant-a"
    assert full.source_claims.consent_claimed is True  # captured, never authoritative


def test_material_values_without_evidence_are_rejected():
    with pytest.raises(ValidationError):
        candidate(evidence=[])


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("tenant_id",), ""),
        (("campaign_id",), ""),
        (("schema_version",), "unsupported"),
        (("source", "collected_at"), "2026-08-08T12:00:00"),
        (("contact", "business_email"), "malformed"),
        (("evidence", 0, "source_url"), "http://127.0.0.1/private"),
        (("evidence", 0, "source_url"), "https://user:pass@example.com/evidence"),
        (("evidence", 0, "source_url"), "https://example.com/tool.exe"),
        (("evidence", 0, "snippet"), "x" * 513),
    ],
)
def test_invalid_contract_matrix(path, value):
    document = candidate().model_dump(mode="json")
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        LeadCandidate.model_validate(document)


def test_unknown_fields_and_too_many_evidence_rejected():
    document = candidate().model_dump(mode="json")
    document["unknown"] = True
    with pytest.raises(ValidationError):
        LeadCandidate.model_validate(document)
    document.pop("unknown")
    document["evidence"] *= 21
    with pytest.raises(ValidationError):
        LeadCandidate.model_validate(document)


def test_normalization_is_deterministic_and_country_safe():
    assert normalized_company_name("  ACME, Inc. ") == "acme"
    assert (
        normalized_domain("https://WWW.xn--bcher-kva.example/path?q=1")
        == "xn--bcher-kva.example"
    )
    assert registrable_domain("sales.example.co.uk") == "example.co.uk"
    phone = normalized_phone("(305) 555-0123 ext. 9", "US")
    assert phone and phone.e164 == "+13055550123" and phone.extension == "9"
    with pytest.raises(ValueError):
        normalized_phone("3055550123", None)


def test_exact_registration_domain_and_cross_tenant_company_matching():
    item = candidate(
        company={**candidate().company.model_dump(), "registration_number": "REG-1"}
    )
    registration = OdooCompany(
        "company-1", "tenant-a", "Other", registration_number="reg-1", country_code="US"
    )
    domain = OdooCompany(
        "company-2",
        "tenant-a",
        "Other",
        domain="https://example.com",
        country_code="US",
    )
    foreign = OdooCompany(
        "company-3", "tenant-b", "Acme", domain="example.com", country_code="US"
    )
    assert company_match(item, registration).score == 100
    assert company_match(item, domain).score == 95
    assert company_match(item, foreign).reasons == ("CROSS_TENANT_DENIED",)


def test_contact_exact_and_weak_identifiers_review_only():
    item = candidate()
    company = Match(95, "company-1", ("ROOT_DOMAIN_EXACT",))
    exact = OdooContact(
        "lead-1", "tenant-a", "company-1", "Someone", business_email="JANE@example.com"
    )
    role = OdooContact(
        "lead-2", "tenant-a", "company-1", "Someone", business_email="info@example.com"
    )
    switchboard = OdooContact(
        "lead-3",
        "tenant-a",
        "company-x",
        "Someone",
        business_phone="+13055550123",
        country_code="US",
    )
    assert contact_match(item, exact, company).score == 100
    role_candidate = candidate(
        contact={**item.contact.model_dump(), "business_email": "info@example.com"}
    )
    assert contact_match(role_candidate, role, company).score == 75
    assert contact_match(item, switchboard, Match()).score == 75


def test_fuzzy_company_and_person_create_review_scores():
    item = candidate(
        company={
            **candidate().company.model_dump(),
            "name": "Acme Logistics Group",
            "domain": None,
            "website_url": None,
        }
    )
    company = OdooCompany(
        "company-1",
        "tenant-a",
        "Acme Logistics Grup",
        country_code="US",
        city="Miami",
        region="FL",
    )
    match = company_match(item, company)
    assert 70 <= match.score < 90
    person = OdooContact("lead-1", "tenant-a", "company-1", "Jane Do", title="Director")
    assert 70 <= contact_match(item, person, Match(95, "company-1")).score < 90


@pytest.mark.parametrize(
    ("snapshot", "expected"),
    [
        (
            ComplianceSnapshot("tenant-a", "campaign-a", global_dnc=True),
            ComplianceStatus.BLOCKED_GLOBAL_DNC,
        ),
        (
            ComplianceSnapshot("tenant-a", "campaign-a", campaign_dnc=True),
            ComplianceStatus.BLOCKED_CAMPAIGN_DNC,
        ),
        (
            ComplianceSnapshot("tenant-a", "campaign-a", internal_suppression=True),
            ComplianceStatus.BLOCKED_INTERNAL_SUPPRESSION,
        ),
        (
            ComplianceSnapshot("tenant-a", "campaign-a", consent="WITHDRAWN"),
            ComplianceStatus.BLOCKED_CONSENT_WITHDRAWN,
        ),
        (
            ComplianceSnapshot("tenant-a", "campaign-a", consent="UNKNOWN"),
            ComplianceStatus.REVIEW_CONSENT_UNKNOWN,
        ),
        (
            ComplianceSnapshot("tenant-a", "campaign-a", available=False),
            ComplianceStatus.DEPENDENCY_UNAVAILABLE,
        ),
    ],
)
def test_compliance_precedence_and_fail_closed(snapshot, expected):
    assert evaluate(snapshot, "tenant-a", "campaign-a").status == expected


def test_campaign_dnc_does_not_cross_campaign_and_high_score_cannot_override():
    wrong_campaign = ComplianceSnapshot("tenant-a", "campaign-b", campaign_dnc=True)
    assert (
        evaluate(wrong_campaign, "tenant-a", "campaign-a").status
        == ComplianceStatus.DEPENDENCY_UNAVAILABLE
    )
    adapter = FakeOdooReadOnlyAdapter(
        eligible_lookup(
            companies=[
                OdooCompany(
                    "company-1",
                    "tenant-a",
                    "Acme",
                    domain="example.com",
                    country_code="US",
                )
            ],
            global_dnc=True,
        )
    )
    result, _ = run(
        SalesLeadService(adapter).resolve(candidate(), "idempotency-key-0001", "corr-1")
    )
    assert result.decision == "SUPPRESSED"


def test_idempotent_replay_conflict_concurrency_and_cross_tenant_isolation():
    service = SalesLeadService(FakeOdooReadOnlyAdapter(eligible_lookup()))
    first, replay = run(service.resolve(candidate(), "idempotency-key-0001", "corr-1"))
    second, replay2 = run(
        service.resolve(candidate(), "idempotency-key-0001", "corr-2")
    )
    assert first == second and not replay and replay2
    changed = candidate(
        company={**candidate().company.model_dump(), "name": "Different"}
    )
    with pytest.raises(SalesConflict):
        run(service.resolve(changed, "idempotency-key-0001", "corr-3"))
    foreign = candidate(tenant_id="tenant-b")
    foreign_result, _ = run(service.resolve(foreign, "idempotency-key-0001", "corr-4"))
    assert foreign_result.candidate_id != first.candidate_id

    async def concurrent():
        next_service = SalesLeadService(FakeOdooReadOnlyAdapter(eligible_lookup()))
        return await asyncio.gather(
            next_service.resolve(candidate(), "concurrent-key-0001", "corr-a"),
            next_service.resolve(candidate(), "concurrent-key-0001", "corr-b"),
        )

    values = run(concurrent())
    assert values[0][0].candidate_id == values[1][0].candidate_id
    assert sorted(value[1] for value in values) == [False, True]


def test_possible_duplicate_review_and_zero_writes():
    company = OdooCompany(
        "company-1",
        "tenant-a",
        "Acme Incorporated",
        country_code="US",
        city="Miami",
        region="FL",
    )
    item = candidate(
        company={
            **candidate().company.model_dump(),
            "domain": None,
            "website_url": None,
        }
    )
    adapter = FakeOdooReadOnlyAdapter(eligible_lookup(companies=[company]))
    service = SalesLeadService(adapter)
    result, _ = run(service.resolve(item, "idempotency-key-0002", "corr-1"))
    assert result.decision == "POSSIBLE_DUPLICATE"
    assert len(service.reviews) == 1
    assert adapter.create_count == adapter.update_count == adapter.delete_count == 0
    assert service.vicidial_write_count == service.outreach_event_count == 0


def test_authoritative_failure_never_classifies_net_new():
    adapter = FakeOdooReadOnlyAdapter()
    adapter.unavailable = True
    result, _ = run(
        SalesLeadService(adapter).resolve(candidate(), "idempotency-key-0003", "corr-1")
    )
    assert result.decision == "MANUAL_REVIEW"
    assert result.decision_code == "ODOO_UNAVAILABLE"
    assert result.gates.global_dnc == "DEPENDENCY_UNAVAILABLE"


def test_verification_job_is_bounded_idempotent_and_write_free():
    adapter = FakeOdooReadOnlyAdapter(eligible_lookup(), [candidate()])
    service = SalesLeadService(adapter)
    request = VerificationJobRequest(
        source="odoo",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        dry_run=True,
        write_changes=False,
        publish_to_vicidial=False,
        batch_size=100,
    )
    job, replay = run(service.create_job(request, "verification-key-0001", "corr-1"))
    repeated, replay2 = run(
        service.create_job(request, "verification-key-0001", "corr-2")
    )
    assert job.state == "COMPLETED" and job.processed == 1
    assert repeated.job_id == job.job_id and not replay and replay2
    assert adapter.create_count == adapter.update_count == adapter.delete_count == 0
    with pytest.raises(ValidationError):
        VerificationJobRequest(
            source="odoo",
            tenant_id="tenant-a",
            dry_run=False,
            write_changes=True,
            publish_to_vicidial=True,
            batch_size=101,
        )


def test_scraper_signature_matrix_and_replay():
    body = json.dumps(
        candidate().model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    identity = ScraperIdentity(
        "scraper-c",
        "tenant-a",
        frozenset({"campaign-a"}),
        "scraper-key-2026-08",
        b"s" * 32,
    )
    timestamp = "1786190400"
    kwargs = dict(
        identity=identity,
        key_id="scraper-key-2026-08",
        scraper_id="scraper-c",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        request_id="request-1",
        timestamp=timestamp,
        nonce="nonce-1",
        body=body,
        supplied_hash=hashlib.sha256(body).hexdigest(),
        version="hmac-sha256-v2",
        now=1786190400,
    )
    supplied = signature(
        identity=identity,
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        request_id="request-1",
        timestamp=timestamp,
        nonce="nonce-1",
        body=body,
    )
    ledger = NonceLedger()
    verify(**kwargs, supplied_signature=supplied, nonces=ledger)
    with pytest.raises(ScraperAuthenticationError, match="REPLAYED_NONCE"):
        verify(**kwargs, supplied_signature=supplied, nonces=ledger)
    for changed in (
        {
            "key_id": "unknown-key",
            "supplied_signature": supplied,
            "nonces": NonceLedger(),
        },
        {"supplied_signature": "0" * 64, "nonces": NonceLedger()},
        {
            "supplied_hash": "0" * 64,
            "supplied_signature": supplied,
            "nonces": NonceLedger(),
        },
        {
            "tenant_id": "tenant-b",
            "supplied_signature": supplied,
            "nonces": NonceLedger(),
        },
        {"identity": None, "supplied_signature": supplied, "nonces": NonceLedger()},
        {
            "version": "hmac-sha256-v1",
            "supplied_signature": supplied,
            "nonces": NonceLedger(),
        },
    ):
        current = {**kwargs, **changed}
        with pytest.raises(ScraperAuthenticationError):
            verify(**current)
    rotated = ScraperIdentity(
        "scraper-c",
        "tenant-a",
        frozenset({"campaign-a"}),
        "scraper-key-next",
        b"n" * 32,
    )
    rotated_kwargs = {
        **kwargs,
        "identity": rotated,
        "key_id": rotated.key_id,
        "nonce": "nonce-rotated",
    }
    rotated_signature = signature(
        identity=rotated,
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        request_id="request-1",
        timestamp=timestamp,
        nonce="nonce-rotated",
        body=body,
    )
    verify(
        **rotated_kwargs,
        supplied_signature=rotated_signature,
        nonces=NonceLedger(),
    )


def test_provider_interfaces_are_disabled_and_never_fabricate():
    disabled = DisabledProvider("hunter")
    result = run(disabled.execute("email_verification", {}))
    assert result.state == ProviderState.DISABLED and not result.authoritative
    fake = FakeProvider(
        "openai",
        {
            "lead_fit_explanation": ProviderResult(
                "openai",
                ProviderState.AVAILABLE,
                "lead_fit_explanation",
                normalized={"explanation": "non-authoritative"},
            )
        },
    )
    ai = run(fake.execute("lead_fit_explanation", {}))
    assert ai.authoritative is False


def test_registry_odoo_adapter_uses_read_operations_and_denies_scope_mismatch():
    class Client:
        def __init__(self):
            self.operations = []

        async def request(self, operation, payload, **kwargs):
            self.operations.append(operation)
            body = (
                {
                    "tenant_id": "tenant-a",
                    "companies": [],
                    "contacts": [],
                    "compliance": {
                        "tenant_id": "tenant-a",
                        "campaign_id": "campaign-a",
                        "consent": "GRANTED",
                    },
                }
                if operation == "sales.lookup"
                else {"tenant_id": "tenant-a", "records": []}
            )
            return httpx.Response(
                200,
                json=body,
                request=httpx.Request("POST", "https://odoo.test.invalid"),
            )

    client = Client()
    adapter = RegistryOdooReadOnlyAdapter(client)  # type: ignore[arg-type]
    assert run(adapter.lookup(candidate())).compliance is not None
    assert (
        run(adapter.verification_page("tenant-a", "campaign-a", offset=0, limit=10))
        == []
    )
    assert client.operations == ["sales.lookup", "sales.verification.read"]
    assert adapter.create_count == adapter.update_count == adapter.delete_count == 0
