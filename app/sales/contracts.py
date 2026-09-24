from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CANDIDATE_SCHEMA = "codestra.sales.lead-candidate.v1"
RESOLUTION_SCHEMA = "codestra.sales.lead-resolution.v1"
POLICY_VERSION = "codestra.sales.policy.v1"
MAX_EVIDENCE = 20
MAX_SNIPPET = 512
EXECUTABLE_SUFFIXES = frozenset(
    {
        ".apk",
        ".bat",
        ".bin",
        ".cmd",
        ".com",
        ".dll",
        ".dmg",
        ".exe",
        ".jar",
        ".msi",
        ".ps1",
        ".scr",
        ".sh",
    }
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must be ISO-8601 UTC")
    return value


def validate_public_url(value: str) -> str:
    if len(value) > 2048:
        raise ValueError("URL is too long")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials in URLs are forbidden")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise ValueError("private URL destinations are forbidden")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if "." not in host:
            raise ValueError("URL host must be a public fully-qualified name") from None
    else:
        if not address.is_global:
            raise ValueError("private or reserved URL destinations are forbidden")
    if PurePosixPath(parsed.path.lower()).suffix in EXECUTABLE_SUFFIXES:
        raise ValueError("executable-download URLs are forbidden")
    return value


class Source(StrictModel):
    provider: str = Field(pattern=r"^self_hosted_scraper$")
    job_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    collected_at: datetime

    _collected_utc = field_validator("collected_at")(_utc)


class Address(StrictModel):
    line1: str | None = Field(default=None, max_length=256)
    line2: str | None = Field(default=None, max_length=256)
    city: str | None = Field(default=None, max_length=128)
    region: str | None = Field(default=None, max_length=128)
    postal_code: str | None = Field(default=None, max_length=32)
    country_code: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")


class Company(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    legal_name: str | None = Field(default=None, max_length=256)
    domain: str | None = Field(default=None, max_length=253)
    website_url: str | None = None
    registration_number: str | None = Field(default=None, max_length=128)
    tax_identifier: str | None = Field(default=None, max_length=128)
    trading_name: str | None = Field(default=None, max_length=256)
    business_telephone: str | None = Field(default=None, max_length=64)
    country_code: str = Field(pattern=r"^[A-Z]{2}$")
    industry: str | None = Field(default=None, max_length=128)
    services: list[str] = Field(default_factory=list, max_length=32)
    address: Address = Field(default_factory=Address)

    @field_validator("website_url")
    @classmethod
    def public_website(cls, value: str | None) -> str | None:
        return validate_public_url(value) if value else value


class Contact(StrictModel):
    first_name: str | None = Field(default=None, max_length=128)
    last_name: str | None = Field(default=None, max_length=128)
    full_name: str | None = Field(default=None, max_length=256)
    title: str | None = Field(default=None, max_length=128)
    department: str | None = Field(default=None, max_length=128)
    business_email: str | None = Field(default=None, max_length=320)
    business_phone: str | None = Field(default=None, max_length=64)
    country_code: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    company_association: str | None = Field(default=None, max_length=256)
    public_profile_url: str | None = None

    @field_validator("business_email")
    @classmethod
    def email_shape(cls, value: str | None) -> str | None:
        if value and (value.count("@") != 1 or "." not in value.rsplit("@", 1)[1]):
            raise ValueError("business email is malformed")
        return value

    @field_validator("public_profile_url")
    @classmethod
    def public_profile(cls, value: str | None) -> str | None:
        return validate_public_url(value) if value else value


class ProvenanceClassification(StrEnum):
    VERIFIED_FACT = "VERIFIED_FACT"
    PUBLIC_OBSERVATION = "PUBLIC_OBSERVATION"
    SYSTEM_INFERENCE = "SYSTEM_INFERENCE"
    UNKNOWN = "UNKNOWN"


class Evidence(StrictModel):
    field: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.]*$")
    source_url: str
    page_title: str | None = Field(default=None, max_length=256)
    snippet: str = Field(min_length=1, max_length=MAX_SNIPPET)
    content_hash: str = Field(pattern=r"^(sha256:)?[0-9a-f]{64}$")
    observed_at: datetime
    classification: ProvenanceClassification = (
        ProvenanceClassification.PUBLIC_OBSERVATION
    )
    extraction_method: str = Field(default="structured", max_length=64)
    field_paths: list[str] = Field(default_factory=list, max_length=32)
    robots_policy_reference: str | None = Field(default=None, max_length=256)
    provider_verification_reference: str | None = Field(default=None, max_length=256)

    _public_url = field_validator("source_url")(validate_public_url)
    _observed_utc = field_validator("observed_at")(_utc)

    @field_validator("snippet")
    @classmethod
    def bounded_plain_text(cls, value: str) -> str:
        lowered = value.lower()
        if "<html" in lowered or "<script" in lowered or "<!doctype" in lowered:
            raise ValueError("raw HTML is forbidden")
        return value

    @model_validator(mode="after")
    def supported_fields(self) -> "Evidence":
        paths = self.field_paths or [self.field]
        allowed = ("company.", "contact.")
        if any(not value.startswith(allowed) for value in paths):
            raise ValueError("evidence references an unsupported material field")
        return self


class SourceClaims(StrictModel):
    consent_claimed: bool = False
    consent_source: str | None = Field(default=None, max_length=128)
    consent_timestamp: datetime | None = None

    @field_validator("consent_timestamp")
    @classmethod
    def timestamp_utc(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if value else None


MetadataValue = Annotated[str | int | float | bool | None, Field()]


class LeadCandidate(StrictModel):
    schema_version: str = Field(pattern=r"^codestra\.sales\.lead-candidate\.v1$")
    tenant_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    candidate_id: str | None = Field(default=None, max_length=128)
    scraper_job_id: str | None = Field(default=None, max_length=128)
    source_type: str = Field(default="public_web", pattern=r"^public_web$")
    source: Source
    company: Company
    contact: Contact = Field(default_factory=Contact)
    evidence: list[Evidence] = Field(default_factory=list, max_length=MAX_EVIDENCE)
    source_claims: SourceClaims = Field(default_factory=SourceClaims)
    provenance: list[ProvenanceClassification] = Field(
        default_factory=list, max_length=8
    )
    provider_results: dict[str, MetadataValue] = Field(
        default_factory=dict, max_length=16
    )
    extraction_timestamp: datetime | None = None
    content_hashes: list[str] = Field(default_factory=list, max_length=32)
    idempotency_metadata: dict[str, MetadataValue] = Field(
        default_factory=dict, max_length=8
    )
    metadata: dict[str, MetadataValue] = Field(default_factory=dict, max_length=32)

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(
        cls, value: dict[str, MetadataValue]
    ) -> dict[str, MetadataValue]:
        for key, item in value.items():
            if len(key) > 64 or (isinstance(item, str) and len(item) > 256):
                raise ValueError("metadata is outside bounded limits")
        return value

    _extraction_utc = field_validator("extraction_timestamp")(
        lambda value: _utc(value) if value else value
    )

    @field_validator("content_hashes")
    @classmethod
    def hashes_are_sha256(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"(sha256:)?[0-9a-f]{64}", value) for value in values):
            raise ValueError("content hash must be SHA-256")
        return values

    @model_validator(mode="after")
    def material_values_have_evidence(self) -> "LeadCandidate":
        material = {
            "company.name": self.company.name,
            "company.legal_name": self.company.legal_name,
            "company.trading_name": self.company.trading_name,
            "company.domain": self.company.domain,
            "company.website_url": self.company.website_url,
            "company.registration_number": self.company.registration_number,
            "company.tax_identifier": self.company.tax_identifier,
            "company.business_telephone": self.company.business_telephone,
            "company.industry": self.company.industry,
            "company.services": self.company.services,
            "company.address.line1": self.company.address.line1,
            "company.address.city": self.company.address.city,
            "company.address.region": self.company.address.region,
            "contact.full_name": self.contact.full_name,
            "contact.title": self.contact.title,
            "contact.business_email": self.contact.business_email,
            "contact.business_phone": self.contact.business_phone,
            "contact.company_association": self.contact.company_association,
            "contact.public_profile_url": self.contact.public_profile_url,
        }
        supported = {
            path
            for item in self.evidence
            for path in (item.field_paths or [item.field])
        }
        missing = sorted(
            path for path, value in material.items() if value and path not in supported
        )
        if missing:
            raise ValueError(f"material fields lack evidence: {', '.join(missing)}")
        return self


class Decision(StrEnum):
    ACCEPTED = "ACCEPTED"
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    POSSIBLE_DUPLICATE = "POSSIBLE_DUPLICATE"
    SUPPRESSED = "SUPPRESSED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    REJECTED = "REJECTED"


class GateState(StrEnum):
    NOT_CHECKED = "NOT_CHECKED"
    ELIGIBLE = "ELIGIBLE"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"


class MatchResolution(StrictModel):
    matched: bool
    odoo_company_id: str | None = None
    odoo_lead_id: str | None = None
    score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list, max_length=20)


class Gates(StrictModel):
    global_dnc: GateState
    campaign_dnc: GateState
    suppression: GateState
    consent: GateState
    channel_eligibility: GateState = GateState.NOT_CHECKED


class LeadResolution(StrictModel):
    schema_version: str = RESOLUTION_SCHEMA
    candidate_id: str
    decision: Decision
    decision_code: str = "VERIFICATION_COMPLETED"
    eligible_for_storage: bool = True
    eligible_for_outreach: bool = False
    duplicate_status: str = "NONE"
    match_type: str = "NONE"
    matched_entity_references: list[str] = Field(default_factory=list, max_length=8)
    match_confidence: int = Field(default=0, ge=0, le=100)
    company_resolution: MatchResolution
    contact_resolution: MatchResolution
    gates: Gates
    rejection_reasons: list[str] = Field(default_factory=list)
    manual_review_reasons: list[str] = Field(default_factory=list)
    suppression_results: list[str] = Field(default_factory=list)
    consent_results: list[str] = Field(default_factory=list)
    evidence_validation: str = "VALIDATED"
    provider_validation_summaries: dict[str, str] = Field(default_factory=dict)
    audit_reference: str | None = None
    idempotency_result: str = "CREATED"
    contract_version: str = RESOLUTION_SCHEMA
    review_required: bool
    dry_run: bool = True
    correlation_id: str
    policy_version: str = POLICY_VERSION

    @model_validator(mode="after")
    def phase_one_is_dry_run(self) -> "LeadResolution":
        if not self.dry_run:
            raise ValueError("Phase 1 results must be dry-run")
        return self


class VerificationFilters(StrictModel):
    verification_status: list[str] = Field(
        default_factory=lambda: ["UNVERIFIED", "STALE"], max_length=8
    )
    updated_before: datetime | None = None

    @field_validator("updated_before")
    @classmethod
    def before_utc(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if value else None


class VerificationJobRequest(StrictModel):
    source: str = Field(pattern=r"^odoo$")
    tenant_id: str = Field(min_length=1, max_length=128)
    campaign_id: str | None = Field(default=None, max_length=128)
    filters: VerificationFilters = Field(default_factory=VerificationFilters)
    dry_run: bool
    write_changes: bool
    publish_to_vicidial: bool
    batch_size: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def prohibit_writes(self) -> "VerificationJobRequest":
        if not self.dry_run or self.write_changes or self.publish_to_vicidial:
            raise ValueError("Phase 1 verification is dry-run and cannot publish")
        return self


class VerificationJobState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class SafeError(StrictModel):
    code: str
    message: str
    correlation_id: str
    retryable: bool = False
