from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol

import httpx
from app.adapters.odoo.client import OdooDeliveryClient, OdooDeliveryError

from .compliance import ComplianceSnapshot
from .contracts import LeadCandidate
from .identity import OdooCompany, OdooContact
from .normalization import (
    normalized_company_name,
    normalized_email,
    normalized_phone,
    registrable_domain,
)


class OdooReadUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class OdooLookup:
    companies: list[OdooCompany] = field(default_factory=list)
    contacts: list[OdooContact] = field(default_factory=list)
    compliance: ComplianceSnapshot | None = None


class OdooReadOnlyPort(Protocol):
    create_count: int
    update_count: int
    delete_count: int

    async def lookup(
        self, candidate: LeadCandidate, *, limit: int = 100
    ) -> OdooLookup: ...

    async def verification_page(
        self, tenant_id: str, campaign_id: str | None, *, offset: int, limit: int
    ) -> list[LeadCandidate]: ...


class DisabledOdooReadOnlyAdapter:
    create_count = 0
    update_count = 0
    delete_count = 0

    async def lookup(self, candidate: LeadCandidate, *, limit: int = 100) -> OdooLookup:
        raise OdooReadUnavailable("authoritative Odoo lookup is disabled")

    async def verification_page(
        self, tenant_id: str, campaign_id: str | None, *, offset: int, limit: int
    ) -> list[LeadCandidate]:
        raise OdooReadUnavailable("authoritative Odoo lookup is disabled")


class SyntheticCanaryOdooReadOnlyAdapter:
    """Empty staging registry with fail-closed consent for TEST_SYN canaries only."""

    create_count = 0
    update_count = 0
    delete_count = 0

    async def lookup(self, candidate: LeadCandidate, *, limit: int = 100) -> OdooLookup:
        if (
            candidate.campaign_id != "TEST_SYN"
            or candidate.metadata.get("synthetic_canary") is not True
        ):
            raise OdooReadUnavailable("synthetic staging lookup scope mismatch")
        consent = "GRANTED" if candidate.source_claims.consent_claimed else "UNKNOWN"
        return OdooLookup(
            compliance=ComplianceSnapshot(
                candidate.tenant_id,
                candidate.campaign_id,
                consent=consent,
                channel_eligible=consent == "GRANTED",
            )
        )

    async def verification_page(
        self, tenant_id: str, campaign_id: str | None, *, offset: int, limit: int
    ) -> list[LeadCandidate]:
        return []

class FakeOdooReadOnlyAdapter:
    """Bounded test double with explicit zero-mutation counters."""

    create_count = 0
    update_count = 0
    delete_count = 0

    def __init__(
        self, lookup: OdooLookup | None = None, pages: list[LeadCandidate] | None = None
    ) -> None:
        self.result = lookup or OdooLookup()
        self.pages = pages or []
        self.unavailable = False
        self.calls: list[tuple[str, str]] = []

    async def lookup(self, candidate: LeadCandidate, *, limit: int = 100) -> OdooLookup:
        if self.unavailable:
            raise OdooReadUnavailable("authoritative Odoo lookup is unavailable")
        if limit not in range(1, 101):
            raise ValueError("Odoo lookup limit is outside bounds")
        self.calls.append((candidate.tenant_id, candidate.campaign_id))
        companies = [
            value
            for value in self.result.companies
            if value.tenant_id == candidate.tenant_id
        ][:limit]
        contacts = [
            value
            for value in self.result.contacts
            if value.tenant_id == candidate.tenant_id
        ][:limit]
        compliance = self.result.compliance
        return OdooLookup(companies, contacts, compliance)

    async def verification_page(
        self, tenant_id: str, campaign_id: str | None, *, offset: int, limit: int
    ) -> list[LeadCandidate]:
        if self.unavailable:
            raise OdooReadUnavailable("authoritative Odoo lookup is unavailable")
        if limit not in range(1, 101) or offset < 0:
            raise ValueError("Odoo page is outside bounds")
        return [
            value
            for value in self.pages[offset : offset + limit]
            if value.tenant_id == tenant_id
            and (campaign_id is None or value.campaign_id == campaign_id)
        ]


class RegistryOdooReadOnlyAdapter:
    """Least-privilege registry client; only Odoo read operations are reachable."""

    create_count = 0
    update_count = 0
    delete_count = 0

    def __init__(self, client: OdooDeliveryClient) -> None:
        self.client = client

    @staticmethod
    def _traceparent(seed: str) -> str:
        digest = hashlib.sha256(seed.encode()).hexdigest()
        return f"00-{digest[:32]}-{digest[32:48]}-01"

    async def lookup(self, candidate: LeadCandidate, *, limit: int = 100) -> OdooLookup:
        if limit not in range(1, 101):
            raise ValueError("Odoo lookup limit is outside bounds")
        phone = normalized_phone(
            candidate.contact.business_phone, candidate.contact.country_code
        )
        payload = {
            "tenant_id": candidate.tenant_id,
            "campaign_id": candidate.campaign_id,
            "limit": limit,
            "company": {
                "normalized_name": normalized_company_name(candidate.company.name),
                "registration_number": candidate.company.registration_number,
                "country_code": candidate.company.country_code,
                "root_domain": registrable_domain(
                    candidate.company.domain or candidate.company.website_url
                ),
            },
            "contact": {
                "normalized_email": normalized_email(candidate.contact.business_email),
                "e164_phone": phone.e164 if phone else None,
            },
        }
        try:
            response = await self.client.request(
                "sales.lookup",
                payload,
                idempotency_key=f"read:{candidate.tenant_id}:{candidate.source.request_id}",
                request_id=candidate.source.request_id,
                correlation_id=candidate.source.request_id,
                causation_id=candidate.source.job_id,
                traceparent=self._traceparent(
                    f"{candidate.tenant_id}:{candidate.source.request_id}"
                ),
            )
            response.raise_for_status()
            document = response.json()
        except (
            OdooDeliveryError,
            httpx.HTTPError,
            RuntimeError,
            ValueError,
            TypeError,
        ) as exc:
            raise OdooReadUnavailable("authoritative Odoo lookup failed") from exc
        if document.get("tenant_id") != candidate.tenant_id:
            raise OdooReadUnavailable("authoritative Odoo scope mismatch")
        companies = [
            OdooCompany(**value) for value in document.get("companies", [])[:limit]
        ]
        contacts = [
            OdooContact(**value) for value in document.get("contacts", [])[:limit]
        ]
        compliance_value = document.get("compliance")
        compliance = (
            ComplianceSnapshot(**compliance_value) if compliance_value else None
        )
        return OdooLookup(companies, contacts, compliance)

    async def verification_page(
        self, tenant_id: str, campaign_id: str | None, *, offset: int, limit: int
    ) -> list[LeadCandidate]:
        if limit not in range(1, 101) or offset < 0:
            raise ValueError("Odoo page is outside bounds")
        try:
            response = await self.client.request(
                "sales.verification.read",
                {
                    "tenant_id": tenant_id,
                    "campaign_id": campaign_id,
                    "offset": offset,
                    "limit": limit,
                },
                idempotency_key=f"read:{tenant_id}:{campaign_id or 'all'}:{offset}:{limit}",
                request_id=f"verification:{offset}",
                correlation_id=f"verification:{tenant_id}:{offset}",
                causation_id="sales-verification-job",
                traceparent=self._traceparent(
                    f"{tenant_id}:{campaign_id or 'all'}:{offset}:{limit}"
                ),
            )
            response.raise_for_status()
            document = response.json()
        except (
            OdooDeliveryError,
            httpx.HTTPError,
            RuntimeError,
            ValueError,
            TypeError,
        ) as exc:
            raise OdooReadUnavailable(
                "authoritative Odoo verification read failed"
            ) from exc
        if document.get("tenant_id") != tenant_id:
            raise OdooReadUnavailable("authoritative Odoo scope mismatch")
        return [
            LeadCandidate.model_validate(value)
            for value in document.get("records", [])[:limit]
        ]
