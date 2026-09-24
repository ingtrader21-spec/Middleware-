from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .contracts import LeadCandidate
from .normalization import (
    normalized_address_component,
    normalized_company_name,
    normalized_email,
    normalized_person_name,
    normalized_phone,
    registrable_domain,
    role_email,
)


@dataclass(frozen=True)
class OdooCompany:
    public_id: str
    tenant_id: str
    name: str
    legal_name: str | None = None
    registration_number: str | None = None
    country_code: str = ""
    domain: str | None = None
    city: str | None = None
    region: str | None = None
    address_line1: str | None = None


@dataclass(frozen=True)
class OdooContact:
    public_id: str
    tenant_id: str
    company_public_id: str
    full_name: str
    business_email: str | None = None
    business_phone: str | None = None
    country_code: str | None = None
    title: str | None = None
    is_lead: bool = True


@dataclass(frozen=True)
class Match:
    score: int = 0
    public_id: str | None = None
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class MatchPolicy:
    exact_threshold: int = 90
    review_threshold: int = 70
    version: str = "codestra.sales.identity.v1"


def company_match(candidate: LeadCandidate, company: OdooCompany) -> Match:
    if candidate.tenant_id != company.tenant_id:
        return Match(reasons=("CROSS_TENANT_DENIED",))
    incoming = candidate.company
    if (
        incoming.registration_number
        and company.registration_number
        and incoming.country_code == company.country_code
        and incoming.registration_number.casefold()
        == company.registration_number.casefold()
    ):
        return Match(100, company.public_id, ("REGISTRATION_JURISDICTION_EXACT",))
    incoming_domain = registrable_domain(incoming.domain or incoming.website_url)
    existing_domain = registrable_domain(company.domain)
    if incoming_domain and existing_domain and incoming_domain == existing_domain:
        return Match(95, company.public_id, ("ROOT_DOMAIN_EXACT",))
    incoming_name = normalized_company_name(incoming.legal_name or incoming.name)
    existing_name = normalized_company_name(company.legal_name or company.name)
    incoming_address = normalized_address_component(incoming.address.line1)
    existing_address = normalized_address_component(company.address_line1)
    address_exact = bool(
        incoming_address and existing_address and incoming_address == existing_address
    )
    if (
        incoming_name == existing_name
        and address_exact
        and incoming.country_code == company.country_code
    ):
        return Match(90, company.public_id, ("LEGAL_NAME_ADDRESS_EXACT",))
    similarity = int(SequenceMatcher(None, incoming_name, existing_name).ratio() * 100)
    location_matches = sum(
        [
            incoming.country_code == company.country_code,
            bool(
                incoming.address.city
                and normalized_address_component(incoming.address.city)
                == normalized_address_component(company.city)
            ),
            bool(
                incoming.address.region
                and normalized_address_component(incoming.address.region)
                == normalized_address_component(company.region)
            ),
        ]
    )
    if similarity >= 88 and location_matches >= 2:
        return Match(
            min(89, 75 + location_matches * 4),
            company.public_id,
            ("COMPANY_NAME_LOCATION_STRONG",),
        )
    if similarity >= 75:
        return Match(
            min(79, similarity), company.public_id, ("COMPANY_NAME_FUZZY_REVIEW",)
        )
    return Match()


def contact_match(
    candidate: LeadCandidate, contact: OdooContact, company: Match
) -> Match:
    if candidate.tenant_id != contact.tenant_id:
        return Match(reasons=("CROSS_TENANT_DENIED",))
    incoming = candidate.contact
    if incoming.business_email and contact.business_email:
        if normalized_email(incoming.business_email) == normalized_email(
            contact.business_email
        ):
            if role_email(incoming.business_email):
                return Match(75, contact.public_id, ("ROLE_EMAIL_REVIEW_ONLY",))
            return Match(100, contact.public_id, ("BUSINESS_EMAIL_EXACT",))
    incoming_phone = (
        normalized_phone(incoming.business_phone, incoming.country_code)
        if incoming.business_phone
        else None
    )
    existing_phone = (
        normalized_phone(contact.business_phone, contact.country_code)
        if contact.business_phone
        else None
    )
    if incoming_phone and existing_phone and incoming_phone.e164 == existing_phone.e164:
        if company.score >= 90:
            return Match(95, contact.public_id, ("E164_PHONE_COMPANY_CONFIRMED",))
        return Match(75, contact.public_id, ("SHARED_PHONE_REVIEW_ONLY",))
    incoming_name = normalized_person_name(
        incoming.full_name
        or " ".join(filter(None, [incoming.first_name, incoming.last_name]))
    )
    existing_name = normalized_person_name(contact.full_name)
    similarity = (
        int(SequenceMatcher(None, incoming_name, existing_name).ratio() * 100)
        if incoming_name
        else 0
    )
    title_compatible = bool(
        incoming.title
        and contact.title
        and normalized_person_name(incoming.title)
        == normalized_person_name(contact.title)
    )
    if similarity == 100 and company.score >= 90 and title_compatible:
        return Match(85, contact.public_id, ("NAME_COMPANY_TITLE_EXACT",))
    if similarity >= 75:
        return Match(
            min(79, similarity), contact.public_id, ("PERSON_NAME_FUZZY_REVIEW",)
        )
    return Match()


def best_company(candidate: LeadCandidate, values: list[OdooCompany]) -> Match:
    return max(
        (company_match(candidate, value) for value in values),
        key=lambda value: value.score,
        default=Match(),
    )


def best_contact(
    candidate: LeadCandidate, values: list[OdooContact], company: Match
) -> Match:
    return max(
        (contact_match(candidate, value, company) for value in values),
        key=lambda value: value.score,
        default=Match(),
    )
