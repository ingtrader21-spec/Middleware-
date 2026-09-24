from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class ProviderState(StrEnum):
    DISABLED = "DISABLED"
    AVAILABLE = "AVAILABLE"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    state: ProviderState
    operation: str
    evidence: tuple[str, ...] = ()
    confidence: int | None = None
    normalized: dict[str, Any] | None = None
    authoritative: bool = False


class ProviderPort(Protocol):
    name: str
    enabled: bool

    async def execute(
        self, operation: str, payload: dict[str, Any]
    ) -> ProviderResult: ...


class DisabledProvider:
    def __init__(self, name: str) -> None:
        self.name = name
        self.enabled = False
        self.attempt_count = 0

    async def execute(self, operation: str, payload: dict[str, Any]) -> ProviderResult:
        self.attempt_count += 1
        return ProviderResult(self.name, ProviderState.DISABLED, operation)


class FakeProvider(DisabledProvider):
    def __init__(
        self, name: str, responses: dict[str, ProviderResult] | None = None
    ) -> None:
        super().__init__(name)
        self.enabled = True
        self.responses = responses or {}

    async def execute(self, operation: str, payload: dict[str, Any]) -> ProviderResult:
        self.attempt_count += 1
        return self.responses.get(
            operation,
            ProviderResult(self.name, ProviderState.DEPENDENCY_UNAVAILABLE, operation),
        )


PROVIDER_OPERATIONS = {
    "hunter": frozenset(
        {"domain_email_discovery", "email_finder", "email_verification"}
    ),
    "apollo": frozenset(
        {
            "organization_search",
            "person_search",
            "organization_enrichment",
            "person_enrichment",
            "phone_result",
        }
    ),
    "twilio_lookup": frozenset({"phone_lookup"}),
    "opencorporates": frozenset({"company_search"}),
    "openai": frozenset(
        {
            "industry_classification",
            "service_classification",
            "public_evidence_summary",
            "lead_fit_explanation",
        }
    ),
}
