from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AppointmentState(StrEnum):
    REQUESTED = "requested"
    MATCHING = "matching"
    CONFIRMED = "confirmed"
    RESCHEDULED = "rescheduled"
    CANCELLED = "cancelled"


class Service(BaseModel):
    code: str
    name: str
    category: str
    duration_minutes: int
    active: bool = True


class ContactRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    tenant_id: UUID
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    message: str = Field(min_length=5, max_length=4000)
    consent: bool


class ProviderInterest(ContactRequest):
    service_codes: list[str] = Field(min_length=1, max_length=20)
    service_area: str = Field(min_length=2, max_length=160)


class ServiceRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    tenant_id: UUID
    customer_id: UUID
    service_code: str = Field(pattern=r"^[A-Z0-9_-]{2,40}$")
    address: str = Field(min_length=5, max_length=300)
    country_code: str = Field(pattern=r"^[A-Z]{2}$")
    timezone: str = Field(min_length=3, max_length=64)
    requested_start: datetime
    notes: str = Field(default="", max_length=2000)
    consent: bool
    dnc: bool = False

    @field_validator("requested_start")
    @classmethod
    def must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("requested_start must include a timezone")
        return value


class AppointmentChange(BaseModel):
    tenant_id: UUID
    customer_id: UUID
    requested_start: datetime | None = None
    reason: str = Field(min_length=3, max_length=500)


class BookingRecord(BaseModel):
    id: UUID
    tenant_id: UUID
    customer_id: UUID
    service_code: str
    state: AppointmentState
    requested_start: datetime
    provider_match_id: UUID | None = None
    idempotency_key: str
    created_at: datetime
    updated_at: datetime
