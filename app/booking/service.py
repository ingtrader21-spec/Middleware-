from datetime import UTC, datetime
from threading import RLock
from uuid import UUID, uuid4

from app.booking.contracts import AppointmentState, BookingRecord, Service, ServiceRequest


CATALOG = (
    Service(code="HOME_CLEANING", name="Home Cleaning", category="home", duration_minutes=120),
    Service(code="SEASONAL_MAINTENANCE", name="Seasonal Maintenance", category="property", duration_minutes=180),
    Service(code="HANDYMAN", name="Handyman Service", category="property", duration_minutes=120),
    Service(code="LAWN_CARE", name="Lawn Care", category="outdoor", duration_minutes=90),
)


class BookingError(ValueError):
    def __init__(self, code: str, status: int):
        self.code, self.status = code, status
        super().__init__(code)


class BookingRepository:
    """Staging repository. Production adapter must use the durable DB/outbox."""

    def __init__(self):
        self._lock = RLock()
        self._records: dict[UUID, BookingRecord] = {}
        self._keys: dict[tuple[UUID, str], UUID] = {}

    def create(self, request: ServiceRequest, key: str) -> tuple[BookingRecord, bool]:
        if not key or len(key) > 128:
            raise BookingError("INVALID_IDEMPOTENCY_KEY", 422)
        if not request.consent or request.dnc:
            raise BookingError("CONSENT_OR_DNC_BLOCKED", 409)
        if request.service_code not in {item.code for item in CATALOG}:
            raise BookingError("UNKNOWN_SERVICE", 422)
        binding = (request.tenant_id, key)
        with self._lock:
            if binding in self._keys:
                return self._records[self._keys[binding]], True
            duplicate = next((row for row in self._records.values() if row.tenant_id == request.tenant_id and row.customer_id == request.customer_id and row.service_code == request.service_code and row.state != AppointmentState.CANCELLED), None)
            if duplicate:
                raise BookingError("DUPLICATE_SERVICE_REQUEST", 409)
            now = datetime.now(UTC)
            row = BookingRecord(id=uuid4(), tenant_id=request.tenant_id, customer_id=request.customer_id, service_code=request.service_code, state=AppointmentState.REQUESTED, requested_start=request.requested_start, idempotency_key=key, created_at=now, updated_at=now)
            self._records[row.id] = row
            self._keys[binding] = row.id
            return row, False

    def get_for_customer(self, record_id: UUID, tenant_id: UUID, customer_id: UUID) -> BookingRecord:
        row = self._records.get(record_id)
        if not row or row.tenant_id != tenant_id or row.customer_id != customer_id:
            raise BookingError("BOOKING_NOT_FOUND", 404)
        return row

    def transition(self, record_id: UUID, tenant_id: UUID, customer_id: UUID, state: AppointmentState, requested_start=None) -> BookingRecord:
        with self._lock:
            row = self.get_for_customer(record_id, tenant_id, customer_id)
            if row.state == AppointmentState.CANCELLED:
                raise BookingError("BOOKING_ALREADY_CANCELLED", 409)
            values = {"state": state, "updated_at": datetime.now(UTC)}
            if requested_start is not None:
                if requested_start.tzinfo is None:
                    raise BookingError("TIMEZONE_REQUIRED", 422)
                values["requested_start"] = requested_start
            updated = row.model_copy(update=values)
            self._records[record_id] = updated
            return updated
