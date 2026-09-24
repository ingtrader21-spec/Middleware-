from uuid import UUID

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from app.booking.contracts import AppointmentChange, AppointmentState, ContactRequest, ProviderInterest, ServiceRequest
from app.booking.service import CATALOG, BookingError, BookingRepository

router = APIRouter(prefix="/api/v1/booking", tags=["booked4seasons-staging"])
repository = BookingRepository()


def error(exc: BookingError):
    return JSONResponse({"code": exc.code, "detail": "booking request rejected"}, status_code=exc.status)


@router.get("/services")
async def services():
    return {"services": [item.model_dump() for item in CATALOG], "environment": "staging", "external_delivery": False}


@router.post("/requests", status_code=201)
async def request_service(body: ServiceRequest, idempotency_key: str = Header("", alias="Idempotency-Key")):
    try:
        row, replay = repository.create(body, idempotency_key)
    except BookingError as exc:
        return error(exc)
    return JSONResponse(row.model_dump(mode="json"), status_code=200 if replay else 201, headers={"X-Idempotent-Replay": str(replay).lower()})


@router.post("/contact", status_code=202)
async def contact(body: ContactRequest):
    if not body.consent:
        return JSONResponse({"code": "CONSENT_REQUIRED"}, status_code=409)
    return {"accepted": True, "external_delivery": False}


@router.post("/providers/interest", status_code=202)
async def provider_interest(body: ProviderInterest):
    if not body.consent:
        return JSONResponse({"code": "CONSENT_REQUIRED"}, status_code=409)
    unknown = sorted(set(body.service_codes) - {item.code for item in CATALOG})
    if unknown:
        return JSONResponse({"code": "UNKNOWN_SERVICE"}, status_code=422)
    return {"accepted": True, "provider_status": "pending_review", "external_delivery": False}


@router.get("/appointments/{appointment_id}")
async def appointment(appointment_id: UUID, tenant_id: UUID, customer_id: UUID):
    try:
        return repository.get_for_customer(appointment_id, tenant_id, customer_id)
    except BookingError as exc:
        return error(exc)


@router.post("/appointments/{appointment_id}/reschedule")
async def reschedule(appointment_id: UUID, body: AppointmentChange):
    if body.requested_start is None:
        return JSONResponse({"code": "REQUESTED_START_REQUIRED"}, status_code=422)
    try:
        return repository.transition(appointment_id, body.tenant_id, body.customer_id, AppointmentState.RESCHEDULED, body.requested_start)
    except BookingError as exc:
        return error(exc)


@router.post("/appointments/{appointment_id}/cancel")
async def cancel(appointment_id: UUID, body: AppointmentChange):
    try:
        return repository.transition(appointment_id, body.tenant_id, body.customer_id, AppointmentState.CANCELLED)
    except BookingError as exc:
        return error(exc)
