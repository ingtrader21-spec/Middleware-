from __future__ import annotations

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .service import PayloadTooLargeError, ReplayConflictError
from .storage import ReplayConflict
from .survey_intake import (
    INTAKE_PRODUCER_CLIENT_ID,
    SurveyResponseSubmission,
    accept_survey_response,
)


async def _read_limited_body(request: Request, maximum: int) -> bytes:
    raw_length = request.headers.get("Content-Length")
    if raw_length is not None:
        try:
            length = int(raw_length)
        except ValueError as exc:
            from .security import RequestValidationError

            raise RequestValidationError("Content-Length must be an integer") from exc
        if length < 0:
            from .security import RequestValidationError

            raise RequestValidationError("Content-Length must not be negative")
        if length > maximum:
            raise PayloadTooLargeError(f"request body exceeds {maximum} bytes")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise PayloadTooLargeError(f"request body exceeds {maximum} bytes")
        body.extend(chunk)
    return bytes(body)


def register_survey_routes(app: FastAPI | APIRouter) -> None:
    @app.post("/v1/intake/surveys/responses")
    async def submit_survey_response(request: Request) -> JSONResponse:
        from .security import RequestValidationError, authorize_tenant

        active = request.app.state.runtime
        content_type = request.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise RequestValidationError("Content-Type must be application/json")

        tenant_id = request.headers.get("X-Tenant-ID", "")
        correlation_id = request.headers.get("X-Correlation-ID", "")
        idempotency_key = request.headers.get("Idempotency-Key", "")
        if not tenant_id:
            raise RequestValidationError("X-Tenant-ID is required")
        if not correlation_id or len(correlation_id) > 180:
            raise RequestValidationError("X-Correlation-ID must contain 1 to 180 characters")
        if not idempotency_key or not 8 <= len(idempotency_key) <= 180:
            raise RequestValidationError("Idempotency-Key must contain 8 to 180 characters")

        claims = await active.tokens.verify(
            request.headers.get("Authorization", ""),
            expected_client_id=INTAKE_PRODUCER_CLIENT_ID,
            required_scope="surveys.write",
        )
        authorize_tenant(claims, tenant_id)

        raw = await _read_limited_body(request, active.settings.max_request_body_bytes)
        try:
            submission = SurveyResponseSubmission.model_validate_json(raw)
        except (ValidationError, ValueError) as exc:
            raise RequestValidationError(
                "body does not match the canonical survey response contract"
            ) from exc
        request.state.intake_metrics = {
            "channel": submission.source,
            "survey_kind": submission.surveyCategory,
            "anonymous": "true" if submission.anonymous else "false",
        }
        if submission.tenantId != tenant_id:
            raise RequestValidationError("X-Tenant-ID does not match submission tenantId")

        try:
            result = await accept_survey_response(
                active,
                submission,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
            )
        except ReplayConflict as exc:
            raise ReplayConflictError(str(exc)) from exc

        return JSONResponse(
            status_code=200 if result.duplicate else 202,
            content=result.model_dump(mode="json"),
            headers={"X-Correlation-ID": result.correlation_id},
        )
