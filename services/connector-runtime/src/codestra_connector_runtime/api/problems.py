"""RFC 9457 Problem Details errors and FastAPI handlers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


@dataclass(slots=True)
class ProblemError(Exception):
    status: int
    code: str
    title: str
    detail: str
    type_uri: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    extensions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Exception.__init__(self, self.detail)


def _correlation_id(request: Request) -> str:
    return str(getattr(request.state, "correlation_id", "unknown"))


def problem_response(request: Request, error: ProblemError) -> JSONResponse:
    payload: dict[str, Any] = {
        "type": error.type_uri or f"https://errors.codestra.co/{error.code.lower()}",
        "title": error.title,
        "status": error.status,
        "detail": error.detail,
        "instance": str(request.url.path),
        "code": error.code,
        "correlation_id": _correlation_id(request),
    }
    payload.update(error.extensions)
    headers = {
        "Cache-Control": "no-store",
        "X-Correlation-ID": _correlation_id(request),
        **error.headers,
    }
    return JSONResponse(
        status_code=error.status,
        content=payload,
        media_type="application/problem+json",
        headers=headers,
    )


def install_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def handle_problem(request: Request, error: ProblemError) -> JSONResponse:
        return problem_response(request, error)

    @app.exception_handler(RequestValidationError)
    async def handle_validation(
        request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        return problem_response(
            request,
            ProblemError(
                status=422,
                code="VALIDATION_ERROR",
                title="Request validation failed",
                detail="One or more request fields are invalid.",
                extensions={"errors": error.errors()},
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http(
        request: Request,
        error: StarletteHTTPException,
    ) -> JSONResponse:
        return problem_response(
            request,
            ProblemError(
                status=error.status_code,
                code=f"HTTP_{error.status_code}",
                title="HTTP request failed",
                detail=str(error.detail),
                headers=dict(error.headers or {}),
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, error: Exception) -> JSONResponse:
        # The exception is intentionally not exposed in the response. Runtime
        # logging records the correlation ID and safe exception class only.
        request.app.state.logger.exception(
            "unhandled_connector_runtime_error",
            error_type=type(error).__name__,
            correlation_id=_correlation_id(request),
        )
        return problem_response(
            request,
            ProblemError(
                status=500,
                code="INTERNAL_ERROR",
                title="Internal server error",
                detail="The request could not be completed.",
            ),
        )
