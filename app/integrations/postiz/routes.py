from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from app.core.config import settings
from .client import PostizClient
from .exceptions import PostizError
from .schemas import PostizCancelRequest, PostizErrorResult, PostizMediaUploadRequest, PostizPostRequest, PostizResult

router = APIRouter(prefix="/api/v1/integrations/postiz", tags=["postiz"])


def _error(exc: PostizError) -> HTTPException:
    return HTTPException(503 if exc.retryable else 502, {"error_code": exc.code, "retryable": exc.retryable, "message": exc.message})


@router.get("/health")
async def health() -> dict[str, object]:
    return {"configured": bool(settings.postiz_internal_base_url), "authenticated": bool(settings.postiz_api_key), "delivery_enabled": settings.postiz_delivery_enabled}


@router.get("/readiness")
async def readiness() -> dict[str, object]:
    ready = bool(settings.postiz_internal_base_url and settings.postiz_api_key)
    return {"status": "ready" if ready else "not-ready", "provider": "postiz", "delivery_enabled": settings.postiz_delivery_enabled}


@router.post("/results", status_code=202)
async def result_callback(body: PostizResult) -> dict[str, object]:
    return {"accepted": True, "command_id": body.command_id, "status": body.status, "trace_id": body.trace_id}


@router.post("/errors", status_code=202)
async def error_callback(body: PostizErrorResult) -> dict[str, object]:
    return {"accepted": True, "command_id": body.command_id, "status": body.status, "retryable": body.retryable, "trace_id": body.trace_id}


@router.get("/channels")
async def channels() -> object:
    try:
        return await PostizClient().channels(str(datetime.now(timezone.utc)))
    except PostizError as exc:
        raise _error(exc) from exc


@router.post("/posts")
async def create_post(body: PostizPostRequest) -> dict[str, object]:
    if not settings.postiz_delivery_enabled:
        raise HTTPException(503, "Postiz delivery is disabled")
    if body.publish and not settings.postiz_publish_enabled:
        raise HTTPException(403, "Postiz publication is disabled")
    try:
        result = await PostizClient().create_post(body.model_dump(mode="json"), body.correlation_id)
        return {"command_id": body.command_id, "status": "SCHEDULED" if body.scheduled_at else "DRAFT_CREATED", "provider": result}
    except PostizError as exc:
        raise _error(exc) from exc


@router.post("/media")
async def upload_media(body: PostizMediaUploadRequest) -> dict[str, object]:
    if not settings.postiz_media_upload_enabled:
        raise HTTPException(503, "Postiz media upload is disabled")
    if not body.source_url:
        raise HTTPException(422, "source_url is required for the URL-based adapter")
    try:
        result = await PostizClient().upload_from_url(body.source_url, body.correlation_id)
        return {"command_id": body.command_id, "result": result}
    except PostizError as exc:
        raise _error(exc) from exc


@router.get("/posts")
async def list_posts(start_date: str, end_date: str, correlation_id: str) -> object:
    try:
        return await PostizClient().list_posts(start_date=start_date, end_date=end_date, correlation_id=correlation_id)
    except PostizError as exc:
        raise _error(exc) from exc


@router.post("/posts/{post_id}/cancel")
async def cancel_post(post_id: str, body: PostizCancelRequest) -> object:
    if not settings.postiz_delivery_enabled:
        raise HTTPException(503, "Postiz delivery is disabled")
    try:
        return await PostizClient().cancel_post(post_id, body.correlation_id)
    except PostizError as exc:
        raise _error(exc) from exc


@router.get("/analytics/platform")
async def analytics(
    integration_id: str = Query(min_length=1),
    date: str = Query(min_length=1),
    correlation_id: str = Query(min_length=1),
) -> object:
    if not settings.postiz_analytics_enabled:
        raise HTTPException(503, "Postiz analytics is disabled")
    try:
        return await PostizClient().analytics(integration_id, date, correlation_id)
    except PostizError as exc:
        raise _error(exc) from exc
