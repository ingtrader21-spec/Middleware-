from typing import Any

from fastapi import APIRouter, Header, HTTPException

from app.ai_tasks import AiError, AiProgress, AiReconciliation, AiResult, AiTask, AI_STORE, TaskStatus
from app.order_orchestration import verify_body_integrity

router = APIRouter(prefix="/api/v1/ai", tags=["ai-tasks"])


def _integrity(body: Any, timestamp: str | None, nonce: str | None,
               signature: str | None, body_hash: str | None) -> None:
    verify_body_integrity(body, timestamp, nonce, signature, body_hash)


@router.post("/tasks", status_code=202)
async def create_task(task: AiTask, x_timestamp: str | None = Header(default=None),
                      x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None),
                      x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(task, x_timestamp, x_nonce, x_signature, x_body_sha256)
    return AI_STORE.create(task)


@router.get("/tasks/{task_id}")
async def get_task(task_id: str) -> dict[str, Any]:
    return AI_STORE.get(task_id)


@router.post("/tasks/{task_id}/start", status_code=202)
async def start_task(task_id: str, x_timestamp: str | None = Header(default=None),
                     x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None),
                     x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity({}, x_timestamp, x_nonce, x_signature, x_body_sha256)
    return AI_STORE.transition(task_id, TaskStatus.RUNNING)


@router.post("/tasks/{task_id}/progress", status_code=202)
async def progress_task(task_id: str, progress: AiProgress, x_timestamp: str | None = Header(default=None),
                        x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None),
                        x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(progress, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if progress.task_id != task_id:
        raise HTTPException(409, "task reference mismatch")
    return AI_STORE.transition(task_id, TaskStatus(progress.status), progress_percent=progress.percent)


@router.post("/tasks/{task_id}/result", status_code=202)
async def result_task(task_id: str, result: AiResult, x_timestamp: str | None = Header(default=None),
                     x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None),
                     x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(result, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if result.task_id != task_id:
        raise HTTPException(409, "task reference mismatch")
    return AI_STORE.transition(task_id, TaskStatus(result.status), output=result.output, model=result.model)


@router.post("/tasks/{task_id}/error", status_code=202)
async def error_task(task_id: str, error: AiError, x_timestamp: str | None = Header(default=None),
                    x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None),
                    x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(error, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if error.task_id != task_id:
        raise HTTPException(409, "task reference mismatch")
    status = TaskStatus.FAILED_RETRYABLE if error.retryable else TaskStatus.FAILED_FINAL
    return AI_STORE.transition(task_id, status, error_code=error.error_code, error_message=error.message)


@router.post("/tasks/{task_id}/cancel", status_code=202)
async def cancel_task(task_id: str, x_timestamp: str | None = Header(default=None),
                      x_nonce: str | None = Header(default=None), x_signature: str | None = Header(default=None),
                      x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity({}, x_timestamp, x_nonce, x_signature, x_body_sha256)
    return AI_STORE.transition(task_id, TaskStatus.CANCELLED)


@router.post("/tasks/{task_id}/reconcile", status_code=202)
async def reconcile_task(task_id: str, reconciliation: AiReconciliation,
                         x_timestamp: str | None = Header(default=None), x_nonce: str | None = Header(default=None),
                         x_signature: str | None = Header(default=None), x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(reconciliation, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if reconciliation.task_id != task_id:
        raise HTTPException(409, "task reference mismatch")
    return AI_STORE.transition(task_id, TaskStatus.RECONCILED, observed_status=reconciliation.observed_status)
