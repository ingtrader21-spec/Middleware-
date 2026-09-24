from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Response, status
from pydantic import Field

from app.order_orchestration import (
    STORE,
    ApprovalRequest,
    DeadLetterEnvelope,
    ErrorEnvelope,
    OrderEnvelope,
    OrderStatus,
    ResultEnvelope,
    content_hash,
    validate_for_dispatch,
    verify_body_integrity,
)

router = APIRouter(prefix="/api/v1", tags=["approved-order-orchestration"])


class CommandRequest(OrderEnvelope):
    pass


class ProgressRequest(OrderEnvelope):
    progress_percent: int = Field(ge=0, le=100)
    message: str = Field(max_length=256)


class ReconciliationRequest(OrderEnvelope):
    n8n_execution_id: str = Field(min_length=1, max_length=128)


class ProgressEnvelope(OrderEnvelope):
    progress_percent: int = Field(ge=0, le=100)
    message: str = Field(max_length=256)


def _integrity(body: Any, timestamp: str | None, nonce: str | None,
               signature: str | None, body_hash: str | None) -> None:
    verify_body_integrity(body, timestamp, nonce, signature, body_hash)


@router.post("/orders", status_code=status.HTTP_202_ACCEPTED)
async def receive_order(order: OrderEnvelope, response: Response,
                        x_timestamp: str | None = Header(default=None),
                        x_nonce: str | None = Header(default=None),
                        x_signature: str | None = Header(default=None),
                        x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(order, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.create(order)
    response.headers["X-Order-Status"] = record["status"]
    return record


@router.get("/orders/{order_id}")
async def get_order(order_id: str) -> dict[str, Any]:
    return STORE.get(order_id)


@router.post("/orders/{order_id}/approve", status_code=status.HTTP_202_ACCEPTED)
async def approve_order(order_id: str, approval: ApprovalRequest,
                        x_timestamp: str | None = Header(default=None),
                        x_nonce: str | None = Header(default=None),
                        x_signature: str | None = Header(default=None),
                        x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(approval, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(order_id)
    if approval.content_hash != record["content_hash"]:
        raise HTTPException(409, "approval content hash does not match order")
    if approval.approved_by == record["envelope"]["source_system"]:
        raise HTTPException(403, "self approval is not permitted")
    record["envelope"]["approval"].update(
        {"status": "approved", "approved_by": approval.approved_by,
         "approved_at": datetime.now(UTC).isoformat()}
    )
    record["status"] = OrderStatus.APPROVED.value
    return record


@router.post("/orders/{order_id}/reject", status_code=status.HTTP_202_ACCEPTED)
async def reject_order(order_id: str,
                       x_timestamp: str | None = Header(default=None),
                       x_nonce: str | None = Header(default=None),
                       x_signature: str | None = Header(default=None),
                       x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity({}, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(order_id)
    record["status"] = OrderStatus.REJECTED.value
    return record


@router.post("/orchestration/n8n/dispatch", status_code=status.HTTP_202_ACCEPTED)
async def dispatch_order(order: OrderEnvelope,
                         x_timestamp: str | None = Header(default=None),
                         x_nonce: str | None = Header(default=None),
                         x_signature: str | None = Header(default=None),
                         x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(order, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(order.order_id)
    validate_for_dispatch(order)
    if record["content_hash"] != content_hash(order):
        raise HTTPException(409, "order content changed after intake")
    record["status"] = OrderStatus.DISPATCHED_TO_N8N.value
    record["n8n_dispatch"] = {"workflow_code": order.workflow_code, "accepted_at": datetime.now(UTC).isoformat()}
    STORE.command(order.command_id, order.order_id)["status"] = OrderStatus.DISPATCHED_TO_N8N.value
    return {"accepted": True, "status": record["status"], "command_id": order.command_id, "trace_id": order.trace_id}


@router.post("/orchestration/n8n/results", status_code=status.HTTP_202_ACCEPTED)
async def receive_result(result: ResultEnvelope,
                         x_timestamp: str | None = Header(default=None),
                         x_nonce: str | None = Header(default=None),
                         x_signature: str | None = Header(default=None),
                         x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(result, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(result.order_id)
    if record["command_id"] != result.command_id or record["trace_id"] != result.trace_id:
        raise HTTPException(409, "command or trace reference mismatch")
    STORE.record_result(result.command_id, result.status)
    record["result"] = result.model_dump(mode="json")
    return {"accepted": True, "status": record["status"], "order_id": result.order_id}


@router.post("/orchestration/n8n/errors", status_code=status.HTTP_202_ACCEPTED)
async def receive_error(error: ErrorEnvelope,
                        x_timestamp: str | None = Header(default=None),
                        x_nonce: str | None = Header(default=None),
                        x_signature: str | None = Header(default=None),
                        x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(error, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(error.order_id)
    if record["command_id"] != error.command_id or record["trace_id"] != error.trace_id:
        raise HTTPException(409, "command or trace reference mismatch")
    STORE.record_failure(error.command_id, error.error_code, error.retryable)
    record["error_code"] = error.error_code
    return {"accepted": True, "status": record["status"], "order_id": error.order_id}


@router.post("/orchestration/n8n/progress", status_code=status.HTTP_202_ACCEPTED)
async def receive_progress(progress: ProgressEnvelope,
                           x_timestamp: str | None = Header(default=None),
                           x_nonce: str | None = Header(default=None),
                           x_signature: str | None = Header(default=None),
                           x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(progress, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(progress.order_id)
    command = STORE.commands.get(progress.command_id)
    if not command or record["command_id"] != progress.command_id:
        raise HTTPException(409, "command or trace reference mismatch")
    command["progress"].append({"percent": progress.progress_percent, "message": progress.message})
    record["status"] = OrderStatus.RUNNING.value
    STORE._count("order_progress_total")
    STORE._audit(progress.order_id, "command_progress", command_id=progress.command_id,
                 percent=progress.progress_percent)
    return {"accepted": True, "status": record["status"], "order_id": progress.order_id}


@router.post("/orchestration/n8n/dead-letter", status_code=status.HTTP_202_ACCEPTED)
async def receive_dead_letter(dead_letter: DeadLetterEnvelope,
                              x_timestamp: str | None = Header(default=None),
                              x_nonce: str | None = Header(default=None),
                              x_signature: str | None = Header(default=None),
                              x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(dead_letter, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(dead_letter.order_id)
    if record["command_id"] != dead_letter.command_id or record["trace_id"] != dead_letter.trace_id:
        raise HTTPException(409, "command or trace reference mismatch")
    record["status"] = OrderStatus.DEAD_LETTER.value
    record["dead_letter"] = dead_letter.model_dump(mode="json")
    STORE._count("orders_dead_lettered_total")
    STORE._audit(dead_letter.order_id, "command_dead_letter", command_id=dead_letter.command_id)
    return {"accepted": True, "status": record["status"], "order_id": dead_letter.order_id}


@router.post("/orchestration/n8n/reconciliation", status_code=status.HTTP_202_ACCEPTED)
async def reconcile_order(order: OrderEnvelope,
                          x_timestamp: str | None = Header(default=None),
                          x_nonce: str | None = Header(default=None),
                          x_signature: str | None = Header(default=None),
                          x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(order, x_timestamp, x_nonce, x_signature, x_body_sha256)
    record = STORE.get(order.order_id)
    return {"accepted": True, "order_id": order.order_id, "canonical_status": record["status"]}


@router.post("/orchestration/commands", status_code=status.HTTP_202_ACCEPTED)
async def create_command(order: OrderEnvelope,
                         x_timestamp: str | None = Header(default=None),
                         x_nonce: str | None = Header(default=None),
                         x_signature: str | None = Header(default=None),
                         x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(order, x_timestamp, x_nonce, x_signature, x_body_sha256)
    return STORE.command(order.command_id, order.order_id)


@router.get("/orchestration/commands/{command_id}")
async def get_command(command_id: str) -> dict[str, Any]:
    if command_id not in STORE.commands:
        raise HTTPException(404, "command not found")
    return STORE.commands[command_id]


@router.post("/orchestration/commands/{command_id}/start", status_code=status.HTTP_202_ACCEPTED)
async def start_command(command_id: str,
                        x_timestamp: str | None = Header(default=None),
                        x_nonce: str | None = Header(default=None),
                        x_signature: str | None = Header(default=None),
                        x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity({}, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if command_id not in STORE.commands:
        raise HTTPException(404, "command not found")
    STORE.commands[command_id]["status"] = OrderStatus.RUNNING.value
    STORE.get(STORE.commands[command_id]["order_id"])["status"] = OrderStatus.RUNNING.value
    return STORE.commands[command_id]


@router.post("/orchestration/commands/{command_id}/progress", status_code=status.HTTP_202_ACCEPTED)
async def progress_command(command_id: str, progress: ProgressRequest,
                           x_timestamp: str | None = Header(default=None),
                           x_nonce: str | None = Header(default=None),
                           x_signature: str | None = Header(default=None),
                           x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(progress, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if command_id not in STORE.commands:
        raise HTTPException(404, "command not found")
    if progress.command_id != command_id:
        raise HTTPException(409, "command reference mismatch")
    STORE.commands[command_id]["progress"].append({"percent": progress.progress_percent, "message": progress.message})
    return STORE.commands[command_id]


@router.post("/orchestration/commands/{command_id}/result", status_code=status.HTTP_202_ACCEPTED)
async def command_result(command_id: str, result: ResultEnvelope,
                         x_timestamp: str | None = Header(default=None),
                         x_nonce: str | None = Header(default=None),
                         x_signature: str | None = Header(default=None),
                         x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(result, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if result.command_id != command_id:
        raise HTTPException(409, "command reference mismatch")
    return await receive_result(result, x_timestamp, x_nonce, x_signature, x_body_sha256)


@router.post("/orchestration/commands/{command_id}/error", status_code=status.HTTP_202_ACCEPTED)
async def command_error(command_id: str, error: ErrorEnvelope,
                        x_timestamp: str | None = Header(default=None),
                        x_nonce: str | None = Header(default=None),
                        x_signature: str | None = Header(default=None),
                        x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(error, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if error.command_id != command_id:
        raise HTTPException(409, "command reference mismatch")
    return await receive_error(error, x_timestamp, x_nonce, x_signature, x_body_sha256)


@router.post("/orchestration/commands/{command_id}/dead-letter", status_code=status.HTTP_202_ACCEPTED)
async def command_dead_letter(command_id: str, dead_letter: DeadLetterEnvelope,
                              x_timestamp: str | None = Header(default=None),
                              x_nonce: str | None = Header(default=None),
                              x_signature: str | None = Header(default=None),
                              x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(dead_letter, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if dead_letter.command_id != command_id:
        raise HTTPException(409, "command reference mismatch")
    return await receive_dead_letter(dead_letter, x_timestamp, x_nonce, x_signature, x_body_sha256)


@router.post("/orchestration/commands/{command_id}/reconcile", status_code=status.HTTP_202_ACCEPTED)
async def command_reconcile(command_id: str, reconciliation: ReconciliationRequest,
                            x_timestamp: str | None = Header(default=None),
                            x_nonce: str | None = Header(default=None),
                            x_signature: str | None = Header(default=None),
                            x_body_sha256: str | None = Header(default=None)) -> dict[str, Any]:
    _integrity(reconciliation, x_timestamp, x_nonce, x_signature, x_body_sha256)
    if reconciliation.command_id != command_id:
        raise HTTPException(409, "command reference mismatch")
    return await reconcile_order(reconciliation, x_timestamp, x_nonce, x_signature, x_body_sha256)
