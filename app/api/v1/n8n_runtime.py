"""Canonical tenant-bound n8n dispatch and authenticated result callback."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.n8n_runtime import (
    TERMINAL_STATUSES,
    DispatchRequest,
    ExecutionStatus,
    ResultContract,
    SocialEventEnvelope,
    canonical_bytes,
    dispatch_target_posture,
    load_secret,
    sha256,
    verify_fresh,
    verify_runtime,
)
from app.adapters.odoo.results import (
    approved_runtime_binding,
    is_test_syn_odoo_execution,
)
from app.db.models import (
    AuditEvent,
    N8nRuntimeExecution,
    N8nRuntimeNonce,
    N8nRuntimeResult,
    N8nWorkflowRegistry,
    OdooResultDelivery,
)
from app.db.session import get_session
from app.metrics import N8N_DISPATCH, N8N_RESULT, N8N_RESULT_FAILURE
from app.social.metrics import (
    n8n_callback_rejections,
    n8n_delivery_deadletter,
    n8n_delivery_success,
)

router = APIRouter(prefix="/api/v1/n8n-runtime", tags=["n8n-runtime"])

# Identity of this serving process. A restart yields a new instance id while
# every durable execution, result and audit row must read back unchanged; the
# TEST_SYN failure-path certification relies on exactly that contrast.
PROCESS_INSTANCE_ID = str(uuid4())
PROCESS_STARTED_AT = datetime.now(UTC)


def _process_identity() -> dict[str, Any]:
    return {
        "process_instance_id": PROCESS_INSTANCE_ID,
        "started_at": PROCESS_STARTED_AT.isoformat(),
    }


def _safe_execution(
    value: N8nRuntimeExecution, duplicate: bool = False
) -> dict[str, Any]:
    return {
        "schema_version": "codestra.n8n.execution.v1",
        "execution_id": str(value.execution_id),
        "tenant_id": value.tenant_id,
        "event_id": value.event_id,
        "workflow_code": value.workflow_code,
        "workflow_version": value.workflow_version,
        "status": value.status,
        "correlation_id": value.correlation_id,
        "duplicate": duplicate,
    }


@router.post("/dispatch", status_code=status.HTTP_202_ACCEPTED)
async def dispatch(
    body: DispatchRequest,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    if not settings.n8n_runtime_enabled:
        raise HTTPException(503, "governed n8n runtime is disabled")
    payload_hash = sha256(canonical_bytes(body.payload))
    key_hash = hashlib.sha256(body.idempotency_key.encode()).hexdigest()
    lock_scope = f"{body.tenant_id}:{body.event_type}:{body.source_event_id}:{key_hash}"
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {"scope": lock_scope},
    )
    registry = await db.scalar(
        select(N8nWorkflowRegistry).where(
            N8nWorkflowRegistry.enabled.is_(True),
            N8nWorkflowRegistry.event_types.contains([body.event_type]),
            N8nWorkflowRegistry.tenant_scope.contains([body.tenant_id]),
        )
    )
    if registry is None:
        await db.rollback()
        raise HTTPException(403, "no approved workflow mapping")
    existing = await db.scalar(
        select(N8nRuntimeExecution).where(
            N8nRuntimeExecution.tenant_id == body.tenant_id,
            N8nRuntimeExecution.event_type == body.event_type,
            N8nRuntimeExecution.source_event_id == body.source_event_id,
            N8nRuntimeExecution.workflow_version == registry.workflow_version,
            N8nRuntimeExecution.idempotency_key_hash == key_hash,
        )
    )
    if existing is not None:
        if existing.payload_hash != payload_hash:
            await db.rollback()
            raise HTTPException(409, "workflow payload conflict")
        await db.commit()
        response.status_code = status.HTTP_200_OK
        N8N_DISPATCH.labels(outcome="duplicate").inc()
        return _safe_execution(existing, True)
    now = datetime.now(UTC)
    execution = N8nRuntimeExecution(
        execution_id=uuid4(),
        tenant_id=body.tenant_id,
        event_id=body.event_id,
        event_type=body.event_type,
        source_event_id=body.source_event_id,
        workflow_code=registry.workflow_code,
        workflow_version=registry.workflow_version,
        correlation_id=body.correlation_id,
        causation_id=body.causation_id,
        trace_id=body.trace_id,
        idempotency_key_hash=key_hash,
        payload_hash=payload_hash,
        payload_json=body.payload,
        status=ExecutionStatus.PENDING,
        timeout_at=now + timedelta(seconds=registry.timeout_seconds),
    )
    db.add(execution)
    db.add(
        AuditEvent(
            action="n8n.runtime.created",
            subject=str(execution.execution_id),
            correlation_id=body.correlation_id,
            decision="accepted",
            redacted_payload={
                "tenant_id": body.tenant_id,
                "event_id": body.event_id,
                "workflow_code": registry.workflow_code,
                "workflow_version": registry.workflow_version,
                "payload_hash": payload_hash,
            },
        )
    )
    await db.commit()
    N8N_DISPATCH.labels(outcome="created").inc()
    return _safe_execution(execution)


@router.get("/executions/{execution_id}")
async def execution_status(
    execution_id: UUID,
    tenant_id: str,
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    execution = await db.get(N8nRuntimeExecution, execution_id)
    if execution is None or execution.tenant_id != tenant_id:
        raise HTTPException(404, "execution not found")
    return _safe_execution(execution)


@router.get("/process")
async def runtime_process() -> dict[str, Any]:
    """Secret-free runtime identity and dispatch-target posture."""
    return {
        "schema_version": "codestra.n8n.runtime-process.v1",
        **_process_identity(),
        "environment": settings.environment,
        "runtime_environment": settings.n8n_runtime_environment,
        "runtime_enabled": settings.n8n_runtime_enabled,
        "dispatch_target": dispatch_target_posture(
            settings.n8n_runtime_base_url, settings.n8n_runtime_environment
        ),
    }


def certification_evidence(
    execution: N8nRuntimeExecution,
    results: list[N8nRuntimeResult],
    audits: list[AuditEvent],
    accepted_nonces: int,
    odoo_deliveries: list[OdooResultDelivery],
) -> dict[str, Any]:
    """Durable, redacted evidence for one execution's command/result lifecycle.

    Payloads and result bodies are never echoed; only hashes, statuses,
    identifiers and the continuity/reconciliation verdicts derived from them.
    """
    ordered = sorted(
        results, key=lambda r: (r.occurred_at, r.persisted_at or r.occurred_at)
    )
    correlation_ids = {execution.correlation_id}
    correlation_ids.update(str(r.result_json.get("correlation_id")) for r in ordered)
    correlation_ids.update(a.correlation_id for a in audits)
    bound = all(
        r.result_json.get("execution_id") == str(execution.execution_id)
        and r.result_json.get("tenant_id") == execution.tenant_id
        and r.tenant_id == execution.tenant_id
        and r.workflow_code == execution.workflow_code
        for r in ordered
    )
    if not ordered:
        reconciliation = (
            "terminal_without_result"
            if execution.status in TERMINAL_STATUSES
            else "awaiting_result"
        )
    elif ordered[-1].status == execution.status:
        reconciliation = "reconciled"
    else:
        reconciliation = "divergent"
    return {
        "schema_version": "codestra.n8n.execution-evidence.v1",
        "execution": {
            **_safe_execution(execution),
            "event_type": execution.event_type,
            "causation_id": execution.causation_id,
            "trace_id": execution.trace_id,
            "payload_hash": execution.payload_hash,
            "attempt_count": execution.attempt_count,
            "failure_class": execution.failure_class,
            "last_error_code": execution.last_error_code,
            "created_at": execution.created_at.isoformat()
            if execution.created_at
            else None,
            "completed_at": execution.completed_at.isoformat()
            if execution.completed_at
            else None,
        },
        "results": [
            {
                "result_id": str(r.result_id),
                "status": r.status,
                "result_hash": r.result_hash,
                "occurred_at": r.occurred_at.isoformat(),
            }
            for r in ordered
        ],
        "audit": [
            {
                "action": a.action,
                "decision": a.decision,
                "correlation_id": a.correlation_id,
            }
            for a in sorted(audits, key=lambda a: (a.created_at is None, a.created_at))
        ],
        "accepted_callback_nonces": accepted_nonces,
        "odoo_result_deliveries": [
            {"status": d.status, "request_hash": d.request_hash}
            for d in odoo_deliveries
        ],
        "checks": {
            "correlation_continuous": len(correlation_ids) == 1,
            "result_binding_intact": bound,
            "result_hashes_unique": len({r.result_hash for r in ordered})
            == len(ordered),
            "reconciliation": reconciliation,
            "synthetic_odoo_binding": is_test_syn_odoo_execution(execution),
            "odoo_result_deliveries": len(odoo_deliveries),
        },
        "process": _process_identity(),
    }


@router.get("/executions/{execution_id}/evidence")
async def execution_evidence(
    execution_id: UUID,
    tenant_id: str,
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    execution = await db.get(N8nRuntimeExecution, execution_id)
    if execution is None or execution.tenant_id != tenant_id:
        raise HTTPException(404, "execution not found")
    results = list(
        (
            await db.scalars(
                select(N8nRuntimeResult).where(
                    N8nRuntimeResult.execution_id == execution.execution_id
                )
            )
        ).all()
    )
    result_ids = [r.result_id for r in results]
    subjects = [str(execution.execution_id), *(str(i) for i in result_ids)]
    audits = list(
        (
            await db.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.subject.in_(subjects),
                    AuditEvent.action.like("n8n.runtime.%"),
                )
                .limit(200)
            )
        ).all()
    )
    accepted_nonces = await db.scalar(
        select(func.count())
        .select_from(N8nRuntimeNonce)
        .where(N8nRuntimeNonce.execution_id == execution.execution_id)
    )
    deliveries = (
        list(
            (
                await db.scalars(
                    select(OdooResultDelivery).where(
                        OdooResultDelivery.runtime_result_id.in_(result_ids)
                    )
                )
            ).all()
        )
        if result_ids
        else []
    )
    return certification_evidence(
        execution, results, audits, int(accepted_nonces or 0), deliveries
    )


@router.post("/social-authorize", status_code=202)
async def authorize_social_ingress(
    request: Request,
    response: Response,
    x_codestra_identity: Annotated[str, Header(alias="X-Codestra-Identity")],
    x_codestra_tenant: Annotated[str, Header(alias="X-Codestra-Tenant")],
    x_codestra_workflow: Annotated[str, Header(alias="X-Codestra-Workflow")],
    x_codestra_execution: Annotated[str, Header(alias="X-Codestra-Execution")],
    x_codestra_correlation_id: Annotated[
        str, Header(alias="X-Codestra-Correlation-ID")
    ],
    x_codestra_timestamp: Annotated[str, Header(alias="X-Codestra-Timestamp")],
    x_codestra_nonce: Annotated[str, Header(alias="X-Codestra-Nonce")],
    x_codestra_body_sha256: Annotated[str, Header(alias="X-Codestra-Body-SHA256")],
    x_codestra_signature: Annotated[str, Header(alias="X-Codestra-Signature")],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Authorize n8n handling with durable replay and event deduplication."""
    raw = await request.body()
    body_hash = sha256(raw)
    try:
        verify_fresh(x_codestra_timestamp, settings.signature_ttl_seconds)
        if x_codestra_identity != "codestra-middleware":
            raise ValueError("wrong identity")
        if x_codestra_workflow != "CDST_SOCIAL_EVENT_ROUTER":
            raise ValueError("wrong workflow")
        if body_hash != x_codestra_body_sha256.removeprefix("sha256:"):
            raise ValueError("body hash mismatch")
        verify_runtime(
            x_codestra_signature,
            load_secret(settings.n8n_runtime_hmac_secret_file),
            identity=x_codestra_identity,
            tenant_id=x_codestra_tenant,
            workflow_code=x_codestra_workflow,
            execution_id=x_codestra_execution,
            correlation_id=x_codestra_correlation_id,
            timestamp=x_codestra_timestamp,
            nonce=x_codestra_nonce,
            body_hash=body_hash,
        )
        outer = json.loads(raw)
        social = SocialEventEnvelope.model_validate(outer["payload"])
        execution_id = UUID(x_codestra_execution)
    except (KeyError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        n8n_callback_rejections.labels(reason="ingress_authentication").inc()
        raise HTTPException(401, "invalid social n8n ingress") from exc
    execution = await db.get(N8nRuntimeExecution, execution_id, with_for_update=True)
    delivery_id = await db.scalar(
        text(
            "SELECT delivery_id FROM social_n8n_delivery_execution "
            "WHERE execution_id=:execution"
        ),
        {"execution": execution_id},
    )
    if (
        execution is None
        or delivery_id is None
        or execution.tenant_id != x_codestra_tenant
        or execution.workflow_code != x_codestra_workflow
        or execution.correlation_id != x_codestra_correlation_id
        or social.tenant_id != execution.tenant_id
        or social.event_id != execution.event_id
        or social.event_type != execution.event_type
        or outer.get("execution_id") != str(execution.execution_id)
    ):
        await db.rollback()
        n8n_callback_rejections.labels(reason="ingress_binding").inc()
        raise HTTPException(409, "social n8n ingress binding mismatch")
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope,0))"),
        {"scope": f"social-n8n:{x_codestra_identity}:{x_codestra_nonce}"},
    )
    if await db.get(N8nRuntimeNonce, (x_codestra_identity, x_codestra_nonce)):
        await db.rollback()
        n8n_callback_rejections.labels(reason="ingress_replay").inc()
        raise HTTPException(409, "replayed social n8n ingress")
    db.add(
        N8nRuntimeNonce(
            identity=x_codestra_identity,
            nonce=x_codestra_nonce,
            tenant_id=execution.tenant_id,
            execution_id=execution.execution_id,
            body_hash=body_hash,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=settings.signature_ttl_seconds),
        )
    )
    existing = (
        (
            await db.execute(
                text(
                    "SELECT body_hash FROM social_n8n_ingress_events "
                    "WHERE event_id=:event"
                ),
                {"event": social.event_id},
            )
        )
        .mappings()
        .first()
    )
    if existing is not None:
        if existing["body_hash"] != body_hash:
            await db.rollback()
            raise HTTPException(409, "social event payload conflict")
        await db.commit()
        response.status_code = 200
        return {"authorized": True, "duplicate": True, "route": "duplicate"}
    await db.execute(
        text(
            """INSERT INTO social_n8n_ingress_events
            (event_id,execution_id,delivery_id,body_hash,first_nonce)
            VALUES (:event,:execution,:delivery,:hash,:nonce)"""
        ),
        {
            "event": social.event_id,
            "execution": execution.execution_id,
            "delivery": delivery_id,
            "hash": body_hash,
            "nonce": x_codestra_nonce,
        },
    )
    await db.commit()
    return {
        "authorized": True,
        "duplicate": False,
        "route": social.event_type,
        "event_id": social.event_id,
        "event": social.model_dump(mode="json"),
        "execution_id": str(execution.execution_id),
        "workflow_code": execution.workflow_code,
        "workflow_version": execution.workflow_version,
        "tenant_id": execution.tenant_id,
        "correlation_id": execution.correlation_id,
    }


@router.post("/results", status_code=202)
async def result_callback(
    request: Request,
    response: Response,
    x_codestra_identity: Annotated[str, Header(alias="X-Codestra-Identity")],
    x_codestra_tenant: Annotated[str, Header(alias="X-Codestra-Tenant")],
    x_codestra_workflow: Annotated[str, Header(alias="X-Codestra-Workflow")],
    x_codestra_execution: Annotated[str, Header(alias="X-Codestra-Execution")],
    x_codestra_correlation_id: Annotated[
        str, Header(alias="X-Codestra-Correlation-ID")
    ],
    x_codestra_timestamp: Annotated[str, Header(alias="X-Codestra-Timestamp")],
    x_codestra_nonce: Annotated[str, Header(alias="X-Codestra-Nonce")],
    x_codestra_body_sha256: Annotated[str, Header(alias="X-Codestra-Body-SHA256")],
    x_codestra_signature: Annotated[str, Header(alias="X-Codestra-Signature")],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    raw = await request.body()
    body_hash = sha256(raw)
    try:
        verify_fresh(x_codestra_timestamp, settings.signature_ttl_seconds)
        if body_hash != x_codestra_body_sha256.removeprefix("sha256:"):
            raise ValueError("body hash mismatch")
        verify_runtime(
            x_codestra_signature,
            load_secret(settings.n8n_runtime_hmac_secret_file),
            identity=x_codestra_identity,
            tenant_id=x_codestra_tenant,
            workflow_code=x_codestra_workflow,
            execution_id=x_codestra_execution,
            correlation_id=x_codestra_correlation_id,
            timestamp=x_codestra_timestamp,
            nonce=x_codestra_nonce,
            body_hash=body_hash,
        )
        body = ResultContract.model_validate_json(raw)
        execution_id = UUID(x_codestra_execution)
    except (RuntimeError, ValueError) as exc:
        N8N_RESULT_FAILURE.labels(reason="authentication_or_contract").inc()
        n8n_callback_rejections.labels(reason="authentication_or_contract").inc()
        raise HTTPException(
            401, "invalid n8n result authentication or contract"
        ) from exc
    execution = await db.get(N8nRuntimeExecution, execution_id, with_for_update=True)
    if (
        execution is None
        or execution.tenant_id != x_codestra_tenant
        or execution.workflow_code != x_codestra_workflow
        or execution.correlation_id != x_codestra_correlation_id
        or body.tenant_id != execution.tenant_id
        or body.workflow_code != execution.workflow_code
        or body.workflow_version != execution.workflow_version
        or body.execution_id != str(execution.execution_id)
        or body.correlation_id != execution.correlation_id
    ):
        await db.rollback()
        N8N_RESULT_FAILURE.labels(reason="binding").inc()
        n8n_callback_rejections.labels(reason="binding").inc()
        raise HTTPException(409, "n8n result binding mismatch")
    if await db.get(N8nRuntimeNonce, (x_codestra_identity, x_codestra_nonce)):
        await db.rollback()
        N8N_RESULT_FAILURE.labels(reason="replay").inc()
        n8n_callback_rejections.labels(reason="replay").inc()
        raise HTTPException(409, "replayed n8n result")
    db.add(
        N8nRuntimeNonce(
            identity=x_codestra_identity,
            nonce=x_codestra_nonce,
            tenant_id=execution.tenant_id,
            execution_id=execution.execution_id,
            body_hash=body_hash,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=settings.signature_ttl_seconds),
        )
    )
    result_hash = sha256(canonical_bytes(body))
    prior = await db.scalar(
        select(N8nRuntimeResult).where(
            N8nRuntimeResult.execution_id == execution.execution_id,
            N8nRuntimeResult.result_hash == result_hash,
        )
    )
    if prior is not None:
        await db.commit()
        response.status_code = 200
        return {
            "accepted": True,
            "duplicate": True,
            "execution_id": str(execution.execution_id),
        }
    mapped = {
        "running": ExecutionStatus.RUNNING,
        "completed": ExecutionStatus.COMPLETED,
        "failed": ExecutionStatus.FAILED,
        "retry": ExecutionStatus.RETRY,
        "dead_letter": ExecutionStatus.DEAD_LETTER,
    }[body.status]
    execution.status = mapped
    execution.n8n_execution_id = execution.n8n_execution_id or x_codestra_execution
    execution.updated_at = datetime.now(UTC)
    if mapped in {
        ExecutionStatus.COMPLETED,
        ExecutionStatus.FAILED,
        ExecutionStatus.DEAD_LETTER,
    }:
        execution.completed_at = datetime.now(UTC)
    runtime_result = N8nRuntimeResult(
        result_id=uuid4(),
        execution_id=execution.execution_id,
        tenant_id=execution.tenant_id,
        workflow_code=execution.workflow_code,
        result_hash=result_hash,
        status=mapped,
        result_json=body.model_dump(mode="json"),
        occurred_at=body.occurred_at,
    )
    db.add(runtime_result)
    synthetic_binding = approved_runtime_binding(execution, runtime_result)
    if is_test_syn_odoo_execution(execution) and synthetic_binding is None:
        await db.rollback()
        N8N_RESULT_FAILURE.labels(reason="unapproved_test_syn_result").inc()
        raise HTTPException(422, "unapproved TEST_SYN result contract")
    if mapped == ExecutionStatus.COMPLETED and synthetic_binding is not None:
        db.add(
            OdooResultDelivery(
                runtime_result_id=runtime_result.result_id,
                originating_outbox_public_id=synthetic_binding[
                    "originating_outbox_public_id"
                ],
                request_hash=result_hash,
                status="PENDING",
            )
        )
        db.add(
            AuditEvent(
                action="n8n.runtime.odoo_result_queued",
                subject=str(runtime_result.result_id),
                correlation_id=execution.correlation_id,
                decision="allowlisted_synthetic",
                redacted_payload={
                    "tenant_id": execution.tenant_id,
                    "workflow_code": execution.workflow_code,
                    "result_hash": result_hash,
                },
            )
        )
    db.add(
        AuditEvent(
            action="n8n.runtime.result",
            subject=str(execution.execution_id),
            correlation_id=execution.correlation_id,
            decision=mapped,
            redacted_payload={
                "tenant_id": execution.tenant_id,
                "result_hash": result_hash,
            },
        )
    )
    delivery_id = await db.scalar(
        text(
            "SELECT delivery_id FROM social_n8n_delivery_execution "
            "WHERE execution_id=:execution"
        ),
        {"execution": execution.execution_id},
    )
    if delivery_id is not None and mapped in {
        ExecutionStatus.COMPLETED,
        ExecutionStatus.FAILED,
        ExecutionStatus.DEAD_LETTER,
    }:
        delivery_status = (
            "delivered" if mapped == ExecutionStatus.COMPLETED else "dead_letter"
        )
        await db.execute(
            text(
                """UPDATE integration_delivery SET status=:status,last_error=:error,
                lease_owner=NULL,lease_expires_at=NULL,result_json=CAST(:result AS jsonb)
                WHERE id=:delivery AND status='delivering'"""
            ),
            {
                "status": delivery_status,
                "error": None if delivery_status == "delivered" else f"N8N_{mapped}",
                "result": json.dumps(body.model_dump(mode="json"), default=str),
                "delivery": delivery_id,
            },
        )
        if delivery_status == "delivered":
            n8n_delivery_success.inc()
        else:
            n8n_delivery_deadletter.labels(reason=f"N8N_{mapped}").inc()
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "n8n result conflict") from exc
    N8N_RESULT.labels(status=mapped).inc()
    return {
        "accepted": True,
        "duplicate": False,
        "execution_id": str(execution.execution_id),
        "status": mapped,
    }
