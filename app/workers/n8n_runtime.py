"""Lease-safe dispatcher for durable n8n runtime executions."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.n8n_runtime import (
    ExecutionStatus,
    canonical_bytes,
    load_secret,
    retry_delay,
    retryable,
    sha256,
    sign_runtime,
)
from app.db.models import N8nRuntimeExecution, N8nWorkflowRegistry
from app.metrics import (
    N8N_DEAD_LETTER,
    N8N_DISPATCH,
    N8N_DISPATCH_FAILURE,
    N8N_RETRY,
    N8N_TIMEOUT,
)


async def claim(session: AsyncSession, limit: int = 10) -> list[N8nRuntimeExecution]:
    if limit < 1 or limit > 25:
        raise ValueError("claim limit is outside bounds")
    now = datetime.now(UTC)
    rows = (
        await session.scalars(
            select(N8nRuntimeExecution)
            .where(
                N8nRuntimeExecution.status.in_(
                    [ExecutionStatus.PENDING, ExecutionStatus.RETRY]
                ),
                (N8nRuntimeExecution.next_attempt_at.is_(None))
                | (N8nRuntimeExecution.next_attempt_at <= now),
            )
            .order_by(N8nRuntimeExecution.created_at)
            .with_for_update(skip_locked=True)
            .limit(limit)
        )
    ).all()
    for row in rows:
        if row.timeout_at <= now:
            row.status = ExecutionStatus.TIMED_OUT
            row.completed_at = now
            N8N_TIMEOUT.inc()
        else:
            row.status = ExecutionStatus.DISPATCHING
            row.attempt_count += 1
            row.updated_at = now
    await session.commit()
    return [row for row in rows if row.status == ExecutionStatus.DISPATCHING]


async def recover_stale_dispatches(
    session: AsyncSession, lease_seconds: int = 60
) -> int:
    """Return abandoned dispatch leases to retry without losing the durable job."""
    if lease_seconds < 10 or lease_seconds > 600:
        raise ValueError("dispatch lease is outside bounds")
    now = datetime.now(UTC)
    result = await session.execute(
        update(N8nRuntimeExecution)
        .where(
            N8nRuntimeExecution.status == ExecutionStatus.DISPATCHING,
            N8nRuntimeExecution.updated_at <= now - timedelta(seconds=lease_seconds),
        )
        .values(
            status=ExecutionStatus.RETRY,
            next_attempt_at=now,
            failure_class="TRANSIENT",
            last_error_code="STALE_DISPATCH_LEASE",
            updated_at=now,
        )
    )
    await session.commit()
    return int(result.rowcount or 0)


async def expire_running(session: AsyncSession) -> int:
    """Close executions whose durable workflow deadline has elapsed."""
    now = datetime.now(UTC)
    result = await session.execute(
        update(N8nRuntimeExecution)
        .where(
            N8nRuntimeExecution.status == ExecutionStatus.RUNNING,
            N8nRuntimeExecution.timeout_at <= now,
        )
        .values(
            status=ExecutionStatus.TIMED_OUT,
            failure_class="PERMANENT",
            last_error_code="WORKFLOW_TIMEOUT",
            completed_at=now,
            updated_at=now,
        )
    )
    await session.commit()
    count = int(result.rowcount or 0)
    if count:
        N8N_TIMEOUT.inc(count)
    return count


async def dispatch_one(
    session: AsyncSession,
    execution: N8nRuntimeExecution,
    client: httpx.AsyncClient,
) -> bool:
    durable = await session.get(
        N8nRuntimeExecution, execution.execution_id, with_for_update=True
    )
    if durable is None or durable.status != ExecutionStatus.DISPATCHING:
        N8N_DISPATCH_FAILURE.labels(failure_class="LEASE_NOT_OWNED").inc()
        return False
    execution = durable
    registry = await session.scalar(
        select(N8nWorkflowRegistry).where(
            N8nWorkflowRegistry.workflow_code == execution.workflow_code,
            N8nWorkflowRegistry.workflow_version == execution.workflow_version,
            N8nWorkflowRegistry.enabled.is_(True),
        )
    )
    if registry is None or execution.tenant_id not in registry.tenant_scope:
        await _fail(session, execution, "REGISTRY_DENIED", False)
        return False
    target = urlsplit(settings.n8n_runtime_base_url)
    approved_staging_hosts = {
        "webhook",
        "n8n-webhook-staging",
        "n8n-runtime-test-double",
    }
    target_is_allowed = (target.scheme == "https" and bool(target.hostname)) or (
        settings.n8n_runtime_environment == "staging"
        and target.scheme == "http"
        and target.hostname in approved_staging_hosts
    )
    if (
        not target_is_allowed
        or target.username
        or target.password
        or target.query
        or target.fragment
    ):
        await _fail(session, execution, "TARGET_NOT_PRIVATE_HTTPS", False)
        return False
    url = settings.n8n_runtime_base_url.rstrip("/") + registry.webhook_path
    envelope = {
        "schema_version": "codestra.n8n.execution.v1",
        "execution_id": str(execution.execution_id),
        "tenant_id": execution.tenant_id,
        "event_id": execution.event_id,
        "event_type": execution.event_type,
        "workflow_code": execution.workflow_code,
        "workflow_version": execution.workflow_version,
        "correlation_id": execution.correlation_id,
        "causation_id": execution.causation_id,
        "trace_id": execution.trace_id,
        "payload": execution.payload_json,
    }
    raw = canonical_bytes(envelope)
    timestamp = str(int(time.time()))
    nonce = uuid4().hex
    body_hash = sha256(raw)
    headers = {
        "Content-Type": "application/json",
        "X-Codestra-Identity": "codestra-middleware",
        "X-Codestra-Tenant": execution.tenant_id,
        "X-Codestra-Workflow": execution.workflow_code,
        "X-Codestra-Execution": str(execution.execution_id),
        "X-Codestra-Correlation-ID": execution.correlation_id,
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Nonce": nonce,
        "X-Codestra-Body-SHA256": f"sha256:{body_hash}",
        "X-Codestra-Signature": "sha256="
        + sign_runtime(
            secret=load_secret(settings.n8n_runtime_hmac_secret_file),
            identity="codestra-middleware",
            tenant_id=execution.tenant_id,
            workflow_code=execution.workflow_code,
            execution_id=str(execution.execution_id),
            correlation_id=execution.correlation_id,
            timestamp=timestamp,
            nonce=nonce,
            body_hash=body_hash,
        ),
    }
    try:
        response = await client.post(url, content=raw, headers=headers)
    except httpx.HTTPError:
        await _fail(session, execution, "NETWORK_INTERRUPTION", True)
        return False
    if response.status_code not in {200, 202} or response.is_redirect:
        await _fail(
            session,
            execution,
            f"HTTP_{response.status_code}",
            retryable(response.status_code),
        )
        return False
    execution.status = ExecutionStatus.RUNNING
    execution.failure_class = None
    execution.last_error_code = None
    execution.next_attempt_at = None
    execution.updated_at = datetime.now(UTC)
    await session.commit()
    N8N_DISPATCH.labels(outcome="submitted").inc()
    return True


async def _fail(
    session: AsyncSession,
    execution: N8nRuntimeExecution,
    error_code: str,
    can_retry: bool,
) -> None:
    execution.failure_class = "TRANSIENT" if can_retry else "PERMANENT"
    execution.last_error_code = error_code
    max_attempts = min(settings.n8n_runtime_max_attempts, 8)
    if can_retry and execution.attempt_count < max_attempts:
        execution.status = ExecutionStatus.RETRY
        execution.next_attempt_at = datetime.now(UTC) + timedelta(
            seconds=retry_delay(execution.attempt_count)
        )
        N8N_RETRY.labels(failure_class=error_code).inc()
    else:
        execution.status = ExecutionStatus.DEAD_LETTER
        execution.completed_at = datetime.now(UTC)
        N8N_DEAD_LETTER.labels(workflow_code=execution.workflow_code).inc()
    execution.updated_at = datetime.now(UTC)
    await session.commit()
    N8N_DISPATCH_FAILURE.labels(failure_class=error_code).inc()
