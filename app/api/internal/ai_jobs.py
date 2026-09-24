"""Private polling contract for the outbound-only Qwen worker."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import base64
import binascii
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Mapping
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import ai_jobs, ai_orchestration
from app.core.ai_contracts import AIResult
from app.core.config import settings
from app.db.session import get_session
from app.qwen_auth_verifier import canonical_signing_string_v2

router = APIRouter(prefix="/internal/api/v1/ai", tags=["internal-ai-worker"])
HEX_64 = re.compile(r"[0-9a-f]{64}")
DECIMAL_TIMESTAMP = re.compile(r"[0-9]{10,11}")
SAFE_NONCE = re.compile(r"[A-Za-z0-9._~-]{16,128}")

SERVER_SCOPES = frozenset(
    {
        "ai.auth.verify/read-only",
        "ai.worker.claim",
        "ai.worker.heartbeat",
        "ai.worker.chunks",
        "ai.worker.complete",
        "ai.worker.fail",
        "ai.worker.get",
        "ai.worker.cancel",
        "ai.worker.dead-letters",
        "ai.worker.dead-letters.retry",
        "ai.worker.cancellation-check",
        "ai.worker.recover-expired",
    }
)


@dataclass(frozen=True)
class WorkerPrincipal:
    service_id: str
    worker_id: str
    tenant_id: UUID
    workspace_id: UUID
    request_id: str
    correlation_id: str
    scopes: frozenset[str]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LeaseRequest(StrictModel):
    worker_id: str = Field(min_length=3, max_length=128)
    allowed_model_profiles: list[str] | None = Field(
        default=None, min_length=1, max_length=7
    )


class LeaseMutation(StrictModel):
    worker_id: str = Field(min_length=3, max_length=128)
    fencing_token: int = Field(ge=1)


class ChunkRequest(LeaseMutation):
    sequence: int = Field(ge=0)
    content: str = Field(min_length=1)


class FailureRequest(LeaseMutation):
    error_code: str = Field(pattern=r"^[a-z0-9_.-]{1,64}$")
    retryable: bool = False
    safe_error_details: dict[str, str | int | bool] = Field(default_factory=dict)


class CompleteRequest(LeaseMutation):
    result: AIResult | None = None


class DeadLetterRetryRequest(StrictModel):
    approval_id: UUID


class RegistrationRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
    capabilities: dict[str, list[str] | int | str]
    max_concurrency: int = Field(ge=1, le=4)


class WorkerHeartbeatRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
    current_job_id: UUID | None = None


def _source_allowed(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
        return any(
            address in ipaddress.ip_network(item.strip(), strict=False)
            for item in settings.ai_worker_source_cidrs.split(",")
            if item.strip()
        )
    except ValueError:
        return False


def _certificate_identity(encoded_certificate: str) -> None:
    try:
        certificate = x509.load_der_x509_certificate(
            base64.b64decode(encoded_certificate, validate=True)
        )
        ca_path = Path(settings.ai_worker_client_ca_file)
        if not ca_path.is_absolute() or ca_path.is_symlink() or not ca_path.is_file():
            raise ValueError("CA")
        authority = x509.load_pem_x509_certificate(ca_path.read_bytes())
        certificate.verify_directly_issued_by(authority)
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_names != [
            x509.NameAttribute(NameOID.COMMON_NAME, settings.ai_worker_service_id)
        ]:
            raise ValueError("service identity")
        now = datetime.now(timezone.utc)
        if certificate.serial_number != int(settings.ai_worker_certificate_serial):
            raise ValueError("serial")
        if not (
            certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        ):
            raise ValueError("validity")
        uris = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        if uris != [settings.ai_worker_spiffe_id]:
            raise ValueError("SPIFFE")
        addresses = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.IPAddress)
        if addresses != [ipaddress.ip_address(settings.ai_worker_certificate_ip)]:
            raise ValueError("IP SAN")
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError("key usage")
        extended = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in extended:
            raise ValueError("client auth")
    except (
        InvalidSignature,
        ValueError,
        UnicodeError,
        binascii.Error,
        x509.ExtensionNotFound,
    ) as exc:
        raise HTTPException(401, "authentication denied") from exc


async def _claim_nonce(
    db: AsyncSession, service_id: str, nonce: str, correlation_id: str
) -> None:
    now = datetime.now(timezone.utc)
    digest = hashlib.sha256(f"{service_id}\n{nonce}".encode("ascii")).hexdigest()
    await db.execute(text("DELETE FROM ai_service_nonces WHERE expires_at <= now()"))
    result = await db.execute(
        text("""
        INSERT INTO ai_service_nonces
          (service_id, nonce_digest, received_at, expires_at, correlation_id)
        VALUES (:service, :digest, :received, :expires, :correlation)
        ON CONFLICT(service_id, nonce_digest) DO NOTHING
        RETURNING nonce_digest
    """),
        {
            "service": service_id,
            "digest": digest,
            "received": now,
            "expires": now + timedelta(seconds=settings.ai_signature_ttl_seconds),
            "correlation": correlation_id,
        },
    )
    if result.scalar_one_or_none() is None:
        await db.rollback()
        raise HTTPException(409, "replay detected")
    await db.commit()


async def authenticate_worker(
    request: Request,
    service_id: Annotated[str, Header(alias="X-Service-ID")],
    hmac_key_id: Annotated[str, Header(alias="X-HMAC-Key-ID")],
    timestamp: Annotated[str, Header(alias="X-Timestamp")],
    nonce: Annotated[str, Header(alias="X-Nonce", min_length=16, max_length=128)],
    body_digest: Annotated[str, Header(alias="X-Body-SHA256")],
    signature: Annotated[
        str, Header(alias="X-Signature", min_length=64, max_length=64)
    ],
    certificate: Annotated[str, Header(alias="X-Codestra-Client-Certificate-DER")],
    source_ip: Annotated[str, Header(alias="X-Codestra-Source-IP")],
    correlation_id: Annotated[
        str, Header(alias="X-Correlation-ID", min_length=8, max_length=128)
    ],
    request_id: Annotated[
        str, Header(alias="X-Request-ID", min_length=8, max_length=128)
    ],
    worker_id: Annotated[
        str, Header(alias="X-Worker-ID", min_length=3, max_length=128)
    ],
    signature_version: Annotated[str, Header(alias="X-Signature-Version")],
    tenant_id: Annotated[UUID, Header(alias="X-Tenant-ID")],
    workspace_id: Annotated[UUID, Header(alias="X-Workspace-ID")],
    db: AsyncSession = Depends(get_session),
) -> WorkerPrincipal:
    try:
        proxy = ipaddress.ip_address(request.client.host if request.client else "")
        trusted_proxy = ipaddress.ip_network(
            settings.ai_worker_trusted_proxy_cidr, strict=True
        )
    except ValueError as exc:
        raise HTTPException(404, "not found") from exc
    if proxy not in trusted_proxy or not _source_allowed(source_ip):
        raise HTTPException(404, "not found")
    _certificate_identity(certificate)
    if (
        service_id != settings.ai_worker_service_id
        or hmac_key_id != settings.ai_worker_hmac_key_id
    ):
        raise HTTPException(401, "authentication denied")
    if worker_id != settings.ai_worker_id:
        raise HTTPException(401, "authentication denied")
    if signature_version != "v2":
        raise HTTPException(401, "authentication denied")
    if not DECIMAL_TIMESTAMP.fullmatch(timestamp) or not SAFE_NONCE.fullmatch(nonce):
        raise HTTPException(401, "authentication denied")
    signed_at = int(timestamp)
    now = time.time()
    if abs(now - signed_at) > settings.ai_signature_ttl_seconds:
        raise HTTPException(401, "authentication denied")
    secret_path = Path(settings.ai_hmac_secret_file)
    if not secret_path.is_absolute() or not secret_path.is_file():
        raise HTTPException(503, "worker authentication unavailable")
    secret = secret_path.read_bytes().strip()
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", secret):
        raise HTTPException(503, "worker authentication unavailable")
    body = await request.body()
    digest = hashlib.sha256(body).hexdigest()
    if not HEX_64.fullmatch(body_digest) or not hmac.compare_digest(
        digest, body_digest
    ):
        raise HTTPException(401, "authentication denied")
    canonical = canonical_signing_string_v2(
        request.method.upper(),
        request.url.path,
        timestamp,
        nonce,
        body_digest,
        request_id,
        correlation_id,
        worker_id,
        str(tenant_id),
        str(workspace_id),
    )
    expected = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise HTTPException(401, "authentication denied")
    try:
        enrolled_tenant = UUID(settings.ai_worker_tenant_id)
        enrolled_workspace = UUID(settings.ai_worker_workspace_id)
    except ValueError as exc:
        raise HTTPException(503, "worker authorization unavailable") from exc
    if tenant_id != enrolled_tenant or workspace_id != enrolled_workspace:
        raise HTTPException(403, "worker tenant binding denied")
    await _claim_nonce(db, service_id, nonce, correlation_id)
    return WorkerPrincipal(
        service_id=settings.ai_worker_service_id,
        worker_id=worker_id,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        request_id=request_id,
        correlation_id=correlation_id,
        scopes=SERVER_SCOPES,
    )


def require_scope(scope: str):
    async def dependency(
        principal: WorkerPrincipal = Depends(authenticate_worker),
    ) -> WorkerPrincipal:
        if scope not in principal.scopes:
            raise HTTPException(403, "worker scope denied")
        return principal

    return dependency


def correlation(value: Annotated[str, Header(alias="X-Correlation-ID")]) -> str:
    if not 1 <= len(value) <= 128:
        raise HTTPException(400, "invalid correlation ID")
    return value


@router.post("/auth/verify")
async def verify_identity(
    _: WorkerPrincipal = Depends(require_scope("ai.auth.verify/read-only")),
) -> dict[str, object]:
    return {
        "verified": True,
        "service": settings.ai_worker_service_id,
        "scope": "ai.auth.verify/read-only",
        "version": "1.0",
    }


@router.post("/worker/jobs/claim")
async def claim_job(
    body: LeaseRequest,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.claim")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if not settings.ai_worker_claims_enabled:
        raise HTTPException(503, "AI worker claims are disabled")
    await ai_jobs.expire_deadlines(db, principal.tenant_id, principal.workspace_id)
    await ai_jobs.recover_expired(db, principal.tenant_id, principal.workspace_id)
    if body.worker_id != principal.worker_id:
        raise HTTPException(401, "authentication denied")
    try:
        item = await ai_jobs.claim(
            db,
            principal.worker_id,
            settings.ai_job_lease_seconds,
            principal.correlation_id,
            organization_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            service_id=principal.service_id,
            allowed_model_profiles=body.allowed_model_profiles,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except OverflowError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"job": item}


@router.post("/worker/jobs/{job_id}/heartbeat")
async def job_heartbeat(
    job_id: UUID,
    body: LeaseMutation,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.heartbeat")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    try:
        if body.worker_id != principal.worker_id:
            raise HTTPException(401, "authentication denied")
        expires = await ai_jobs.heartbeat(
            db,
            job_id,
            body.worker_id,
            body.fencing_token,
            settings.ai_job_lease_seconds,
            service_id=principal.service_id,
            certificate_serial=settings.ai_worker_certificate_serial,
            spiffe_id=settings.ai_worker_spiffe_id,
            organization_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
        )
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"accepted": True, "lease_expires_at": expires}


@router.post("/worker/jobs/{job_id}/chunks")
async def job_chunk(
    job_id: UUID,
    body: ChunkRequest,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.chunks")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    try:
        if body.worker_id != principal.worker_id:
            raise HTTPException(401, "authentication denied")
        inserted = await ai_jobs.append_chunk(
            db,
            job_id,
            body.worker_id,
            body.fencing_token,
            body.sequence,
            body.content,
            settings.ai_job_max_output_bytes,
            organization_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
        )
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    except OverflowError as exc:
        raise HTTPException(413, str(exc)) from exc
    return {"accepted": True, "duplicate": not inserted}


async def _finish(
    job_id: UUID,
    body: LeaseMutation,
    failed: bool,
    error_code: str | None,
    retryable: bool,
    request_id: str,
    db: AsyncSession,
    *,
    safe_error_details: Mapping[str, object] | None = None,
    principal: WorkerPrincipal | None = None,
) -> dict[str, str]:
    try:
        if principal is not None and body.worker_id != principal.worker_id:
            raise HTTPException(401, "authentication denied")
        state = await ai_jobs.finish(
            db,
            job_id,
            body.worker_id,
            body.fencing_token,
            failed=failed,
            error_code=error_code,
            retryable=retryable,
            correlation_id=request_id,
            safe_error_details=safe_error_details,
            organization_id=principal.tenant_id if principal else None,
            workspace_id=principal.workspace_id if principal else None,
        )
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"state": state}


@router.post("/worker/jobs/{job_id}/complete")
async def complete_job(
    job_id: UUID,
    body: CompleteRequest,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.complete")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    if body.worker_id != principal.worker_id:
        raise HTTPException(401, "authentication denied")
    try:
        duplicate = await ai_jobs.completed_result_status(
            db, job_id, principal.tenant_id, principal.workspace_id, body.result
        )
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    if duplicate is not None:
        return duplicate
    completion_state = "completed"
    if body.result is not None:
        if body.result.job_id != job_id or body.result.command_id != job_id:
            raise HTTPException(409, "result reference mismatch")
        try:
            job = await ai_jobs.assert_lease(
                db,
                job_id,
                body.worker_id,
                body.fencing_token,
                organization_id=principal.tenant_id,
                workspace_id=principal.workspace_id,
            )
        except PermissionError as exc:
            raise HTTPException(409, str(exc)) from exc
        completion_state = await ai_orchestration.store_result(db, job, body.result)
    try:
        state = await ai_jobs.finish(
            db,
            job_id,
            body.worker_id,
            body.fencing_token,
            failed=False,
            error_code=None,
            retryable=False,
            correlation_id=principal.correlation_id,
            completion_state=completion_state,
            organization_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
        )
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"state": state, "duplicate": "false"}


@router.post("/worker/jobs/{job_id}/fail")
async def fail_job(
    job_id: UUID,
    body: FailureRequest,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.fail")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    return await _finish(
        job_id,
        body,
        True,
        body.error_code,
        body.retryable,
        principal.correlation_id,
        db,
        safe_error_details=body.safe_error_details,
        principal=principal,
    )


@router.get("/worker/jobs/{job_id}")
async def get_job(
    job_id: UUID,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.get")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    try:
        return await ai_jobs.get_worker_job(
            db, job_id, principal.tenant_id, principal.workspace_id
        )
    except LookupError as exc:
        raise HTTPException(404, "job not found") from exc


@router.post("/worker/jobs/{job_id}/cancel")
async def cancel_job(
    job_id: UUID,
    body: LeaseMutation,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.cancel")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if body.worker_id != principal.worker_id:
        raise HTTPException(401, "authentication denied")
    try:
        return await ai_jobs.worker_cancel(
            db,
            job_id,
            principal.worker_id,
            body.fencing_token,
            principal.tenant_id,
            principal.workspace_id,
            principal.correlation_id,
        )
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/worker/dead-letters")
async def dead_letters(
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.dead-letters")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    return {
        "items": await ai_jobs.list_dead_letters(
            db, principal.tenant_id, principal.workspace_id
        )
    }


@router.post("/worker/dead-letters/{job_id}/retry")
async def retry_dead_letter(
    job_id: UUID,
    body: DeadLetterRetryRequest,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.dead-letters.retry")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    try:
        return await ai_jobs.retry_dead_letter(
            db,
            job_id,
            body.approval_id,
            principal.tenant_id,
            principal.workspace_id,
            principal.worker_id,
            principal.correlation_id,
        )
    except (LookupError, PermissionError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/worker/jobs/{job_id}/cancellation-check")
async def cancellation_check(
    job_id: UUID,
    body: LeaseMutation,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.cancellation-check")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    try:
        if body.worker_id != principal.worker_id:
            raise HTTPException(401, "authentication denied")
        row = await ai_jobs.assert_lease(
            db,
            job_id,
            body.worker_id,
            body.fencing_token,
            organization_id=principal.tenant_id,
            workspace_id=principal.workspace_id,
            allow_cancel_requested=True,
        )
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"cancel_requested": row["cancel_requested_at"] is not None}


@router.post("/worker/recover-expired")
async def recover(
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.recover-expired")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    return await ai_jobs.recover_expired(
        db, principal.tenant_id, principal.workspace_id
    )


@router.post("/worker/jobs/{job_id}/release")
async def release_job(
    job_id: UUID,
    body: LeaseMutation,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.fail")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    return await _finish(
        job_id,
        body,
        True,
        "worker_released",
        True,
        principal.correlation_id,
        db,
        principal=principal,
    )


@router.post("/worker/register", status_code=201)
async def register_worker(
    body: RegistrationRequest,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.heartbeat")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if body.worker_id != principal.worker_id:
        raise HTTPException(401, "authentication denied")
    canonical = __import__("json").dumps(
        body.capabilities, sort_keys=True, separators=(",", ":")
    )
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    await db.execute(
        text("""INSERT INTO ai_worker_registrations
      (worker_id,service_id,capability_digest,capabilities,max_concurrency,enabled)
      VALUES(:worker,:service,:digest,CAST(:capabilities AS jsonb),:concurrency,false)
      ON CONFLICT(worker_id) DO UPDATE SET service_id=:service,capability_digest=:digest,
      capabilities=CAST(:capabilities AS jsonb),max_concurrency=:concurrency,
      updated_at=now(),version=ai_worker_registrations.version+1"""),
        {
            "worker": body.worker_id,
            "service": principal.service_id,
            "digest": digest,
            "capabilities": canonical,
            "concurrency": body.max_concurrency,
        },
    )
    await db.commit()
    return {
        "worker_id": body.worker_id,
        "registered": True,
        "claims_enabled": False,
        "capability_digest": digest,
    }


@router.post("/worker/heartbeat")
async def worker_heartbeat(
    body: WorkerHeartbeatRequest,
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.heartbeat")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if body.worker_id != principal.worker_id:
        raise HTTPException(401, "authentication denied")
    await db.execute(
        text("""INSERT INTO ai_worker_heartbeats
      (worker_id,service_id,certificate_serial,spiffe_id,last_seen_at,current_job_id)
      VALUES(:worker,:service,:serial,:spiffe,now(),:job)
      ON CONFLICT(worker_id) DO UPDATE SET service_id=:service,certificate_serial=:serial,
      spiffe_id=:spiffe,last_seen_at=now(),current_job_id=:job"""),
        {
            "worker": body.worker_id,
            "service": principal.service_id,
            "serial": settings.ai_worker_certificate_serial,
            "spiffe": settings.ai_worker_spiffe_id,
            "job": body.current_job_id,
        },
    )
    await db.commit()
    return {"accepted": True, "claims_enabled": settings.ai_worker_claims_enabled}


@router.get("/worker/config")
async def worker_config(
    principal: WorkerPrincipal = Depends(require_scope("ai.worker.claim")),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    registration_max = (
        await db.execute(
            text("""SELECT max_concurrency FROM ai_worker_registrations
              WHERE worker_id=:worker AND service_id=:service AND enabled=true"""),
            {"worker": principal.worker_id, "service": principal.service_id},
        )
    ).scalar_one_or_none()
    if registration_max is None:
        raise HTTPException(403, "worker_not_enabled")
    return {
        "contract_version": "1.0",
        "claims_enabled": settings.ai_worker_claims_enabled,
        "lease_seconds": settings.ai_job_lease_seconds,
        "max_output_bytes": settings.ai_job_max_output_bytes,
        "registration_max_concurrency": registration_max,
        "hard_safety_cap": ai_jobs.WORKER_HARD_SAFETY_CAP,
        "model_runtime_classes": ai_jobs.MODEL_RUNTIME_CLASSES,
        "runtime_class_compatibility": {
            runtime_class: sorted(compatible_classes)
            for runtime_class, compatible_classes in (
                ai_jobs.RUNTIME_CLASS_COMPATIBILITY.items()
            )
        },
        "approved_profiles": [
            "fast-chat",
            "quality-chat",
            "coding-default",
            "coding-large",
            "crm-analysis",
            "voice-summary",
            "embedding-default",
        ],
        "external_endpoints": [],
    }
