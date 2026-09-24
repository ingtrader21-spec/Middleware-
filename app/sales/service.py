from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from .compliance import ComplianceSnapshot, evaluate
from .contracts import (
    Decision,
    LeadCandidate,
    LeadResolution,
    MatchResolution,
    POLICY_VERSION,
    VerificationJobRequest,
    VerificationJobState,
)
from .identity import MatchPolicy, best_company, best_contact
from .odoo import DisabledOdooReadOnlyAdapter, OdooReadOnlyPort, OdooReadUnavailable


SALES_AUDIT_EVENT_TYPES = frozenset(
    {
        "lead_candidate.received",
        "lead_candidate.validated",
        "lead_candidate.rejected",
        "identity_resolution.completed",
        "duplicate_review.created",
        "compliance_gate.evaluated",
        "verification_job.created",
        "verification_job.started",
        "verification_job.completed",
        "verification_job.failed",
        "provider_call.attempted",
        "provider_call.completed",
        "provider_call.failed",
        "scraper_webhook.accepted",
        "scraper_webhook.rejected",
        "idempotent_replay.returned",
        "idempotency_conflict.rejected",
    }
)


class SalesError(ValueError):
    code = "SALES_REQUEST_REJECTED"
    status = 422
    retryable = False


class SalesConflict(SalesError):
    code = "IDEMPOTENCY_PAYLOAD_CONFLICT"
    status = 409


class SalesDependencyUnavailable(SalesError):
    code = "AUTHORITATIVE_DEPENDENCY_UNAVAILABLE"
    status = 503
    retryable = True


@dataclass(frozen=True)
class IdempotencyEntry:
    tenant_id: str
    operation: str
    key_hash: str
    payload_hash: str
    result: dict[str, Any]
    correlation_id: str
    created_at: datetime


@dataclass(frozen=True)
class AuditRecord:
    event_type: str
    tenant_id: str
    actor: str
    correlation_id: str
    subject_id: str
    decision: str
    reason_codes: tuple[str, ...]
    policy_version: str
    payload_hash: str
    source_provider: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class DuplicateReview:
    review_id: str
    tenant_id: str
    campaign_id: str
    candidate_id: str
    odoo_company_id: str | None
    odoo_lead_id: str | None
    company_score: int
    contact_score: int
    match_reasons: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    policy_version: str
    state: str = "PENDING"
    reviewer_identity: str | None = None
    review_decision_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class VerificationJob:
    job_id: str
    request: VerificationJobRequest
    correlation_id: str
    state: VerificationJobState = VerificationJobState.QUEUED
    total: int = 0
    processed: int = 0
    warnings: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def canonical_hash(value: LeadCandidate | VerificationJobRequest) -> str:
    body = value.model_dump(mode="json", exclude_none=False)
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


class SalesLeadService:
    """Phase 1 control plane: deterministic, tenant-bound and write-free."""

    def __init__(
        self, odoo: OdooReadOnlyPort | None = None, policy: MatchPolicy | None = None
    ) -> None:
        self.odoo = odoo or DisabledOdooReadOnlyAdapter()
        self.policy = policy or MatchPolicy()
        self.idempotency: dict[tuple[str, str, str], IdempotencyEntry] = {}
        self.locks: dict[tuple[str, str, str], asyncio.Lock] = {}
        self.candidates: dict[str, LeadCandidate] = {}
        self.resolutions: dict[str, LeadResolution] = {}
        self.reviews: dict[str, DuplicateReview] = {}
        self.jobs: dict[str, VerificationJob] = {}
        self.audits: list[AuditRecord] = []
        self.vicidial_write_count = 0
        self.outreach_event_count = 0

    def _audit(
        self,
        event_type: str,
        candidate: LeadCandidate,
        correlation_id: str,
        subject_id: str,
        decision: str,
        reasons: tuple[str, ...],
        payload_hash: str,
        actor: str = "codestra-sales-lead-service",
    ) -> None:
        self.audits.append(
            AuditRecord(
                event_type,
                candidate.tenant_id,
                actor,
                correlation_id,
                subject_id,
                decision,
                reasons,
                POLICY_VERSION,
                payload_hash,
                candidate.source.provider,
            )
        )

    async def resolve(
        self,
        candidate: LeadCandidate,
        idempotency_key: str,
        correlation_id: str,
    ) -> tuple[LeadResolution, bool]:
        if len(idempotency_key) < 16 or len(idempotency_key) > 255:
            raise SalesError("idempotency key is outside bounded limits")
        operation = "lead_candidate.resolve"
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        scope = (candidate.tenant_id, operation, key_hash)
        payload_hash = canonical_hash(candidate)
        lock = self.locks.setdefault(scope, asyncio.Lock())
        async with lock:
            prior = self.idempotency.get(scope)
            if prior:
                if prior.payload_hash != payload_hash:
                    self._audit(
                        "idempotency_conflict.rejected",
                        candidate,
                        correlation_id,
                        "conflict",
                        "CONFLICT",
                        ("PAYLOAD_HASH_MISMATCH",),
                        payload_hash,
                    )
                    raise SalesConflict(
                        "idempotency key was already used for another payload"
                    )
                self._audit(
                    "idempotent_replay.returned",
                    candidate,
                    prior.correlation_id,
                    str(prior.result["candidate_id"]),
                    "REPLAY",
                    ("IDEMPOTENT_REPLAY",),
                    payload_hash,
                )
                return LeadResolution.model_validate(prior.result), True
            candidate_id = f"LDC-{uuid4().hex}"
            self._audit(
                "lead_candidate.received",
                candidate,
                correlation_id,
                candidate_id,
                "RECEIVED",
                ("SCHEMA_VALID",),
                payload_hash,
            )
            try:
                lookup = await asyncio.wait_for(
                    self.odoo.lookup(candidate, limit=100), timeout=5
                )
            except (OdooReadUnavailable, TimeoutError):
                compliance = evaluate(
                    ComplianceSnapshot(
                        candidate.tenant_id, candidate.campaign_id, available=False
                    ),
                    candidate.tenant_id,
                    candidate.campaign_id,
                )
                resolution = LeadResolution(
                    candidate_id=candidate_id,
                    decision=Decision.MANUAL_REVIEW,
                    decision_code="ODOO_UNAVAILABLE",
                    company_resolution=MatchResolution(
                        matched=False, score=0, reasons=["ODOO_LOOKUP_UNAVAILABLE"]
                    ),
                    contact_resolution=MatchResolution(
                        matched=False, score=0, reasons=["ODOO_LOOKUP_UNAVAILABLE"]
                    ),
                    gates=compliance.gates,
                    rejection_reasons=["ODOO_UNAVAILABLE"],
                    manual_review_reasons=["ODOO_UNAVAILABLE"],
                    provider_validation_summaries={"odoo": "UNAVAILABLE"},
                    audit_reference=candidate_id,
                    review_required=True,
                    correlation_id=correlation_id,
                )
            else:
                company = best_company(candidate, lookup.companies)
                contact = best_contact(candidate, lookup.contacts, company)
                snapshot = lookup.compliance or ComplianceSnapshot(
                    candidate.tenant_id, candidate.campaign_id, available=False
                )
                compliance = evaluate(
                    snapshot, candidate.tenant_id, candidate.campaign_id
                )
                highest = max(company.score, contact.score)
                if compliance.blocked:
                    decision = Decision.SUPPRESSED
                elif highest >= self.policy.exact_threshold:
                    decision = Decision.EXACT_DUPLICATE
                elif highest >= self.policy.review_threshold:
                    decision = Decision.POSSIBLE_DUPLICATE
                elif compliance.review_required:
                    decision = Decision.MANUAL_REVIEW
                else:
                    decision = Decision.ACCEPTED
                review_required = (
                    compliance.review_required
                    or decision == Decision.POSSIBLE_DUPLICATE
                )
                resolution = LeadResolution(
                    candidate_id=candidate_id,
                    decision=decision,
                    decision_code=decision.value,
                    eligible_for_outreach=(
                        decision == Decision.ACCEPTED
                        and not compliance.blocked
                        and not compliance.review_required
                    ),
                    duplicate_status=(
                        "EXACT"
                        if decision == Decision.EXACT_DUPLICATE
                        else "POSSIBLE"
                        if decision == Decision.POSSIBLE_DUPLICATE
                        else "NONE"
                    ),
                    match_type=(
                        "EXACT"
                        if decision == Decision.EXACT_DUPLICATE
                        else "FUZZY"
                        if decision == Decision.POSSIBLE_DUPLICATE
                        else "NONE"
                    ),
                    matched_entity_references=[
                        value
                        for value in (company.public_id, contact.public_id)
                        if value
                    ],
                    match_confidence=highest,
                    company_resolution=MatchResolution(
                        matched=company.score >= self.policy.exact_threshold,
                        odoo_company_id=company.public_id,
                        score=company.score,
                        reasons=list(company.reasons),
                    ),
                    contact_resolution=MatchResolution(
                        matched=contact.score >= self.policy.exact_threshold,
                        odoo_lead_id=contact.public_id,
                        score=contact.score,
                        reasons=list(contact.reasons),
                    ),
                    gates=compliance.gates,
                    rejection_reasons=list(
                        compliance.reasons if compliance.blocked else ()
                    ),
                    manual_review_reasons=list(
                        compliance.reasons
                        if review_required and not compliance.blocked
                        else ()
                    ),
                    suppression_results=list(
                        compliance.reasons if compliance.blocked else ()
                    ),
                    consent_results=[
                        reason
                        for reason in compliance.reasons
                        if reason.startswith("CONSENT_")
                    ],
                    provider_validation_summaries={"odoo": "AVAILABLE"},
                    audit_reference=candidate_id,
                    review_required=review_required,
                    correlation_id=correlation_id,
                )
                if decision == Decision.POSSIBLE_DUPLICATE:
                    review = DuplicateReview(
                        f"LDR-{uuid4().hex}",
                        candidate.tenant_id,
                        candidate.campaign_id,
                        candidate_id,
                        company.public_id,
                        contact.public_id,
                        company.score,
                        contact.score,
                        company.reasons + contact.reasons,
                        tuple(
                            item.content_hash.removeprefix("sha256:")
                            for item in candidate.evidence
                        ),
                        self.policy.version,
                    )
                    self.reviews[review.review_id] = review
                    self._audit(
                        "duplicate_review.created",
                        candidate,
                        correlation_id,
                        review.review_id,
                        "PENDING",
                        review.match_reasons,
                        payload_hash,
                    )
            self.candidates[candidate_id] = candidate
            self.resolutions[candidate_id] = resolution
            self.idempotency[scope] = IdempotencyEntry(
                candidate.tenant_id,
                operation,
                key_hash,
                payload_hash,
                resolution.model_dump(mode="json"),
                correlation_id,
                datetime.now(UTC),
            )
            reasons = tuple(
                resolution.company_resolution.reasons
                + resolution.contact_resolution.reasons
                + resolution.rejection_reasons
            ) or ("ACCEPTED",)
            self._audit(
                "identity_resolution.completed",
                candidate,
                correlation_id,
                candidate_id,
                resolution.decision,
                reasons,
                payload_hash,
            )
            self._audit(
                "compliance_gate.evaluated",
                candidate,
                correlation_id,
                candidate_id,
                resolution.decision,
                tuple(resolution.rejection_reasons) or ("GATES_EVALUATED",),
                payload_hash,
            )
            return resolution, False

    async def create_job(
        self, request: VerificationJobRequest, idempotency_key: str, correlation_id: str
    ) -> tuple[VerificationJob, bool]:
        operation = "verification_job.create"
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        scope = (request.tenant_id, operation, key_hash)
        payload_hash = canonical_hash(request)
        lock = self.locks.setdefault(scope, asyncio.Lock())
        async with lock:
            prior = self.idempotency.get(scope)
            if prior:
                if prior.payload_hash != payload_hash:
                    raise SalesConflict(
                        "idempotency key was already used for another job payload"
                    )
                return self.jobs[str(prior.result["job_id"])], True
            job = VerificationJob(f"LVJ-{uuid4().hex}", request, correlation_id)
            self.jobs[job.job_id] = job
            self.idempotency[scope] = IdempotencyEntry(
                request.tenant_id,
                operation,
                key_hash,
                payload_hash,
                {"job_id": job.job_id},
                correlation_id,
                datetime.now(UTC),
            )
            await self.run_job(job)
            return job, False

    async def run_job(self, job: VerificationJob) -> None:
        job.state = VerificationJobState.RUNNING
        try:
            candidates = await asyncio.wait_for(
                self.odoo.verification_page(
                    job.request.tenant_id,
                    job.request.campaign_id,
                    offset=0,
                    limit=job.request.batch_size,
                ),
                timeout=10,
            )
        except (OdooReadUnavailable, TimeoutError):
            job.state = VerificationJobState.COMPLETED_WITH_WARNINGS
            job.warnings = 1
            job.results.append(
                {
                    "classification": "DEPENDENCY_UNAVAILABLE",
                    "reason_codes": ["ODOO_LOOKUP_UNAVAILABLE"],
                }
            )
            return
        job.total = len(candidates)
        for candidate in candidates:
            resolution, _ = await self.resolve(
                candidate,
                f"verification:{job.job_id}:{candidate.source.request_id}",
                job.correlation_id,
            )
            classification = {
                Decision.EXACT_DUPLICATE: "EXACT_DUPLICATE",
                Decision.POSSIBLE_DUPLICATE: "POSSIBLE_DUPLICATE",
                Decision.SUPPRESSED: "DNC_BLOCKED",
                Decision.ACCEPTED: "VERIFIED_VALID",
                Decision.MANUAL_REVIEW: "NEEDS_REVIEW",
            }.get(resolution.decision, "NEEDS_REVIEW")
            job.results.append(
                {
                    "candidate_id": resolution.candidate_id,
                    "classification": classification,
                    "reason_codes": resolution.rejection_reasons,
                }
            )
            job.processed += 1
        job.state = VerificationJobState.COMPLETED

    def cancel_job(self, job_id: str, tenant_id: str) -> VerificationJob:
        job = self.jobs.get(job_id)
        if not job or job.request.tenant_id != tenant_id:
            raise SalesError("verification job was not found")
        if job.state in {VerificationJobState.QUEUED, VerificationJobState.RUNNING}:
            job.state = VerificationJobState.CANCELED
        return job

    @staticmethod
    def job_document(
        job: VerificationJob, include_results: bool = False
    ) -> dict[str, Any]:
        document: dict[str, Any] = {
            "job_id": job.job_id,
            "state": job.state,
            "dry_run": True,
            "progress": {
                "total": job.total,
                "processed": job.processed,
                "warnings": job.warnings,
            },
            "correlation_id": job.correlation_id,
        }
        if include_results:
            document["results"] = job.results
        return document
