from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import AuditEvent
from app.core.config import settings
from app.db.session import SessionFactory

from .contracts import Decision, LeadCandidate, LeadResolution
from .normalization import (
    normalized_company_name,
    normalized_email,
    normalized_phone,
    registrable_domain,
)
from .service import (
    SalesConflict,
    SalesDependencyUnavailable,
    SalesLeadService,
    VerificationJob,
    canonical_hash,
)


class SalesRepository:
    """PostgreSQL durability boundary for intake, replay, review and audit."""

    def __init__(
        self, sessions: async_sessionmaker[AsyncSession] = SessionFactory
    ) -> None:
        self.sessions = sessions

    async def resolve(
        self,
        candidate: LeadCandidate,
        idempotency_key: str,
        correlation_id: str,
        engine: SalesLeadService,
        *,
        source_identity: str = "middleware-api",
        persist_scraper_inbox: bool = False,
    ) -> tuple[LeadResolution, bool]:
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        payload_hash = canonical_hash(candidate)
        operation = "lead_candidate.resolve"
        try:
            return await self._resolve_transaction(
                candidate,
                idempotency_key,
                correlation_id,
                engine,
                key_hash,
                payload_hash,
                operation,
                source_identity,
                persist_scraper_inbox,
            )
        except SQLAlchemyError as exc:
            raise SalesDependencyUnavailable(
                "sales persistence is unavailable"
            ) from exc

    async def _resolve_transaction(
        self,
        candidate: LeadCandidate,
        idempotency_key: str,
        correlation_id: str,
        engine: SalesLeadService,
        key_hash: str,
        payload_hash: str,
        operation: str,
        source_identity: str,
        persist_scraper_inbox: bool,
    ) -> tuple[LeadResolution, bool]:
        async with self.sessions() as session:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"{candidate.tenant_id}:{operation}:{key_hash}"},
            )
            prior = (
                (
                    await session.execute(
                        text(
                            "SELECT payload_hash,response_json FROM sales_idempotency "
                            "WHERE tenant_id=:tenant AND operation=:operation AND key_hash=:key"
                        ),
                        {
                            "tenant": candidate.tenant_id,
                            "operation": operation,
                            "key": key_hash,
                        },
                    )
                )
                .mappings()
                .first()
            )
            if prior:
                if prior["payload_hash"] != payload_hash:
                    raise SalesConflict(
                        "idempotency key was already used for another payload"
                    )
                return LeadResolution.model_validate(prior["response_json"]), True
            resolution, _ = await engine.resolve(
                candidate, idempotency_key, correlation_id
            )
            await self._persist_resolution(
                session,
                candidate,
                resolution,
                payload_hash,
                key_hash,
                source_identity=source_identity,
                persist_scraper_inbox=persist_scraper_inbox,
            )
            await session.commit()
            return resolution, False

    async def _persist_resolution(
        self,
        session: AsyncSession,
        candidate: LeadCandidate,
        resolution: LeadResolution,
        payload_hash: str,
        key_hash: str,
        *,
        source_identity: str,
        persist_scraper_inbox: bool,
    ) -> None:
        phone = normalized_phone(
            candidate.contact.business_phone, candidate.contact.country_code
        )
        normalized = {
            "company_name": normalized_company_name(candidate.company.name),
            "root_domain": registrable_domain(
                candidate.company.domain or candidate.company.website_url
            ),
            "business_email": normalized_email(candidate.contact.business_email),
            "business_phone": phone.e164 if phone else None,
            "phone_extension": phone.extension if phone else None,
            "country_code": candidate.company.country_code,
        }
        await session.execute(
            text(
                "INSERT INTO sales_lead_candidate "
                "(id,candidate_public_id,tenant_id,campaign_id,schema_version,source_provider,source_request_id,protected_payload_hash,normalized_identity) "
                "VALUES (:id,:public_id,:tenant,:campaign,:schema,:provider,:request_id,:hash,CAST(:normalized AS jsonb))"
            ),
            {
                "id": uuid4(),
                "public_id": resolution.candidate_id,
                "tenant": candidate.tenant_id,
                "campaign": candidate.campaign_id,
                "schema": candidate.schema_version,
                "provider": candidate.source.provider,
                "request_id": candidate.source.request_id,
                "hash": payload_hash,
                "normalized": json.dumps(normalized),
            },
        )
        reason_codes = (
            resolution.company_resolution.reasons
            + resolution.contact_resolution.reasons
            + resolution.rejection_reasons
        )
        await session.execute(
            text(
                "INSERT INTO sales_identity_resolution "
                "(id,candidate_public_id,tenant_id,decision,company_score,contact_score,odoo_company_public_id,odoo_lead_public_id,reason_codes,gate_results,policy_version,correlation_id) "
                "VALUES (:id,:candidate,:tenant,:decision,:company_score,:contact_score,:company_id,:lead_id,CAST(:reasons AS jsonb),CAST(:gates AS jsonb),:policy,:correlation)"
            ),
            {
                "id": uuid4(),
                "candidate": resolution.candidate_id,
                "tenant": candidate.tenant_id,
                "decision": resolution.decision,
                "company_score": resolution.company_resolution.score,
                "contact_score": resolution.contact_resolution.score,
                "company_id": resolution.company_resolution.odoo_company_id,
                "lead_id": resolution.contact_resolution.odoo_lead_id,
                "reasons": json.dumps(reason_codes),
                "gates": json.dumps(resolution.gates.model_dump(mode="json")),
                "policy": resolution.policy_version,
                "correlation": resolution.correlation_id,
            },
        )
        if resolution.decision == Decision.POSSIBLE_DUPLICATE:
            await session.execute(
                text(
                    "INSERT INTO sales_duplicate_review "
                    "(id,review_public_id,tenant_id,campaign_id,candidate_public_id,odoo_company_public_id,odoo_lead_public_id,company_score,contact_score,match_reason_codes,evidence_hashes,policy_version,review_state) "
                    "VALUES (:id,:review,:tenant,:campaign,:candidate,:company,:lead,:company_score,:contact_score,CAST(:reasons AS jsonb),CAST(:evidence AS jsonb),:policy,'PENDING')"
                ),
                {
                    "id": uuid4(),
                    "review": f"LDR-{uuid4().hex}",
                    "tenant": candidate.tenant_id,
                    "campaign": candidate.campaign_id,
                    "candidate": resolution.candidate_id,
                    "company": resolution.company_resolution.odoo_company_id,
                    "lead": resolution.contact_resolution.odoo_lead_id,
                    "company_score": resolution.company_resolution.score,
                    "contact_score": resolution.contact_resolution.score,
                    "reasons": json.dumps(reason_codes),
                    "evidence": json.dumps(
                        [
                            item.content_hash.removeprefix("sha256:")
                            for item in candidate.evidence
                        ]
                    ),
                    "policy": resolution.policy_version,
                },
            )
        response = resolution.model_dump(mode="json")
        await session.execute(
            text(
                "INSERT INTO sales_idempotency "
                "(id,tenant_id,operation,key_hash,payload_hash,result_reference,response_json,status,correlation_id,expires_at) "
                "VALUES (:id,:tenant,'lead_candidate.resolve',:key,:payload_hash,:reference,CAST(:response AS jsonb),'COMPLETED',:correlation,:expires)"
            ),
            {
                "id": uuid4(),
                "tenant": candidate.tenant_id,
                "key": key_hash,
                "payload_hash": payload_hash,
                "reference": resolution.candidate_id,
                "response": json.dumps(response),
                "correlation": resolution.correlation_id,
                "expires": datetime.now(UTC) + timedelta(days=30),
            },
        )
        reasons = reason_codes or ["NET_NEW"]
        delivery_queued = (
            settings.scraper_middleware_delivery_enabled
            and resolution.decision == Decision.ACCEPTED
            and candidate.campaign_id == "TEST_SYN"
        )
        inbox_status = (
            "queued"
            if delivery_queued
            else "eligible"
            if resolution.decision == Decision.ACCEPTED
            else "rejected"
        )
        if persist_scraper_inbox:
            await session.execute(
                text(
                    "INSERT INTO sales_scraper_inbox "
                    "(id,event_id,schema_version,tenant_id,source_identity,campaign_id,"
                    "payload_hash,idempotency_key_hash,correlation_id,status,rejection_code) "
                    "VALUES (:id,:event,:schema,:tenant,:source,:campaign,:payload_hash,"
                    ":key_hash,:correlation,:status,:rejection_code)"
                ),
                {
                    "id": uuid4(),
                    "event": candidate.source.request_id,
                    "schema": candidate.schema_version,
                    "tenant": candidate.tenant_id,
                    "source": source_identity,
                    "campaign": candidate.campaign_id,
                    "payload_hash": payload_hash,
                    "key_hash": key_hash,
                    "correlation": resolution.correlation_id,
                    "status": inbox_status,
                    "rejection_code": (
                        None
                        if inbox_status in {"eligible", "queued"}
                        else resolution.decision_code
                    ),
                },
            )
        redacted = {
            "tenant_id": candidate.tenant_id,
            "campaign_id": candidate.campaign_id,
            "reason_codes": reasons,
            "policy_version": resolution.policy_version,
            "protected_payload_hash": payload_hash,
            "source_provider": candidate.source.provider,
        }
        for action in (
            "lead_candidate.received",
            "identity_resolution.completed",
            "compliance_gate.evaluated",
        ):
            session.add(
                AuditEvent(
                    action=action,
                    subject=resolution.candidate_id,
                    correlation_id=resolution.correlation_id,
                    decision=resolution.decision,
                    redacted_payload=redacted,
                )
            )
        if delivery_queued:
            event_id = f"LAE-{resolution.candidate_id.removeprefix('LDC-')}"
            delivery_key = hashlib.sha256(
                f"{candidate.tenant_id}:{candidate.source.request_id}".encode()
            ).hexdigest()
            now = datetime.now(UTC).isoformat()
            contact_reference = "CONTACT-" + hashlib.sha256(
                f"{candidate.tenant_id}:{resolution.candidate_id}".encode()
            ).hexdigest()[:32]
            payload = {
                "contract_version": "1.1",
                "automation_event_id": event_id,
                "idempotency_key": delivery_key,
                "environment": settings.environment,
                "company_key": settings.scraper_odoo_company_key,
                "business_unit_key": settings.scraper_odoo_business_unit_key,
                "campaign_key": candidate.campaign_id,
                "automation_action": "CREATE_LEAD",
                "policy_version": resolution.policy_version,
                "correlation_id": resolution.correlation_id,
                "attributes_schema_key": "web-mobile-ai-lead-v1",
                "attributes": {"contact_reference": contact_reference},
                "consent_snapshot": {
                    "consent_status": "granted",
                    "consent_purpose": candidate.source_claims.consent_source
                    or "synthetic-canary",
                    "consent_source": candidate.source.provider,
                    "consent_updated_at": now,
                    "dnc_status": False,
                    "dnc_updated_at": now,
                    "jurisdiction": candidate.company.country_code,
                    "source_system": "odoo",
                },
                "workflow_execution_id": f"N8N-{resolution.candidate_id.removeprefix('LDC-')}",
                "result_code": "SCRAPER_VALIDATED",
                "source_reference": f"SRC-{hashlib.sha256(candidate.source.request_id.encode()).hexdigest()}",
            }
            await session.execute(
                text(
                    "INSERT INTO outbox_event "
                    "(id,topic,payload,correlation_id,status,attempts) "
                    "VALUES (:id,'sales.lead.odoo.apply',CAST(:payload AS jsonb),"
                    ":correlation,'pending',0)"
                ),
                {
                    "id": uuid4(),
                    "payload": json.dumps(payload),
                    "correlation": resolution.correlation_id,
                },
            )

    async def persist_job(self, job: VerificationJob) -> None:
        try:
            await self._persist_job_transaction(job)
        except SQLAlchemyError as exc:
            raise SalesDependencyUnavailable(
                "sales persistence is unavailable"
            ) from exc

    async def consume_scraper_nonce(
        self, scraper_id: str, tenant_id: str, nonce: str
    ) -> bool:
        nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
        try:
            async with self.sessions() as session:
                inserted = await session.scalar(
                    text(
                        "INSERT INTO sales_webhook_nonce "
                        "(id,scraper_id,nonce_hash,tenant_id,expires_at) "
                        "VALUES (:id,:scraper,:nonce,:tenant,:expires) "
                        "ON CONFLICT (scraper_id,nonce_hash) DO NOTHING RETURNING id"
                    ),
                    {
                        "id": uuid4(),
                        "scraper": scraper_id,
                        "nonce": nonce_hash,
                        "tenant": tenant_id,
                        "expires": datetime.now(UTC) + timedelta(minutes=5),
                    },
                )
                await session.commit()
                return inserted is not None
        except SQLAlchemyError as exc:
            raise SalesDependencyUnavailable(
                "scraper replay protection is unavailable"
            ) from exc

    async def _persist_job_transaction(self, job: VerificationJob) -> None:
        async with self.sessions() as session:
            await session.execute(
                text(
                    "INSERT INTO sales_verification_job "
                    "(id,job_public_id,tenant_id,campaign_id,state,filter_json,batch_size,total_count,processed_count,warning_count,correlation_id,completed_at) "
                    "VALUES (:id,:job,:tenant,:campaign,:state,CAST(:filters AS jsonb),:batch,:total,:processed,:warnings,:correlation,:completed)"
                ),
                {
                    "id": uuid4(),
                    "job": job.job_id,
                    "tenant": job.request.tenant_id,
                    "campaign": job.request.campaign_id,
                    "state": job.state,
                    "filters": json.dumps(job.request.filters.model_dump(mode="json")),
                    "batch": job.request.batch_size,
                    "total": job.total,
                    "processed": job.processed,
                    "warnings": job.warnings,
                    "correlation": job.correlation_id,
                    "completed": datetime.now(UTC),
                },
            )
            for result in job.results:
                await session.execute(
                    text(
                        "INSERT INTO sales_verification_result "
                        "(id,job_public_id,tenant_id,candidate_public_id,classification,reason_codes) "
                        "VALUES (:id,:job,:tenant,:candidate,:classification,CAST(:reasons AS jsonb))"
                    ),
                    {
                        "id": uuid4(),
                        "job": job.job_id,
                        "tenant": job.request.tenant_id,
                        "candidate": result.get("candidate_id"),
                        "classification": result["classification"],
                        "reasons": json.dumps(result.get("reason_codes", [])),
                    },
                )
            await session.commit()
