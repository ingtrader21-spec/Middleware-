"""Persistent, fail-closed campaign design previews.

This module deliberately has no VICIdial, n8n, messaging, or activation client.
Approval freezes a revision; it does not provision anything.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.campaign_design_contract import (
    CampaignDesignInput,
    LIST_RANGES,
    canonical,
    manifest_hash,
    build_manifest,
)


class DesignConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredDesign:
    revision: int
    manifest: dict[str, Any]
    payload_hash: str
    manifest_hash: str
    approval_state: str


@dataclass(frozen=True)
class StoredApproval:
    approval_id: str
    integration_uuid: str
    design_revision: int
    manifest_hash: str
    approver_subject: str
    reason: str
    approved_at: datetime
    idempotency_key: str
    correlation_id: str


class DesignStore(Protocol):
    async def consume_atomic(
        self, request: CampaignDesignInput
    ) -> tuple[StoredDesign, bool]: ...

    async def record_failure(
        self, request: CampaignDesignInput, error: str, max_attempts: int
    ) -> str: ...

    async def approve(
        self,
        integration_uuid: str,
        revision: int,
        manifest_hash: str,
        actor: str,
        reason: str,
        idempotency_key: str,
        correlation_id: str,
        *,
        business_unit: str,
        environment: str,
        tenant_id: str,
    ) -> tuple[StoredDesign, StoredApproval]: ...


class CampaignDesignService:
    def __init__(self, store: DesignStore):
        self.store = store

    async def consume(
        self, request: CampaignDesignInput, *, max_attempts: int = 3
    ) -> dict[str, Any]:
        try:
            stored, replay = await self.store.consume_atomic(request)
            return {
                "manifest": stored.manifest,
                "design_revision": stored.revision,
                "manifest_hash": stored.manifest_hash,
                "validation_errors": stored.manifest.get("validation_errors", []),
                "idempotent_replay": replay,
            }
        except DesignConflict:
            raise
        except Exception as exc:
            await self.store.record_failure(request, type(exc).__name__, max_attempts)
            raise

    async def approve(
        self,
        integration_uuid: str,
        revision: int,
        expected_manifest_hash: str,
        actor: str,
        reason: str,
        idempotency_key: str,
        correlation_id: str,
        *,
        business_unit: str,
        environment: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        stored, approval = await self.store.approve(
            integration_uuid,
            revision,
            expected_manifest_hash,
            actor,
            reason,
            idempotency_key,
            correlation_id,
            business_unit=business_unit,
            environment=environment,
            tenant_id=tenant_id,
        )
        result = dict(stored.manifest)
        result["approval"] = {
            "state": "approved",
            "actor": approval.approver_subject,
            "reason": approval.reason,
            "approved_at": approval.approved_at.isoformat(),
            "idempotency_key": approval.idempotency_key,
            "correlation_id": approval.correlation_id,
            "provisioning_authorized": False,
        }
        result["lifecycle"] = {
            "state": "approved",
            "history": [
                "draft",
                "design_pending",
                "design_ready",
                "approval_pending",
                "approved",
            ],
            "next_state": "provisioning_pending",
            "adapter_delivery_enabled": False,
        }
        return result


class PostgresDesignStore:
    def __init__(
        self,
        db: AsyncSession,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ):
        self.db = db
        self.fault_hook = fault_hook

    def _fault(self, point: str) -> None:
        if self.fault_hook:
            self.fault_hook(point)

    @staticmethod
    def _stored(row: Any) -> StoredDesign:
        return StoredDesign(
            revision=row["revision"],
            manifest=row["manifest"],
            payload_hash=row["payload_hash"],
            manifest_hash=row["manifest_hash"],
            approval_state=row["approval_state"],
        )

    async def consume_atomic(
        self, request: CampaignDesignInput
    ) -> tuple[StoredDesign, bool]:
        if not request.tenant_id:
            raise DesignConflict("campaign tenant binding is required")
        payload_hash = request.payload_hash()
        try:
            async with self.db.begin():
                failure = (
                    (
                        await self.db.execute(
                            text(
                                "SELECT payload_hash,status,"
                                "(next_attempt_at IS NULL OR next_attempt_at <= now()) "
                                "AS retry_due FROM campaign_design_failure "
                                "WHERE event_id=:event FOR UPDATE"
                            ),
                            {"event": request.event_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if failure:
                    if failure["payload_hash"] != payload_hash:
                        raise DesignConflict("failed event replay payload conflict")
                    if failure["status"] == "dead_letter":
                        raise DesignConflict(
                            "event is dead-lettered; explicit reset required"
                        )
                    if not failure["retry_due"]:
                        raise DesignConflict("event retry is deferred")

                inserted = await self.db.scalar(
                    text(
                        "INSERT INTO campaign_event_inbox"
                        "(event_id,integration_uuid,payload_hash,processing_state,"
                        "correlation_id) "
                        "VALUES(:event,:uuid,:hash,'processing',:correlation) "
                        "ON CONFLICT(event_id) DO NOTHING RETURNING event_id"
                    ),
                    {
                        "event": request.event_id,
                        "uuid": request.integration_uuid,
                        "hash": payload_hash,
                        "correlation": request.correlation_id,
                    },
                )
                if inserted is None:
                    receipt = (
                        (
                            await self.db.execute(
                                text(
                                    "SELECT payload_hash,processing_state,result_revision "
                                    "FROM campaign_event_inbox WHERE event_id=:event "
                                    "FOR UPDATE"
                                ),
                                {"event": request.event_id},
                            )
                        )
                        .mappings()
                        .one()
                    )
                    if receipt["payload_hash"] != payload_hash:
                        raise DesignConflict("event replay payload conflict")
                    if receipt["processing_state"] != "completed":
                        raise RuntimeError("event receipt is not committed")
                    row = (
                        (
                            await self.db.execute(
                                text(
                                    "SELECT revision,manifest,payload_hash,manifest_hash,"
                                    "approval_state FROM campaign_design_revision "
                                    "WHERE integration_uuid=:uuid AND revision=:revision"
                                ),
                                {
                                    "uuid": request.integration_uuid,
                                    "revision": receipt["result_revision"],
                                },
                            )
                        )
                        .mappings()
                        .one()
                    )
                    return self._stored(row), True

                self._fault("after_receipt")
                await self.db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:scope))"),
                    {"scope": f"campaign-design:{request.integration_uuid}"},
                )
                current = (
                    (
                        await self.db.execute(
                            text(
                                "SELECT current.revision,current.lifecycle_state,"
                                "revision.manifest,revision.payload_hash,"
                                "revision.manifest_hash,revision.approval_state "
                                "FROM campaign_design_current current "
                                "JOIN campaign_design_revision revision "
                                "ON revision.integration_uuid=current.integration_uuid "
                                "AND revision.revision=current.revision "
                                "WHERE current.integration_uuid=:uuid FOR UPDATE"
                            ),
                            {"uuid": request.integration_uuid},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if current:
                    prior = current["manifest"]
                    if (
                        prior.get("tenant_id") != request.tenant_id
                        or prior["business_unit"] != request.business_unit
                        or prior["environment"] != request.environment
                        or prior["odoo"]["campaign_id"] != request.odoo_campaign_id
                    ):
                        raise DesignConflict("immutable campaign scope conflict")
                if current and current["payload_hash"] == payload_hash:
                    stored = self._stored(current)
                    await self._complete_receipt(request, stored, replay=True)
                    return stored, True
                revision = int(current["revision"]) + 1 if current else 1
                if request.design_request_revision != revision:
                    raise DesignConflict("campaign design revision is stale or skipped")
                low, high = LIST_RANGES[request.business_unit]
                await self.db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:scope))"),
                    {
                        "scope": (
                            f"campaign-list:{request.environment}:"
                            f"{LIST_RANGES[request.business_unit][0]}"
                        )
                    },
                )
                list_id = await self.db.scalar(
                    text(
                        "SELECT candidate FROM generate_series("
                        "CAST(:low AS integer),CAST(:high AS integer)) candidate "
                        "WHERE NOT EXISTS (SELECT 1 FROM campaign_resource_allocation "
                        "WHERE environment=:environment "
                        "AND resource_type='vicidial_list' "
                        "AND reserved_identifier=candidate::text) "
                        "ORDER BY candidate LIMIT 1"
                    ),
                    {
                        "low": low,
                        "high": high,
                        "environment": request.environment,
                    },
                )
                if list_id is None:
                    raise DesignConflict("list range exhausted")
                manifest = build_manifest(request, revision, int(list_id))
                manifest_digest = manifest_hash(manifest)
                await self.db.execute(
                    text(
                        "INSERT INTO campaign_resource_allocation"
                        "(environment,resource_type,reserved_identifier,"
                        "business_unit,integration_uuid,revision) "
                        "VALUES(:environment,'vicidial_list',:identifier,"
                        ":unit,:uuid,:revision)"
                    ),
                    {
                        "environment": request.environment,
                        "identifier": str(list_id),
                        "unit": request.business_unit,
                        "uuid": request.integration_uuid,
                        "revision": revision,
                    },
                )
                self._fault("after_allocation")
                await self.db.execute(
                    text(
                        "INSERT INTO campaign_design_revision"
                        "(integration_uuid,revision,payload_hash,manifest_hash,"
                        "manifest,approval_state) "
                        "VALUES(:uuid,:revision,:payload_hash,:manifest_hash,"
                        "CAST(:manifest AS jsonb),'preview')"
                    ),
                    {
                        "uuid": request.integration_uuid,
                        "revision": revision,
                        "payload_hash": payload_hash,
                        "manifest_hash": manifest_digest,
                        "manifest": canonical(manifest),
                    },
                )
                self._fault("after_revision")
                await self.db.execute(
                    text(
                        "INSERT INTO campaign_design_current"
                        "(integration_uuid,revision,manifest_hash,lifecycle_state,"
                        "odoo_campaign_id) "
                        "VALUES(:uuid,:revision,:manifest_hash,'approval_pending',"
                        ":odoo_campaign_id) "
                        "ON CONFLICT(integration_uuid) DO UPDATE SET "
                        "revision=excluded.revision,"
                        "manifest_hash=excluded.manifest_hash,"
                        "lifecycle_state=excluded.lifecycle_state,"
                        "odoo_campaign_id=excluded.odoo_campaign_id,"
                        "updated_at=now()"
                    ),
                    {
                        "uuid": request.integration_uuid,
                        "revision": revision,
                        "manifest_hash": manifest_digest,
                        "odoo_campaign_id": request.odoo_campaign_id,
                    },
                )
                stored = StoredDesign(
                    revision,
                    manifest,
                    payload_hash,
                    manifest_digest,
                    "preview",
                )
                await self._complete_receipt(request, stored, replay=False)
                await self.db.execute(
                    text("DELETE FROM campaign_design_failure WHERE event_id=:event"),
                    {"event": request.event_id},
                )
                return stored, False
        except Exception:
            await self.db.rollback()
            raise

    async def _complete_receipt(
        self,
        request: CampaignDesignInput,
        stored: StoredDesign,
        *,
        replay: bool,
    ) -> None:
        await self.db.execute(
            text(
                "UPDATE campaign_event_inbox SET processing_state='completed',"
                "result_revision=:revision,committed_at=now() "
                "WHERE event_id=:event"
            ),
            {"revision": stored.revision, "event": request.event_id},
        )
        await self.db.execute(
            text(
                "INSERT INTO audit_event"
                "(id,action,subject,correlation_id,decision,redacted_payload) "
                "VALUES(:id,'campaign.design.consumed',:subject,:correlation,"
                "'completed',CAST(:payload AS jsonb))"
            ),
            {
                "id": uuid4(),
                "subject": request.integration_uuid,
                "correlation": request.correlation_id,
                "payload": canonical(
                    {
                        "event_id_hash": hashlib.sha256(
                            request.event_id.encode()
                        ).hexdigest(),
                        "business_unit": request.business_unit,
                        "revision": stored.revision,
                        "reused_design": replay,
                    }
                ),
            },
        )
        self._fault("before_commit")

    async def record_failure(
        self, request: CampaignDesignInput, error: str, max_attempts: int
    ) -> str:
        await self.db.rollback()
        row = (
            await self.db.execute(
                text(
                    "INSERT INTO campaign_design_failure"
                    "(event_id,payload_hash,attempts,status,last_error,"
                    "next_attempt_at,correlation_id) "
                    "VALUES(:event,:hash,1,'retry',:error,now(),:correlation) "
                    "ON CONFLICT(event_id) DO UPDATE SET "
                    "attempts=campaign_design_failure.attempts+1,"
                    "last_error=excluded.last_error "
                    "WHERE campaign_design_failure.payload_hash="
                    "excluded.payload_hash RETURNING attempts"
                ),
                {
                    "event": request.event_id,
                    "hash": request.payload_hash(),
                    "error": error[:128],
                    "correlation": request.correlation_id,
                },
            )
        ).scalar_one_or_none()
        if row is None:
            await self.db.rollback()
            raise DesignConflict("failed event replay payload conflict")
        status = "dead_letter" if row >= max_attempts else "retry"
        next_attempt_at = (
            None
            if status == "dead_letter"
            else datetime.now(UTC) + timedelta(seconds=min(300, 2 ** max(0, row - 1)))
        )
        await self.db.execute(
            text(
                "UPDATE campaign_design_failure SET status=:status,"
                "next_attempt_at=:next_attempt_at WHERE event_id=:event"
            ),
            {
                "status": status,
                "next_attempt_at": next_attempt_at,
                "event": request.event_id,
            },
        )
        await self.db.commit()
        return status

    async def approve(
        self,
        integration_uuid: str,
        revision: int,
        expected_manifest_hash: str,
        actor: str,
        reason: str,
        idempotency_key: str,
        correlation_id: str,
        *,
        business_unit: str,
        environment: str,
        tenant_id: str,
    ) -> tuple[StoredDesign, StoredApproval]:
        try:
            async with self.db.begin():
                await self.db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:scope))"),
                    {"scope": f"campaign-approval-key:{idempotency_key}"},
                )
                current = (
                    (
                        await self.db.execute(
                            text(
                                "SELECT current.revision,current.manifest_hash,"
                                "current.lifecycle_state,revision.manifest,"
                                "revision.payload_hash,revision.approval_state "
                                "FROM campaign_design_current current "
                                "JOIN campaign_design_revision revision "
                                "ON revision.integration_uuid=current.integration_uuid "
                                "AND revision.revision=current.revision "
                                "WHERE current.integration_uuid=:uuid FOR UPDATE"
                            ),
                            {"uuid": integration_uuid},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if not current:
                    raise DesignConflict("design revision missing or immutable")
                if (
                    current["manifest"].get("tenant_id") != tenant_id
                    or current["manifest"]["business_unit"] != business_unit
                    or current["manifest"]["environment"] != environment
                ):
                    raise DesignConflict("campaign approval scope conflict")
                replay = (
                    (
                        await self.db.execute(
                            text(
                                "SELECT approval_id,integration_uuid,design_revision,"
                                "manifest_hash,approver_subject,reason,approved_at,"
                                "idempotency_key,correlation_id "
                                "FROM campaign_design_approval "
                                "WHERE idempotency_key=:key"
                            ),
                            {"key": idempotency_key},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if replay:
                    approval = StoredApproval(**dict(replay))
                    expected = (
                        integration_uuid,
                        revision,
                        expected_manifest_hash,
                        actor,
                        reason,
                        correlation_id,
                    )
                    actual = (
                        approval.integration_uuid,
                        approval.design_revision,
                        approval.manifest_hash,
                        approval.approver_subject,
                        approval.reason,
                        approval.correlation_id,
                    )
                    if actual != expected:
                        raise DesignConflict("approval idempotency payload conflict")
                    row = await self._design_row(integration_uuid, revision)
                    return self._stored(row), approval
                if current["manifest"].get("validation_errors"):
                    raise DesignConflict("campaign design validation is incomplete")
                if (
                    current["revision"] != revision
                    or current["manifest_hash"] != expected_manifest_hash
                ):
                    raise DesignConflict("approval revision or manifest conflict")
                if (
                    current["lifecycle_state"] != "approval_pending"
                    or current["approval_state"] != "preview"
                ):
                    raise DesignConflict("design revision already approved")

                approval_id = str(uuid4())
                approval_row = (
                    (
                        await self.db.execute(
                            text(
                                "INSERT INTO campaign_design_approval"
                                "(approval_id,integration_uuid,design_revision,"
                                "manifest_hash,approver_subject,reason,idempotency_key,"
                                "correlation_id) "
                                "VALUES(:approval_id,:uuid,:revision,:manifest_hash,"
                                ":actor,:reason,:key,:correlation) "
                                "RETURNING approval_id,integration_uuid,design_revision,"
                                "manifest_hash,approver_subject,reason,approved_at,"
                                "idempotency_key,correlation_id"
                            ),
                            {
                                "approval_id": approval_id,
                                "uuid": integration_uuid,
                                "revision": revision,
                                "manifest_hash": expected_manifest_hash,
                                "actor": actor,
                                "reason": reason,
                                "key": idempotency_key,
                                "correlation": correlation_id,
                            },
                        )
                    )
                    .mappings()
                    .one()
                )
                changed = await self.db.scalar(
                    text(
                        "UPDATE campaign_design_revision "
                        "SET approval_state='approved' "
                        "WHERE integration_uuid=:uuid AND revision=:revision "
                        "AND manifest_hash=:manifest_hash "
                        "AND approval_state='preview' RETURNING revision"
                    ),
                    {
                        "uuid": integration_uuid,
                        "revision": revision,
                        "manifest_hash": expected_manifest_hash,
                    },
                )
                if changed is None:
                    raise DesignConflict("approval compare-and-set failed")
                await self.db.execute(
                    text(
                        "UPDATE campaign_design_current "
                        "SET lifecycle_state='approved',updated_at=now() "
                        "WHERE integration_uuid=:uuid AND revision=:revision "
                        "AND lifecycle_state='approval_pending'"
                    ),
                    {"uuid": integration_uuid, "revision": revision},
                )
                await self.db.execute(
                    text(
                        "INSERT INTO audit_event"
                        "(id,action,subject,correlation_id,decision,"
                        "redacted_payload) "
                        "VALUES(:id,'campaign.design.approved',:subject,"
                        ":correlation,'approved',CAST(:payload AS jsonb))"
                    ),
                    {
                        "id": uuid4(),
                        "subject": integration_uuid,
                        "correlation": correlation_id,
                        "payload": canonical(
                            {
                                "approval_id": approval_id,
                                "revision": revision,
                                "manifest_hash": expected_manifest_hash,
                                "actor_hash": hashlib.sha256(
                                    actor.encode()
                                ).hexdigest(),
                            }
                        ),
                    },
                )
                row = await self._design_row(integration_uuid, revision)
                return self._stored(row), StoredApproval(**dict(approval_row))
        except Exception:
            await self.db.rollback()
            raise

    async def _design_row(self, integration_uuid: str, revision: int) -> Any:
        return (
            (
                await self.db.execute(
                    text(
                        "SELECT revision,manifest,payload_hash,manifest_hash,"
                        "approval_state FROM campaign_design_revision "
                        "WHERE integration_uuid=:uuid AND revision=:revision"
                    ),
                    {"uuid": integration_uuid, "revision": revision},
                )
            )
            .mappings()
            .one()
        )
