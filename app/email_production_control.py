from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal
from uuid import uuid4

import asyncpg
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from .api_inputs import authenticated_tenant, required_header
from .communications import (
    CommunicationsConflict,
    CommunicationsError,
    CommunicationsService,
    CreateMessageRequest,
)
from app.core.config import Settings
from .security import AuthorizationError, RequestValidationError
from .storage import ZERO_LEDGER_HASH, canonical_payload_sha256, event_ledger_hash


ROOT = Path(__file__).resolve().parents[1]
DOMAIN_REGISTRY_PATH = ROOT / "config" / "postal-domain-registry.json"
PRODUCTION_OPERATOR_CLIENT_ID = "production-operator"
POLICY_EVENT = "codestra.email.production.policy.changed"
QUOTA_RESERVED_EVENT = "codestra.email.production.quota.reserved"
QUOTA_RELEASED_EVENT = "codestra.email.production.quota.released"

ProductionMode = Literal[
    "SAFE",
    "TRANSACTIONAL_CANARY",
    "TRANSACTIONAL_PRODUCTION",
    "CAMPAIGN_PRODUCTION",
]
AuthorizationState = Literal[
    "NOT_AUTHORIZED",
    "AUTHORIZED_NOT_ACTIVE",
    "ACTIVE",
    "REVOKED",
]
RecipientScope = Literal[
    "DENY_ALL",
    "ALLOWLIST",
    "DOMAIN_ALLOWLIST",
    "TRANSACTIONAL_ANY",
    "CONSENTED_MARKETING",
]


class EmailProductionBlocked(CommunicationsError):
    status_code = 403
    code = "email_production_blocked"


class EmailProductionUnavailable(CommunicationsError):
    status_code = 503
    code = "email_production_unavailable"
    retryable = True


class EmailProductionRateLimited(CommunicationsError):
    status_code = 429
    code = "email_production_quota_exhausted"
    retryable = True


class EmailProductionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenantId: str
    enabled: bool = False
    mode: ProductionMode = "SAFE"
    authorizationState: AuthorizationState = "NOT_AUTHORIZED"
    approvedDomains: list[str] = Field(default_factory=list, max_length=100)
    approvedSenders: list[str] = Field(default_factory=list, max_length=500)
    recipientScope: RecipientScope = "DENY_ALL"
    approvedRecipients: list[str] = Field(default_factory=list, max_length=500)
    approvedRecipientDomains: list[str] = Field(default_factory=list, max_length=100)
    approvedCategories: list[str] = Field(default_factory=list, max_length=100)
    perMinuteLimit: int = Field(default=0, ge=0, le=100_000)
    perHourLimit: int = Field(default=0, ge=0, le=1_000_000)
    perDayLimit: int = Field(default=0, ge=0, le=10_000_000)
    validFrom: datetime | None = None
    validUntil: datetime | None = None
    changeId: str | None = Field(default=None, max_length=200)
    approvedBy: str | None = Field(default=None, max_length=300)
    activatedBy: str | None = Field(default=None, max_length=300)
    productionOwner: str | None = Field(default=None, max_length=300)
    monitoringOwner: str | None = Field(default=None, max_length=300)
    escalationOwner: str | None = Field(default=None, max_length=300)
    rollbackOwner: str | None = Field(default=None, max_length=300)
    killSwitchProcedure: str | None = Field(default=None, max_length=4000)
    provider: str | None = Field(default=None, max_length=100)
    environment: str | None = Field(default=None, max_length=32)
    approvedReleaseSha: str | None = Field(default=None, max_length=64)
    authorizationTimestamp: datetime | None = None
    activationTimestamp: datetime | None = None
    killSwitchOpen: bool = False
    version: int = Field(default=1, ge=1)
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("approvedDomains", "approvedRecipientDomains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            domain = value.strip().lower().rstrip(".")
            if (
                not domain
                or len(domain) > 253
                or "@" in domain
                or domain.startswith(".")
                or domain.endswith(".")
            ):
                raise ValueError("invalid approved domain")
            normalized.append(domain)
        if len(set(normalized)) != len(normalized):
            raise ValueError("approved domains must be unique")
        return normalized

    @field_validator("approvedSenders", "approvedRecipients")
    @classmethod
    def normalize_addresses(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().lower() for value in values]
        if any(not value or value.count("@") != 1 for value in normalized):
            raise ValueError("invalid email address")
        if len(set(normalized)) != len(normalized):
            raise ValueError("email addresses must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_window(self) -> "EmailProductionPolicy":
        if self.validFrom and self.validFrom.tzinfo is None:
            raise ValueError("validFrom must be timezone-aware")
        if self.validUntil and self.validUntil.tzinfo is None:
            raise ValueError("validUntil must be timezone-aware")
        if self.validFrom and self.validUntil and self.validUntil <= self.validFrom:
            raise ValueError("validUntil must be after validFrom")
        if self.approvedReleaseSha and not re.fullmatch(
            r"[0-9a-f]{40}", self.approvedReleaseSha
        ):
            raise ValueError("approvedReleaseSha must be an exact SHA-1")
        return self


class AuthorizeEmailProduction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expectedVersion: int = Field(ge=1)
    mode: Literal[
        "TRANSACTIONAL_CANARY",
        "TRANSACTIONAL_PRODUCTION",
        "CAMPAIGN_PRODUCTION",
    ]
    approvedDomains: list[str] = Field(min_length=1, max_length=100)
    approvedSenders: list[EmailStr] = Field(min_length=1, max_length=500)
    recipientScope: RecipientScope
    approvedRecipients: list[EmailStr] = Field(default_factory=list, max_length=500)
    approvedRecipientDomains: list[str] = Field(default_factory=list, max_length=100)
    approvedCategories: list[str] = Field(min_length=1, max_length=100)
    perMinuteLimit: int = Field(ge=1, le=100_000)
    perHourLimit: int = Field(ge=1, le=1_000_000)
    perDayLimit: int = Field(ge=1, le=10_000_000)
    validFrom: datetime
    validUntil: datetime
    changeId: str = Field(min_length=3, max_length=200)
    productionOwner: str = Field(min_length=1, max_length=300)
    monitoringOwner: str = Field(min_length=1, max_length=300)
    escalationOwner: str = Field(min_length=1, max_length=300)
    rollbackOwner: str = Field(min_length=1, max_length=300)
    killSwitchProcedure: str = Field(min_length=10, max_length=4000)
    provider: Literal["klyrow-postal"]
    environment: Literal["staging", "production"]
    approvedReleaseSha: str = Field(pattern=r"^[0-9a-f]{40}$")
    reason: str = Field(min_length=3, max_length=500)

    @model_validator(mode="after")
    def validate_scope(self) -> "AuthorizeEmailProduction":
        if self.perMinuteLimit > self.perHourLimit or self.perHourLimit > self.perDayLimit:
            raise ValueError("quota limits must be monotonic")
        if self.mode == "TRANSACTIONAL_CANARY":
            if (
                self.recipientScope != "ALLOWLIST"
                or not self.approvedRecipients
                or self.approvedRecipientDomains
            ):
                raise ValueError("canary mode requires an explicit recipient allowlist")
        elif self.mode == "TRANSACTIONAL_PRODUCTION":
            if self.recipientScope == "ALLOWLIST":
                if not self.approvedRecipients or self.approvedRecipientDomains:
                    raise ValueError("transactional allowlist requires approved recipients")
            elif self.recipientScope == "DOMAIN_ALLOWLIST":
                if not self.approvedRecipientDomains or self.approvedRecipients:
                    raise ValueError("transactional domain scope requires approved recipient domains")
            else:
                raise ValueError("transactional production requires a bounded recipient scope")
        else:
            raise ValueError("campaign production requires its separate compliance gate")
        categories = [value.strip().lower() for value in self.approvedCategories]
        if len(set(categories)) != len(categories) or any(
            not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,119}", value)
            for value in categories
        ):
            raise ValueError("approved categories are invalid or duplicated")
        if "marketing" in categories:
            raise ValueError("marketing category requires its separate compliance gate")
        # Transactional production is intentionally a closed vocabulary.  A
        # free-form category could accidentally authorize campaign-like mail
        # under a non-marketing label and bypass the separate compliance gate.
        allowed_transactional = {
            "transactional", "account", "security", "trading", "funds",
            "statements", "support", "system", "service",
        }
        if self.mode in {"TRANSACTIONAL_CANARY", "TRANSACTIONAL_PRODUCTION"}:
            unknown = sorted(set(categories) - allowed_transactional)
            if unknown:
                raise ValueError(
                    "unsupported transactional categories: " + ",".join(unknown)
                )
        recipient_domains = [
            value.strip().lower().rstrip(".") for value in self.approvedRecipientDomains
        ]
        if len(set(recipient_domains)) != len(recipient_domains) or any(
            not value or "@" in value or len(value) > 253
            for value in recipient_domains
        ):
            raise ValueError("approved recipient domains are invalid or duplicated")
        self.approvedCategories = categories
        self.approvedRecipientDomains = recipient_domains
        if self.validFrom.tzinfo is None:
            raise ValueError("validFrom must be timezone-aware")
        if self.validUntil.tzinfo is None:
            raise ValueError("validUntil must be timezone-aware")
        if self.validUntil <= self.validFrom:
            raise ValueError("validUntil must be after validFrom")
        return self


class ControlMutation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expectedVersion: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)


class KillSwitchMutation(ControlMutation):
    open: bool


@dataclass(frozen=True)
class QuotaReservation:
    tenant_id: str
    reservation_id: str
    units: int
    reserved_at: datetime


@dataclass
class MemoryEmailProductionPolicyStore:
    policies: dict[str, EmailProductionPolicy] = field(default_factory=dict)
    mutations: dict[tuple[str, str, str, str], tuple[str, dict[str, Any]]] = field(
        default_factory=dict
    )
    audits: list[dict[str, Any]] = field(default_factory=list)
    quota_reservations: dict[str, QuotaReservation] = field(default_factory=dict)
    quota_releases: set[str] = field(default_factory=set)

    async def get(self, tenant_id: str) -> EmailProductionPolicy:
        policy = self.policies.get(tenant_id)
        if policy is None:
            return EmailProductionPolicy(tenantId=tenant_id)
        return policy.model_copy(deep=True)

    async def mutate(
        self,
        tenant_id: str,
        *,
        actor: str,
        correlation_id: str,
        idempotency_key: str,
        action: str,
        expected_version: int,
        reason: str,
        request_sha256: str,
        transform: Callable[[EmailProductionPolicy], EmailProductionPolicy],
    ) -> EmailProductionPolicy:
        mutation_key = (tenant_id, action, actor, idempotency_key)
        prior = self.mutations.get(mutation_key)
        if prior is not None:
            if prior[0] != request_sha256:
                raise CommunicationsConflict(
                    "Idempotency-Key was reused with different production-control content"
                )
            return EmailProductionPolicy.model_validate(prior[1])
        current = await self.get(tenant_id)
        if current.version != expected_version:
            raise CommunicationsConflict("expectedVersion is stale")
        changed = EmailProductionPolicy.model_validate(
            transform(current).model_copy(
                update={"version": current.version + 1, "updatedAt": datetime.now(UTC)}
            ).model_dump(mode="json")
        )
        self.policies[tenant_id] = changed.model_copy(deep=True)
        response = changed.model_dump(mode="json")
        self.mutations[mutation_key] = (request_sha256, response)
        self.audits.append(
            {
                "tenant_id": tenant_id,
                "action": action,
                "actor_id": actor,
                "reason": reason,
                "correlation_id": correlation_id,
                "previous_policy": current.model_dump(mode="json"),
                "new_policy": response,
                "created_at": datetime.now(UTC),
            }
        )
        return changed.model_copy(deep=True)

    async def reserve_quota(
        self, tenant_id: str, units: int, policy: EmailProductionPolicy
    ) -> QuotaReservation:
        reserved_at = datetime.now(UTC)
        usage = self._usage(tenant_id, reserved_at)
        limits = {
            "minute": policy.perMinuteLimit,
            "hour": policy.perHourLimit,
            "day": policy.perDayLimit,
        }
        for window, used in usage.items():
            if used + units > limits[window]:
                raise EmailProductionRateLimited(f"{window} email quota is exhausted")
        reservation = QuotaReservation(
            tenant_id=tenant_id,
            reservation_id=str(uuid4()),
            units=units,
            reserved_at=reserved_at,
        )
        self.quota_reservations[reservation.reservation_id] = reservation
        return reservation

    async def release_quota(self, reservation: QuotaReservation) -> None:
        self.quota_releases.add(reservation.reservation_id)

    def _usage(self, tenant_id: str, now: datetime) -> dict[str, int]:
        cutoffs = _quota_cutoffs(now)
        result = {"minute": 0, "hour": 0, "day": 0}
        for reservation in self.quota_reservations.values():
            if (
                reservation.tenant_id != tenant_id
                or reservation.reservation_id in self.quota_releases
            ):
                continue
            for window, cutoff in cutoffs.items():
                if reservation.reserved_at >= cutoff:
                    result[window] += reservation.units
        return result

    async def quota_status(self, tenant_id: str) -> dict[str, int]:
        return self._usage(tenant_id, datetime.now(UTC))

    async def audit(self, tenant_id: str, limit: int) -> list[dict[str, Any]]:
        return [
            item for item in reversed(self.audits) if item["tenant_id"] == tenant_id
        ][:limit]


@dataclass
class PostgresEmailProductionPolicyStore:
    """Event-sourced production control using the existing immutable ledger.

    This deliberately reuses middleware_event_ledger rather than inserting a new
    SQL migration behind the protected production migration-history authority.
    Policy mutations, quota reservations, releases, and audit history are all
    append-only hash-chained events. A per-tenant PostgreSQL advisory transaction
    lock makes mutation versions and quota decisions atomic.
    """

    pool: asyncpg.Pool

    @staticmethod
    def _decode_payload(value: Any) -> dict[str, Any]:
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, dict):
            raise EmailProductionUnavailable("production-control ledger payload is invalid")
        return dict(value)

    async def _latest_policy(
        self, conn: asyncpg.Connection, tenant_id: str
    ) -> EmailProductionPolicy:
        row = await conn.fetchrow(
            """SELECT payload FROM middleware_event_ledger
               WHERE tenant_id=$1 AND event_type=$2
               ORDER BY tenant_sequence DESC LIMIT 1""",
            tenant_id,
            POLICY_EVENT,
        )
        if row is None:
            return EmailProductionPolicy(tenantId=tenant_id)
        document = self._decode_payload(row["payload"])
        policy = document.get("policy")
        if not isinstance(policy, dict):
            raise EmailProductionUnavailable("production-control policy event is invalid")
        return EmailProductionPolicy.model_validate(policy)

    async def get(self, tenant_id: str) -> EmailProductionPolicy:
        async with self.pool.acquire() as conn:
            return await self._latest_policy(conn, tenant_id)

    async def _append_event(
        self,
        conn: asyncpg.Connection,
        *,
        tenant_id: str,
        event_type: str,
        correlation_id: str,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> None:
        previous = await conn.fetchrow(
            """SELECT tenant_sequence,entry_hash FROM middleware_event_ledger
               WHERE tenant_id=$1 ORDER BY tenant_sequence DESC LIMIT 1""",
            tenant_id,
        )
        sequence = int(previous["tenant_sequence"]) + 1 if previous else 1
        previous_hash = str(previous["entry_hash"]) if previous else ZERO_LEDGER_HASH
        event_id = "email-production-" + uuid4().hex
        semantic_sha256 = canonical_payload_sha256(payload)
        entry_hash = event_ledger_hash(
            tenant_id=tenant_id,
            tenant_sequence=sequence,
            event_id=event_id,
            semantic_sha256=semantic_sha256,
            previous_entry_hash=previous_hash,
        )
        await conn.execute(
            """INSERT INTO middleware_event_ledger(
                 tenant_id,tenant_sequence,event_id,event_type,event_version,
                 source_client_id,correlation_id,causation_id,idempotency_key,
                 semantic_sha256,previous_entry_hash,entry_hash,payload
               ) VALUES($1,$2,$3,$4,'1.0',$5,$6,$6,$7,$8,$9,$10,$11::jsonb)""",
            tenant_id,
            sequence,
            event_id,
            event_type,
            PRODUCTION_OPERATOR_CLIENT_ID,
            correlation_id,
            idempotency_key,
            semantic_sha256,
            previous_hash,
            entry_hash,
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )

    @staticmethod
    def _control_idempotency(action: str, actor: str, raw_key: str) -> str:
        digest = hashlib.sha256(
            f"{action}\0{actor}\0{raw_key}".encode("utf-8")
        ).hexdigest()
        return f"email-production-control:{digest}"

    async def mutate(
        self,
        tenant_id: str,
        *,
        actor: str,
        correlation_id: str,
        idempotency_key: str,
        action: str,
        expected_version: int,
        reason: str,
        request_sha256: str,
        transform: Callable[[EmailProductionPolicy], EmailProductionPolicy],
    ) -> EmailProductionPolicy:
        ledger_key = self._control_idempotency(action, actor, idempotency_key)
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant_id
            )
            replay = await conn.fetchrow(
                """SELECT payload FROM middleware_event_ledger
                   WHERE tenant_id=$1 AND idempotency_key=$2 LIMIT 1""",
                tenant_id,
                ledger_key,
            )
            if replay is not None:
                document = self._decode_payload(replay["payload"])
                if document.get("request_sha256") != request_sha256:
                    raise CommunicationsConflict(
                        "Idempotency-Key was reused with different production-control content"
                    )
                policy = document.get("policy")
                if not isinstance(policy, dict):
                    raise EmailProductionUnavailable(
                        "production-control idempotency record is invalid"
                    )
                return EmailProductionPolicy.model_validate(policy)
            current = await self._latest_policy(conn, tenant_id)
            if current.version != expected_version:
                raise CommunicationsConflict("expectedVersion is stale")
            changed = EmailProductionPolicy.model_validate(
                transform(current).model_copy(
                    update={
                        "version": current.version + 1,
                        "updatedAt": datetime.now(UTC),
                    }
                ).model_dump(mode="json")
            )
            payload = {
                "kind": "email-production-control",
                "action": action,
                "actor_id": actor,
                "reason": reason,
                "request_sha256": request_sha256,
                "previous_policy": current.model_dump(mode="json"),
                "policy": changed.model_dump(mode="json"),
            }
            await self._append_event(
                conn,
                tenant_id=tenant_id,
                event_type=POLICY_EVENT,
                correlation_id=correlation_id,
                idempotency_key=ledger_key,
                payload=payload,
            )
            return changed

    async def _quota_used(
        self, conn: asyncpg.Connection, tenant_id: str, cutoff: datetime
    ) -> int:
        return int(
            await conn.fetchval(
                """SELECT COALESCE(SUM((r.payload->>'units')::bigint),0)
                   FROM middleware_event_ledger r
                   WHERE r.tenant_id=$1
                     AND r.event_type=$2
                     AND r.recorded_at >= $3
                     AND NOT EXISTS(
                       SELECT 1 FROM middleware_event_ledger x
                       WHERE x.tenant_id=r.tenant_id
                         AND x.event_type=$4
                         AND x.payload->>'reservation_id'=r.payload->>'reservation_id'
                     )""",
                tenant_id,
                QUOTA_RESERVED_EVENT,
                cutoff,
                QUOTA_RELEASED_EVENT,
            )
            or 0
        )

    async def reserve_quota(
        self, tenant_id: str, units: int, policy: EmailProductionPolicy
    ) -> QuotaReservation:
        reserved_at = datetime.now(UTC)
        limits = {
            "minute": policy.perMinuteLimit,
            "hour": policy.perHourLimit,
            "day": policy.perDayLimit,
        }
        reservation = QuotaReservation(
            tenant_id=tenant_id,
            reservation_id=str(uuid4()),
            units=units,
            reserved_at=reserved_at,
        )
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant_id
            )
            for window, cutoff in _quota_cutoffs(reserved_at).items():
                used = await self._quota_used(conn, tenant_id, cutoff)
                if used + units > limits[window]:
                    raise EmailProductionRateLimited(
                        f"{window} email quota is exhausted"
                    )
            await self._append_event(
                conn,
                tenant_id=tenant_id,
                event_type=QUOTA_RESERVED_EVENT,
                correlation_id=reservation.reservation_id,
                idempotency_key="email-quota-reserve:" + reservation.reservation_id,
                payload={
                    "kind": "email-production-quota-reservation",
                    "reservation_id": reservation.reservation_id,
                    "units": reservation.units,
                    "policy_version": policy.version,
                    "reserved_at": reservation.reserved_at.isoformat(),
                },
            )
        return reservation

    async def release_quota(self, reservation: QuotaReservation) -> None:
        ledger_key = "email-quota-release:" + reservation.reservation_id
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                reservation.tenant_id,
            )
            existing = await conn.fetchval(
                """SELECT 1 FROM middleware_event_ledger
                   WHERE tenant_id=$1 AND idempotency_key=$2 LIMIT 1""",
                reservation.tenant_id,
                ledger_key,
            )
            if existing:
                return
            await self._append_event(
                conn,
                tenant_id=reservation.tenant_id,
                event_type=QUOTA_RELEASED_EVENT,
                correlation_id=reservation.reservation_id,
                idempotency_key=ledger_key,
                payload={
                    "kind": "email-production-quota-release",
                    "reservation_id": reservation.reservation_id,
                    "units": reservation.units,
                    "released_at": datetime.now(UTC).isoformat(),
                },
            )

    async def quota_status(self, tenant_id: str) -> dict[str, int]:
        now = datetime.now(UTC)
        async with self.pool.acquire() as conn:
            return {
                window: await self._quota_used(conn, tenant_id, cutoff)
                for window, cutoff in _quota_cutoffs(now).items()
            }

    async def audit(self, tenant_id: str, limit: int) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            """SELECT payload,recorded_at,correlation_id
               FROM middleware_event_ledger
               WHERE tenant_id=$1 AND event_type=$2
               ORDER BY tenant_sequence DESC LIMIT $3""",
            tenant_id,
            POLICY_EVENT,
            limit,
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            payload = self._decode_payload(row["payload"])
            result.append(
                {
                    "tenant_id": tenant_id,
                    "action": payload.get("action"),
                    "actor_id": payload.get("actor_id"),
                    "reason": payload.get("reason"),
                    "correlation_id": row["correlation_id"],
                    "previous_policy": payload.get("previous_policy"),
                    "new_policy": payload.get("policy"),
                    "created_at": row["recorded_at"],
                }
            )
        return result


EmailPolicyStore = MemoryEmailProductionPolicyStore | PostgresEmailProductionPolicyStore


def _quota_cutoffs(moment: datetime) -> dict[str, datetime]:
    value = moment.astimezone(UTC)
    return {
        "minute": value.replace(second=0, microsecond=0),
        "hour": value.replace(minute=0, second=0, microsecond=0),
        "day": value.replace(hour=0, minute=0, second=0, microsecond=0),
    }


def _domain_registry() -> dict[str, dict[str, Any]]:
    try:
        document = json.loads(DOMAIN_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EmailProductionUnavailable("postal domain registry is unavailable") from exc
    domains = document.get("domains")
    if not isinstance(domains, list):
        raise EmailProductionUnavailable("postal domain registry is invalid")
    result: dict[str, dict[str, Any]] = {}
    for item in domains:
        if isinstance(item, dict) and isinstance(item.get("domain"), str):
            result[item["domain"].lower()] = item
    return result


def _request_digest(body: BaseModel) -> str:
    return hashlib.sha256(
        json.dumps(
            body.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


@dataclass
class EmailProductionControlService:
    store: EmailPolicyStore
    settings: Settings

    async def get(self, tenant_id: str) -> EmailProductionPolicy:
        return await self.store.get(tenant_id)

    def activation_blockers(self, policy: EmailProductionPolicy) -> list[str]:
        blockers: list[str] = []
        now = datetime.now(UTC)
        if policy.authorizationState not in {"AUTHORIZED_NOT_ACTIVE", "ACTIVE"}:
            blockers.append("production_authorization_missing")
        if not policy.enabled:
            blockers.append("production_policy_disabled")
        if policy.mode == "SAFE":
            blockers.append("production_mode_safe")
        if policy.mode == "CAMPAIGN_PRODUCTION":
            blockers.append("campaign_compliance_gate_not_certified")
        if not self.settings.production_activation_id:
            blockers.append("production_activation_id_missing")
        elif policy.changeId != self.settings.production_activation_id:
            blockers.append("production_activation_id_mismatch")
        if not self.settings.email_delivery_enabled:
            blockers.append("email_delivery_runtime_gate_closed")
        if policy.validFrom and now < policy.validFrom.astimezone(UTC):
            blockers.append("authorization_not_yet_valid")
        if policy.validUntil and now >= policy.validUntil.astimezone(UTC):
            blockers.append("authorization_expired")
        if not policy.approvedDomains:
            blockers.append("approved_domains_empty")
        if not policy.approvedSenders:
            blockers.append("approved_senders_empty")
        if not policy.approvedCategories:
            blockers.append("approved_categories_empty")
        if "marketing" in policy.approvedCategories:
            blockers.append("campaign_category_not_certified")
        if policy.mode in {"TRANSACTIONAL_CANARY", "TRANSACTIONAL_PRODUCTION"} and (
            policy.recipientScope not in {"ALLOWLIST", "DOMAIN_ALLOWLIST"}
        ):
            blockers.append("recipient_scope_unbounded")
        if policy.recipientScope == "ALLOWLIST" and not policy.approvedRecipients:
            blockers.append("approved_recipients_empty")
        if (
            policy.recipientScope == "DOMAIN_ALLOWLIST"
            and not policy.approvedRecipientDomains
        ):
            blockers.append("approved_recipient_domains_empty")
        if policy.provider != "klyrow-postal":
            blockers.append("provider_authority_mismatch")
        if policy.environment != self.settings.app_env:
            blockers.append("policy_environment_mismatch")
        if policy.approvedReleaseSha != self.settings.source_sha:
            blockers.append("release_source_mismatch")
        if not all(
            (
                policy.productionOwner,
                policy.monitoringOwner,
                policy.escalationOwner,
                policy.rollbackOwner,
                policy.killSwitchProcedure,
                policy.approvedBy,
                policy.authorizationTimestamp,
                policy.validFrom,
                policy.validUntil,
            )
        ):
            blockers.append("authorization_record_incomplete")
        if min(policy.perMinuteLimit, policy.perHourLimit, policy.perDayLimit) <= 0:
            blockers.append("quota_not_configured")
        registry = _domain_registry()
        for domain in policy.approvedDomains:
            record = registry.get(domain)
            if record is None:
                blockers.append(f"domain_not_registered:{domain}")
                continue
            if record.get("latest_postal_dns_check") != "pass":
                blockers.append(f"postal_dns_not_pass:{domain}")
            if record.get("dkim_rotation_required") is True:
                blockers.append(f"dkim_rotation_incomplete:{domain}")
            if record.get("post_rotation_recheck_required") is True:
                blockers.append(f"post_rotation_recheck_incomplete:{domain}")
            if record.get("middleware_send_eligible") is not True:
                blockers.append(f"middleware_send_not_eligible:{domain}")
            if record.get("production_ready") is not True:
                blockers.append(f"domain_not_production_ready:{domain}")
        return blockers

    async def authorize(
        self,
        tenant_id: str,
        actor: str,
        correlation_id: str,
        idempotency_key: str,
        body: AuthorizeEmailProduction,
    ) -> EmailProductionPolicy:
        senders = [str(value).lower() for value in body.approvedSenders]
        recipients = [str(value).lower() for value in body.approvedRecipients]
        recipient_domains = list(body.approvedRecipientDomains)
        domains = [value.strip().lower().rstrip(".") for value in body.approvedDomains]
        for sender in senders:
            if sender.rsplit("@", 1)[-1] not in domains:
                raise RequestValidationError(
                    "every approved sender must belong to an approved domain"
                )

        def transform(current: EmailProductionPolicy) -> EmailProductionPolicy:
            return current.model_copy(
                update={
                    "enabled": True,
                    "mode": body.mode,
                    "authorizationState": "AUTHORIZED_NOT_ACTIVE",
                    "approvedDomains": domains,
                    "approvedSenders": senders,
                    "recipientScope": body.recipientScope,
                    "approvedRecipients": recipients,
                    "approvedRecipientDomains": recipient_domains,
                    "approvedCategories": list(body.approvedCategories),
                    "perMinuteLimit": body.perMinuteLimit,
                    "perHourLimit": body.perHourLimit,
                    "perDayLimit": body.perDayLimit,
                    "validFrom": body.validFrom,
                    "validUntil": body.validUntil,
                    "changeId": body.changeId,
                    "approvedBy": actor,
                    "activatedBy": None,
                    "productionOwner": body.productionOwner,
                    "monitoringOwner": body.monitoringOwner,
                    "escalationOwner": body.escalationOwner,
                    "rollbackOwner": body.rollbackOwner,
                    "killSwitchProcedure": body.killSwitchProcedure,
                    "provider": body.provider,
                    "environment": body.environment,
                    "approvedReleaseSha": body.approvedReleaseSha,
                    "authorizationTimestamp": datetime.now(UTC),
                    "activationTimestamp": None,
                    "killSwitchOpen": False,
                }
            )

        return await self.store.mutate(
            tenant_id,
            actor=actor,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            action="authorize",
            expected_version=body.expectedVersion,
            reason=body.reason,
            request_sha256=_request_digest(body),
            transform=transform,
        )

    async def activate(
        self,
        tenant_id: str,
        actor: str,
        correlation_id: str,
        idempotency_key: str,
        body: ControlMutation,
    ) -> EmailProductionPolicy:
        current = await self.store.get(tenant_id)
        if current.version != body.expectedVersion:
            raise CommunicationsConflict("expectedVersion is stale")
        if current.authorizationState != "AUTHORIZED_NOT_ACTIVE":
            raise EmailProductionBlocked(
                "production authorization is not awaiting activation"
            )
        blockers = self.activation_blockers(current)
        if blockers:
            raise EmailProductionBlocked(
                "production activation blocked: " + ",".join(blockers)
            )

        def transform(policy: EmailProductionPolicy) -> EmailProductionPolicy:
            return policy.model_copy(
                update={
                    "authorizationState": "ACTIVE",
                    "activatedBy": actor,
                    "activationTimestamp": datetime.now(UTC),
                    "killSwitchOpen": True,
                }
            )

        return await self.store.mutate(
            tenant_id,
            actor=actor,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            action="activate",
            expected_version=body.expectedVersion,
            reason=body.reason,
            request_sha256=_request_digest(body),
            transform=transform,
        )

    async def revoke(
        self,
        tenant_id: str,
        actor: str,
        correlation_id: str,
        idempotency_key: str,
        body: ControlMutation,
    ) -> EmailProductionPolicy:
        def transform(policy: EmailProductionPolicy) -> EmailProductionPolicy:
            return policy.model_copy(
                update={
                    "enabled": False,
                    "authorizationState": "REVOKED",
                    "mode": "SAFE",
                    "killSwitchOpen": False,
                }
            )

        return await self.store.mutate(
            tenant_id,
            actor=actor,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            action="revoke",
            expected_version=body.expectedVersion,
            reason=body.reason,
            request_sha256=_request_digest(body),
            transform=transform,
        )

    async def set_kill_switch(
        self,
        tenant_id: str,
        actor: str,
        correlation_id: str,
        idempotency_key: str,
        body: KillSwitchMutation,
    ) -> EmailProductionPolicy:
        current = await self.store.get(tenant_id)
        if body.open and current.authorizationState != "ACTIVE":
            raise EmailProductionBlocked(
                "kill switch cannot be opened without active authorization"
            )
        if body.open:
            blockers = self.activation_blockers(current)
            if blockers:
                raise EmailProductionBlocked(
                    "kill switch cannot be opened: " + ",".join(blockers)
                )

        def transform(policy: EmailProductionPolicy) -> EmailProductionPolicy:
            return policy.model_copy(update={"killSwitchOpen": body.open})

        return await self.store.mutate(
            tenant_id,
            actor=actor,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            action="kill-switch-open" if body.open else "kill-switch-close",
            expected_version=body.expectedVersion,
            reason=body.reason,
            request_sha256=_request_digest(body),
            transform=transform,
        )

    async def guard_request(
        self,
        tenant_id: str,
        request: CreateMessageRequest,
        sender: str,
    ) -> tuple[EmailProductionPolicy, QuotaReservation]:
        policy = await self.store.get(tenant_id)
        now = datetime.now(UTC)
        if not self.settings.email_delivery_enabled:
            raise EmailProductionUnavailable("email delivery runtime gate is closed")
        if policy.authorizationState != "ACTIVE":
            raise EmailProductionBlocked("email production is not active")
        if not policy.enabled:
            raise EmailProductionBlocked("email production policy is disabled")
        if not policy.killSwitchOpen:
            raise EmailProductionBlocked("email production kill switch is closed")
        if policy.validFrom and now < policy.validFrom.astimezone(UTC):
            raise EmailProductionBlocked("email production authorization is not yet valid")
        if policy.validUntil and now >= policy.validUntil.astimezone(UTC):
            raise EmailProductionBlocked("email production authorization has expired")
        sender_value = sender.lower()
        sender_domain = sender_value.rsplit("@", 1)[-1]
        if sender_domain not in policy.approvedDomains:
            raise EmailProductionBlocked("sender domain is outside production authorization")
        if sender_value not in policy.approvedSenders:
            raise EmailProductionBlocked("sender identity is outside production authorization")
        category = str(request.metadata.get("category") or "transactional").lower()
        recipients = [value.lower() for value in request.to]
        approved_recipients = set(policy.approvedRecipients)
        if category == "marketing":
            if policy.mode != "CAMPAIGN_PRODUCTION":
                raise EmailProductionBlocked("campaign email is not authorized")
            if policy.recipientScope != "CONSENTED_MARKETING":
                raise EmailProductionBlocked("campaign recipient scope is not authorized")
        else:
            if category not in policy.approvedCategories:
                raise EmailProductionBlocked("message category is outside production authorization")
            if policy.mode not in {
                "TRANSACTIONAL_CANARY",
                "TRANSACTIONAL_PRODUCTION",
            }:
                raise EmailProductionBlocked("transactional email is not authorized")
            if policy.recipientScope == "ALLOWLIST":
                if any(recipient not in approved_recipients for recipient in recipients):
                    raise EmailProductionBlocked("recipient is outside production allowlist")
            elif policy.recipientScope == "DOMAIN_ALLOWLIST":
                approved_domains = set(policy.approvedRecipientDomains)
                if any(
                    "@" not in recipient
                    or recipient.rsplit("@", 1)[1] not in approved_domains
                    for recipient in recipients
                ):
                    raise EmailProductionBlocked("recipient domain is outside production authorization")
            else:
                raise EmailProductionBlocked("recipient scope is not bounded")
            if policy.mode == "TRANSACTIONAL_CANARY" and policy.recipientScope != "ALLOWLIST":
                raise EmailProductionBlocked("canary mode requires recipient allowlist")
            if policy.recipientScope == "DENY_ALL":
                raise EmailProductionBlocked("recipient scope denies delivery")
        return policy, await self.store.reserve_quota(
            tenant_id, len(recipients), policy
        )


@dataclass
class ProductionGatedCommunicationsService(CommunicationsService):
    production_control: EmailProductionControlService | None = None
    enforce_production_policy: bool = False

    async def submit_message(self, request: CreateMessageRequest, **kwargs):
        if request.channel != "email" or not self.enforce_production_policy:
            return await super().submit_message(request, **kwargs)
        tenant_id = kwargs["tenant_id"]
        idempotency_key = kwargs["idempotency_key"]
        route = "POST /v1/communications/messages"
        async with self.store.submission_lock(tenant_id, route, idempotency_key):
            await self.store.refresh_idempotency(tenant_id, route, idempotency_key)
            return await self._submit_production_email_unlocked(request, **kwargs)

    async def _submit_production_email_unlocked(
        self, request: CreateMessageRequest, **kwargs
    ):
        tenant_id = kwargs["tenant_id"]
        idempotency_key = kwargs["idempotency_key"]
        existing = self.store.idempotency.get(
            (tenant_id, "POST /v1/communications/messages", idempotency_key)
        )
        if existing is not None:
            return await super()._submit_message_unlocked(request, **kwargs)
        if "productionAuthorization" in request.metadata:
            raise RequestValidationError(
                "productionAuthorization metadata is reserved for Middleware"
            )
        if self.production_control is None:
            raise EmailProductionUnavailable(
                "email production control service is unavailable"
            )
        if request.from_ is not None:
            sender = request.from_
        elif request.senderIdentityId is not None:
            sender = self.store.sender_identities.get(
                (tenant_id, request.senderIdentityId), ""
            )
        else:
            sender = ""
        if not sender:
            raise RequestValidationError("sender identity is required")
        policy, reservation = await self.production_control.guard_request(
            tenant_id, request, sender
        )
        category = str(request.metadata.get("category") or "transactional").lower()
        governed_metadata = {
            "productionAuthorization": {
                "schemaVersion": "1.0",
                "tenantId": tenant_id,
                "policyVersion": policy.version,
                "mode": policy.mode,
                "authorizationState": policy.authorizationState,
                "killSwitchOpen": policy.killSwitchOpen,
                "changeId": policy.changeId,
                "category": category,
                "validFrom": (
                    policy.validFrom.isoformat() if policy.validFrom else None
                ),
                "validUntil": (
                    policy.validUntil.isoformat() if policy.validUntil else None
                ),
                "provider": policy.provider,
                "environment": policy.environment,
                "approvedReleaseSha": policy.approvedReleaseSha,
                "authorizationTimestamp": (
                    policy.authorizationTimestamp.isoformat()
                    if policy.authorizationTimestamp else None
                ),
                "activationTimestamp": (
                    policy.activationTimestamp.isoformat()
                    if policy.activationTimestamp else None
                ),
            }
        }
        # Once submission is attempted, the command may already be durably
        # queued even if a later projection/persist step fails.  Never release
        # that reservation on an exception: doing so could permit a retry to
        # create a second live send beyond the authorized quota.
        message, duplicate = await super()._submit_message_unlocked(
            request, _governed_metadata=governed_metadata, **kwargs
        )
        if duplicate or message.status == "suppressed":
            await self.production_control.store.release_quota(reservation)
        return message, duplicate


router = APIRouter(prefix="/platform/v1/email/production", tags=["email-production"])


def _control(request: Request) -> EmailProductionControlService:
    service = request.app.state.runtime.communications
    if not isinstance(service, ProductionGatedCommunicationsService):
        raise EmailProductionUnavailable("email production control is unavailable")
    if service.production_control is None:
        raise EmailProductionUnavailable("email production control is unavailable")
    return service.production_control


async def _operator(
    request: Request, *, mutation: bool
) -> tuple[str, str, str | None, str | None]:
    caller, claims, tenant_id = await authenticated_tenant(request, mutation=mutation)
    if caller.client_id != PRODUCTION_OPERATOR_CLIENT_ID:
        raise AuthorizationError("production operator identity is required")
    actor = claims.get("sub")
    if not isinstance(actor, str) or not actor:
        raise AuthorizationError("production operator subject is required")
    if not mutation:
        return tenant_id, actor, None, None
    correlation_id = required_header(
        request, "X-Correlation-ID", minimum=1, maximum=180
    )
    idempotency_key = required_header(
        request, "Idempotency-Key", minimum=8, maximum=180
    )
    return tenant_id, actor, correlation_id, idempotency_key


@router.get("/status", response_model=EmailProductionPolicy)
async def status(request: Request) -> EmailProductionPolicy:
    tenant_id, _, _, _ = await _operator(request, mutation=False)
    return await _control(request).get(tenant_id)


@router.get("/readiness")
async def readiness(request: Request) -> dict[str, Any]:
    tenant_id, _, _, _ = await _operator(request, mutation=False)
    control = _control(request)
    policy = await control.get(tenant_id)
    blockers = control.activation_blockers(policy)
    return {
        "tenant_id": tenant_id,
        "ready": not blockers,
        "blockers": blockers,
        "policy": policy.model_dump(mode="json"),
    }


@router.get("/quotas")
async def quotas(request: Request) -> dict[str, Any]:
    tenant_id, _, _, _ = await _operator(request, mutation=False)
    control = _control(request)
    policy = await control.get(tenant_id)
    used = await control.store.quota_status(tenant_id)
    return {
        "tenant_id": tenant_id,
        "used": used,
        "limits": {
            "minute": policy.perMinuteLimit,
            "hour": policy.perHourLimit,
            "day": policy.perDayLimit,
        },
    }


@router.get("/audit")
async def audit(
    request: Request, limit: int = Query(50, ge=1, le=200)
) -> dict[str, Any]:
    tenant_id, _, _, _ = await _operator(request, mutation=False)
    return {
        "items": await _control(request).store.audit(tenant_id, limit),
        "next_cursor": None,
    }


@router.post("/authorize", response_model=EmailProductionPolicy)
async def authorize(
    body: AuthorizeEmailProduction, request: Request
) -> EmailProductionPolicy:
    tenant_id, actor, correlation_id, idempotency_key = await _operator(
        request, mutation=True
    )
    assert correlation_id is not None and idempotency_key is not None
    return await _control(request).authorize(
        tenant_id, actor, correlation_id, idempotency_key, body
    )


@router.post("/activate", response_model=EmailProductionPolicy)
async def activate(
    body: ControlMutation, request: Request
) -> EmailProductionPolicy:
    tenant_id, actor, correlation_id, idempotency_key = await _operator(
        request, mutation=True
    )
    assert correlation_id is not None and idempotency_key is not None
    return await _control(request).activate(
        tenant_id, actor, correlation_id, idempotency_key, body
    )


@router.post("/revoke", response_model=EmailProductionPolicy)
async def revoke(
    body: ControlMutation, request: Request
) -> EmailProductionPolicy:
    tenant_id, actor, correlation_id, idempotency_key = await _operator(
        request, mutation=True
    )
    assert correlation_id is not None and idempotency_key is not None
    return await _control(request).revoke(
        tenant_id, actor, correlation_id, idempotency_key, body
    )


@router.post("/kill-switch", response_model=EmailProductionPolicy)
async def kill_switch(
    body: KillSwitchMutation, request: Request
) -> EmailProductionPolicy:
    tenant_id, actor, correlation_id, idempotency_key = await _operator(
        request, mutation=True
    )
    assert correlation_id is not None and idempotency_key is not None
    return await _control(request).set_kill_switch(
        tenant_id, actor, correlation_id, idempotency_key, body
    )
