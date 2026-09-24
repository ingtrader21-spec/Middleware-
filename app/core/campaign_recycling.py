from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence
from uuid import UUID

import asyncpg

from app.commands import (
    ADAPTER_COMMAND_DESTINATION,
    CommandEnvelope,
    CommandOperation,
    CommandService,
    PostgresCommandStore,
)

ROOT = Path(__file__).resolve().parents[2]

LifecycleState = Literal[
    "NEW", "VALIDATED", "ELIGIBLE", "ACTIVE_CYCLE", "ENGAGED",
    "COOLING", "REACTIVATION", "CONVERTED", "SUPPRESSED",
]
Channel = Literal["email", "sms", "whatsapp", "voice"]

CONTACTABLE_LIFECYCLE = frozenset(
    {"ELIGIBLE", "ACTIVE_CYCLE", "ENGAGED", "REACTIVATION"}
)
TERMINAL_LIFECYCLE = frozenset({"CONVERTED", "SUPPRESSED"})
CHANNEL_ORDER = {"email": 0, "sms": 1, "whatsapp": 2, "voice": 3}
CHANNEL_HEALTH_STATES = frozenset(
    {
        "unknown",
        "valid",
        "possible",
        "soft_bounce",
        "hard_bounce",
        "complained",
        "unsubscribed",
        "suppressed",
        "invalid",
    }
)
SUPPRESSION_REQUIRED_HEALTH = frozenset({"complained", "unsubscribed", "suppressed"})

REASON_PRECEDENCE = (
    "POLICY_NOT_CONFIGURED",
    "PRODUCTION_NOT_AUTHORIZED",
    "KILL_SWITCH_OPEN",
    "EVIDENCE_STALE_OR_CONFLICTING",
    "SUPPRESSED_GLOBAL",
    "SUPPRESSED_CHANNEL",
    "SUPPRESSED_CAMPAIGN",
    "SUPPRESSED_CAMPAIGN_CHANNEL",
    "LIFECYCLE_TERMINAL",
    "LIFECYCLE_NOT_CONTACTABLE",
    "CONSENT_MISSING",
    "DIALING_NOT_ELIGIBLE",
    "CHANNEL_HEALTH_BLOCKED",
    "CHANNEL_HEALTH_UNKNOWN",
    "CHANNEL_HEALTH_POLICY_GATED",
    "CHANNEL_HEALTH_DEFERRED",
    "CAMPAIGN_NOT_ACTIVE",
    "CAMPAIGN_VERSION_NOT_APPROVED",
    "SENDER_IDENTITY_NOT_AUTHORIZED",
    "SENDER_IDENTITY_UNAVAILABLE",
    "CHANNEL_EXECUTION_NOT_SUPPORTED",
    "DUPLICATE_TOUCH",
    "COOLING_PERIOD_ACTIVE",
    "REACTIVATION_LIMIT_REACHED",
    "LIFETIME_EXPOSURE_CAP_REACHED",
    "RECENT_WINDOW_CAP_REACHED",
    "CHANNEL_CAP_REACHED",
    "CAMPAIGN_COOLDOWN_ACTIVE",
    "CAMPAIGN_VERSION_EXHAUSTED",
    "NO_CANDIDATE",
    "ELIGIBLE",
)
REASON_INDEX = {reason: index for index, reason in enumerate(REASON_PRECEDENCE)}
TEMPORAL_REASONS = frozenset(
    {
        "CHANNEL_HEALTH_DEFERRED",
        "COOLING_PERIOD_ACTIVE",
        "RECENT_WINDOW_CAP_REACHED",
        "CHANNEL_CAP_REACHED",
        "CAMPAIGN_COOLDOWN_ACTIVE",
    }
)

LEGAL_TRANSITIONS: dict[str | None, frozenset[str]] = {
    None: frozenset({"NEW"}),
    "NEW": frozenset({"VALIDATED", "SUPPRESSED"}),
    "VALIDATED": frozenset({"ELIGIBLE", "SUPPRESSED"}),
    "ELIGIBLE": frozenset({"ACTIVE_CYCLE", "CONVERTED", "SUPPRESSED"}),
    "ACTIVE_CYCLE": frozenset({"ENGAGED", "COOLING", "CONVERTED", "SUPPRESSED"}),
    "ENGAGED": frozenset({"ACTIVE_CYCLE", "COOLING", "CONVERTED", "SUPPRESSED"}),
    "COOLING": frozenset({"REACTIVATION", "CONVERTED", "SUPPRESSED"}),
    "REACTIVATION": frozenset(
        {"ACTIVE_CYCLE", "ENGAGED", "COOLING", "CONVERTED", "SUPPRESSED"}
    ),
    "CONVERTED": frozenset({"SUPPRESSED"}),
    "SUPPRESSED": frozenset(),
}


class CampaignRecyclingError(RuntimeError):
    pass


class CampaignRecyclingConflict(CampaignRecyclingError):
    pass


class CampaignRecyclingPolicyError(CampaignRecyclingError):
    pass


@dataclass(frozen=True)
class Suppression:
    scope: Literal["global", "channel", "campaign", "campaign_channel"]
    reason: str
    occurred_at: datetime
    suppression_id: str
    channel: Channel | None = None
    campaign_id: str | None = None

    def matches(self, candidate: "Candidate") -> bool:
        if self.scope == "global":
            return True
        if self.scope == "channel":
            return self.channel == candidate.channel
        if self.scope == "campaign":
            return self.campaign_id == candidate.campaign_id
        return (
            self.channel == candidate.channel
            and self.campaign_id == candidate.campaign_id
        )


@dataclass(frozen=True)
class ChannelHealth:
    state: str
    occurred_at: datetime
    address_ref: str = ""


@dataclass(frozen=True)
class Exposure:
    campaign_id: str
    campaign_version: int
    channel: Channel
    touch_index: int
    status: str
    reserved_at: datetime
    engagement_outcome: str = "none"
    negative_outcome: str = "none"


@dataclass(frozen=True)
class Candidate:
    campaign_id: str
    campaign_version: int
    channel: Channel
    priority: int
    touch_index: int
    sender_identity_id: str | None
    active: bool = True
    version_approved: bool = True
    consent_granted: bool = True
    sender_authorized: bool = True
    dialing_eligible: bool = False


@dataclass(frozen=True)
class LeadSnapshot:
    tenant_id: str
    lead_id: str
    lifecycle_state: LifecycleState
    lifecycle_version: int
    channel_health: Mapping[Channel, ChannelHealth]
    suppressions: Sequence[Suppression] = ()
    exposures: Sequence[Exposure] = ()
    cooling_until: datetime | None = None
    reactivation_cycles: int = 0


@dataclass(frozen=True)
class CandidateDecision:
    campaign_id: str
    campaign_version: int
    channel: Channel
    touch_index: int
    sender_identity_id: str | None
    disposition: Literal["selected", "rejected"]
    reason_codes: tuple[str, ...]
    next_eligible_at: datetime | None


@dataclass(frozen=True)
class NextActionDecision:
    eligible: bool
    selected: CandidateDecision | None
    reason_codes: tuple[str, ...]
    candidates: tuple[CandidateDecision, ...]
    next_eligible_at: datetime | None
    policy_version: str
    decision_hash: str


@dataclass(frozen=True)
class PolicyProfile:
    policy_version: str
    values: Mapping[str, Any]
    configured: bool
    production_authorized: bool
    channel_execution: Mapping[str, Mapping[str, Any]]

    @classmethod
    def load(cls, profile: str, *, root: Path = ROOT) -> "PolicyProfile":
        raw = json.loads(
            (root / "config" / "campaign-recycling-policy.v1.json").read_text(
                encoding="utf-8"
            )
        )
        profiles = raw["parameters"]["profiles"]
        if profile not in profiles:
            raise CampaignRecyclingPolicyError(f"unknown policy profile {profile}")
        values = profiles[profile]["values"]
        configured = all(value is not None for value in _leaf_values(values))
        return cls(
            policy_version=raw["policy_version"],
            values=values,
            configured=configured,
            production_authorized=raw["production"]["authorized"] is True,
            channel_execution=raw["channel_execution"],
        )


class CampaignRecyclingEngine:
    def __init__(self, policy: PolicyProfile) -> None:
        self.policy = policy

    def evaluate(
        self,
        snapshot: LeadSnapshot,
        candidates: Sequence[Candidate],
        *,
        mode: Literal["plan", "read", "execute"] = "plan",
        now: datetime | None = None,
        kill_switch_open: bool = False,
        evidence_stale_or_conflicting: bool = False,
    ) -> NextActionDecision:
        now = _utc(now or datetime.now(UTC))
        ordered = sorted(
            candidates,
            key=lambda item: (
                item.priority,
                item.campaign_id,
                item.campaign_version,
                CHANNEL_ORDER[item.channel],
                item.touch_index,
            ),
        )
        if not ordered:
            return self._decision(
                snapshot, (), None, ("NO_CANDIDATE",), None, mode, now
            )

        evaluated: list[CandidateDecision] = []
        for candidate in ordered:
            reasons, next_at = self._candidate_reasons(
                snapshot,
                candidate,
                mode=mode,
                now=now,
                kill_switch_open=kill_switch_open,
                evidence_stale_or_conflicting=evidence_stale_or_conflicting,
            )
            evaluated.append(
                CandidateDecision(
                    campaign_id=candidate.campaign_id,
                    campaign_version=candidate.campaign_version,
                    channel=candidate.channel,
                    touch_index=candidate.touch_index,
                    sender_identity_id=candidate.sender_identity_id,
                    disposition="selected" if not reasons else "rejected",
                    reason_codes=("ELIGIBLE",) if not reasons else tuple(reasons),
                    next_eligible_at=next_at,
                )
            )

        selected = next(
            (item for item in evaluated if item.disposition == "selected"), None
        )
        if selected is not None:
            selected_index = evaluated.index(selected)
            normalized = tuple(
                item
                if index == selected_index
                else CandidateDecision(
                    campaign_id=item.campaign_id,
                    campaign_version=item.campaign_version,
                    channel=item.channel,
                    touch_index=item.touch_index,
                    sender_identity_id=item.sender_identity_id,
                    disposition="rejected",
                    reason_codes=item.reason_codes
                    if item.reason_codes != ("ELIGIBLE",)
                    else ("NO_CANDIDATE",),
                    next_eligible_at=item.next_eligible_at,
                )
                for index, item in enumerate(evaluated)
            )
            return self._decision(
                snapshot,
                normalized,
                normalized[selected_index],
                ("ELIGIBLE",),
                None,
                mode,
                now,
            )

        aggregate = _sort_reasons(
            reason for item in evaluated for reason in item.reason_codes
        )
        temporal_times = [
            item.next_eligible_at
            for item in evaluated
            if item.next_eligible_at is not None
            and set(item.reason_codes) <= TEMPORAL_REASONS
        ]
        return self._decision(
            snapshot,
            tuple(evaluated),
            None,
            aggregate or ("NO_CANDIDATE",),
            min(temporal_times) if temporal_times else None,
            mode,
            now,
        )

    def _candidate_reasons(
        self,
        snapshot: LeadSnapshot,
        candidate: Candidate,
        *,
        mode: str,
        now: datetime,
        kill_switch_open: bool,
        evidence_stale_or_conflicting: bool,
    ) -> tuple[tuple[str, ...], datetime | None]:
        reasons: list[str] = []
        temporal_until: list[datetime] = []

        if not self.policy.configured:
            reasons.append("POLICY_NOT_CONFIGURED")
        if mode == "execute" and not self.policy.production_authorized:
            reasons.append("PRODUCTION_NOT_AUTHORIZED")
        if kill_switch_open:
            reasons.append("KILL_SWITCH_OPEN")
        if evidence_stale_or_conflicting:
            reasons.append("EVIDENCE_STALE_OR_CONFLICTING")

        matching = [s for s in snapshot.suppressions if s.matches(candidate)]
        if matching:
            scope_code = {
                "global": "SUPPRESSED_GLOBAL",
                "channel": "SUPPRESSED_CHANNEL",
                "campaign": "SUPPRESSED_CAMPAIGN",
                "campaign_channel": "SUPPRESSED_CAMPAIGN_CHANNEL",
            }
            precedence = {
                "global": 0,
                "channel": 1,
                "campaign": 2,
                "campaign_channel": 3,
            }
            reason_precedence = {
                "legal_hold": 0,
                "data_subject_request": 1,
                "do_not_contact_request": 2,
                "complaint": 3,
                "unsubscribe": 4,
                "consent_revoked": 5,
                "dialing_do_not_call": 6,
                "operator_block": 7,
            }
            winner = min(
                matching,
                key=lambda suppression: (
                    precedence[suppression.scope],
                    reason_precedence.get(suppression.reason, 999),
                    suppression.occurred_at,
                    suppression.suppression_id,
                ),
            )
            reasons.append(scope_code[winner.scope])

        if snapshot.lifecycle_state in TERMINAL_LIFECYCLE:
            reasons.append("LIFECYCLE_TERMINAL")
        elif snapshot.lifecycle_state not in CONTACTABLE_LIFECYCLE:
            reasons.append("LIFECYCLE_NOT_CONTACTABLE")

        if not candidate.consent_granted:
            reasons.append("CONSENT_MISSING")
        if candidate.channel == "voice" and not candidate.dialing_eligible:
            reasons.append("DIALING_NOT_ELIGIBLE")

        health = snapshot.channel_health.get(candidate.channel)
        if health is None or health.state == "unknown":
            reasons.append("CHANNEL_HEALTH_UNKNOWN")
        elif health.state in {
            "hard_bounce", "complained", "unsubscribed", "suppressed", "invalid"
        }:
            reasons.append("CHANNEL_HEALTH_BLOCKED")
        elif health.state == "possible" and not self._value(
            "channel_health", "possible_is_contactable", default=False
        ):
            reasons.append("CHANNEL_HEALTH_POLICY_GATED")
        elif health.state == "soft_bounce":
            retry_at = _utc(health.occurred_at) + timedelta(
                seconds=int(
                    self._value(
                        "channel_health",
                        "soft_bounce_retry_after_seconds",
                        default=0,
                    )
                )
            )
            if retry_at > now:
                reasons.append("CHANNEL_HEALTH_DEFERRED")
                temporal_until.append(retry_at)

        if not candidate.active:
            reasons.append("CAMPAIGN_NOT_ACTIVE")
        if not candidate.version_approved:
            reasons.append("CAMPAIGN_VERSION_NOT_APPROVED")
        if candidate.channel in {"email", "sms", "whatsapp"}:
            if candidate.sender_identity_id is None:
                reasons.append("SENDER_IDENTITY_UNAVAILABLE")
            elif not candidate.sender_authorized:
                reasons.append("SENDER_IDENTITY_NOT_AUTHORIZED")

        execution = self.policy.channel_execution.get(candidate.channel, {})
        if mode == "execute" and execution.get("execution") in {
            "not_supported_in_v1",
            "blocked_pending_dependency",
        }:
            reasons.append("CHANNEL_EXECUTION_NOT_SUPPORTED")

        if any(
            exposure.campaign_id == candidate.campaign_id
            and exposure.campaign_version == candidate.campaign_version
            and exposure.channel == candidate.channel
            and exposure.touch_index == candidate.touch_index
            for exposure in snapshot.exposures
        ):
            reasons.append("DUPLICATE_TOUCH")

        if snapshot.cooling_until is not None and _utc(snapshot.cooling_until) > now:
            reasons.append("COOLING_PERIOD_ACTIVE")
            temporal_until.append(_utc(snapshot.cooling_until))

        max_cycles = self._value("reactivation", "max_cycles", default=0)
        if (
            snapshot.lifecycle_state == "REACTIVATION"
            and snapshot.reactivation_cycles >= int(max_cycles)
        ):
            reasons.append("REACTIVATION_LIMIT_REACHED")

        exposure_cfg = self.policy.values.get("exposure", {})
        max_lifetime = int(exposure_cfg.get("max_lifetime_all_campaigns") or 0)
        if max_lifetime and len(snapshot.exposures) >= max_lifetime:
            reasons.append("LIFETIME_EXPOSURE_CAP_REACHED")
        same_campaign = [
            exposure
            for exposure in snapshot.exposures
            if exposure.campaign_id == candidate.campaign_id
        ]
        max_campaign_lifetime = int(
            exposure_cfg.get("max_lifetime_per_campaign") or 0
        )
        if max_campaign_lifetime and len(same_campaign) >= max_campaign_lifetime:
            reasons.append("LIFETIME_EXPOSURE_CAP_REACHED")

        recent_window = int(exposure_cfg.get("recent_window_seconds") or 0)
        recent_cutoff = now - timedelta(seconds=recent_window)
        recent = [
            exposure
            for exposure in snapshot.exposures
            if recent_window and _utc(exposure.reserved_at) >= recent_cutoff
        ]
        max_recent = int(exposure_cfg.get("max_recent_all_campaigns") or 0)
        if max_recent and len(recent) >= max_recent:
            reasons.append("RECENT_WINDOW_CAP_REACHED")
            temporal_until.append(
                min(_utc(e.reserved_at) for e in recent)
                + timedelta(seconds=recent_window)
            )

        channel_cfg = self.policy.values.get("channel_caps", {}).get(
            candidate.channel, {}
        )
        channel_window = int(channel_cfg.get("window_seconds") or 0)
        channel_cutoff = now - timedelta(seconds=channel_window)
        channel_recent = [
            exposure
            for exposure in snapshot.exposures
            if channel_window
            and exposure.channel == candidate.channel
            and _utc(exposure.reserved_at) >= channel_cutoff
        ]
        max_channel = int(channel_cfg.get("max_touches") or 0)
        if max_channel and len(channel_recent) >= max_channel:
            reasons.append("CHANNEL_CAP_REACHED")
            temporal_until.append(
                min(_utc(e.reserved_at) for e in channel_recent)
                + timedelta(seconds=channel_window)
            )

        campaign_cfg = self.policy.values.get("campaign", {})
        cooldown = int(campaign_cfg.get("cooldown_seconds") or 0)
        if same_campaign and cooldown:
            latest = max(_utc(e.reserved_at) for e in same_campaign)
            cooldown_until = latest + timedelta(seconds=cooldown)
            if cooldown_until > now:
                reasons.append("CAMPAIGN_COOLDOWN_ACTIVE")
                temporal_until.append(cooldown_until)

        version_count = sum(
            1
            for exposure in snapshot.exposures
            if exposure.campaign_id == candidate.campaign_id
            and exposure.campaign_version == candidate.campaign_version
        )
        max_per_version = int(campaign_cfg.get("max_touches_per_version") or 0)
        if max_per_version and version_count >= max_per_version:
            reasons.append("CAMPAIGN_VERSION_EXHAUSTED")

        ordered = _sort_reasons(reasons)
        next_at = max(temporal_until) if temporal_until else None
        if ordered and not set(ordered) <= TEMPORAL_REASONS:
            next_at = None
        return ordered, next_at

    def _value(self, section: str, key: str, *, default: Any) -> Any:
        value = self.policy.values.get(section, {}).get(key)
        return default if value is None else value

    def _decision(
        self,
        snapshot: LeadSnapshot,
        candidates: Sequence[CandidateDecision],
        selected: CandidateDecision | None,
        reasons: tuple[str, ...],
        next_eligible_at: datetime | None,
        mode: str,
        evaluated_at: datetime,
    ) -> NextActionDecision:
        body = {
            "tenant_id": snapshot.tenant_id,
            "lead_id": snapshot.lead_id,
            "lifecycle_version": snapshot.lifecycle_version,
            "mode": mode,
            "policy_version": self.policy.policy_version,
            "selected": _candidate_payload(selected),
            "reason_codes": list(reasons),
            "candidates": [_candidate_payload(item) for item in candidates],
        }
        digest = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, separators=(",", ":"), default=str
            ).encode()
        ).hexdigest()
        return NextActionDecision(
            eligible=selected is not None,
            selected=selected,
            reason_codes=reasons,
            candidates=tuple(candidates),
            next_eligible_at=next_eligible_at,
            policy_version=self.policy.policy_version,
            decision_hash=digest,
        )


@dataclass
class PostgresCampaignRecyclingStore:
    pool: asyncpg.Pool

    async def transition_lifecycle(
        self,
        *,
        tenant_id: str,
        lead_id: str,
        from_state: str | None,
        to_state: str,
        reason_code: str,
        source: str,
        correlation_id: str,
        evidence_hash: str,
        evidence_ref: str | None = None,
        occurred_at: datetime | None = None,
    ) -> int:
        if to_state not in LEGAL_TRANSITIONS.get(from_state, frozenset()):
            raise CampaignRecyclingConflict(
                f"illegal lifecycle transition {from_state!r}->{to_state!r}"
            )
        occurred_at = _utc(occurred_at or datetime.now(UTC))
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    """
                    SELECT state, version
                    FROM mcr_lead_lifecycle_current
                    WHERE tenant_id=$1 AND lead_id=$2
                    FOR UPDATE
                    """,
                    tenant_id,
                    lead_id,
                )
                actual_from = current["state"] if current else None
                if actual_from != from_state:
                    raise CampaignRecyclingConflict(
                        f"lifecycle version conflict: expected {from_state!r}, current {actual_from!r}"
                    )
                version = int(current["version"]) + 1 if current else 1
                if current is None:
                    await conn.execute(
                        """
                        INSERT INTO mcr_lead_lifecycle_current
                          (tenant_id,lead_id,state,version,updated_at)
                        VALUES ($1,$2,$3,$4,$5)
                        """,
                        tenant_id,
                        lead_id,
                        to_state,
                        version,
                        occurred_at,
                    )
                else:
                    result = await conn.execute(
                        """
                        UPDATE mcr_lead_lifecycle_current
                        SET state=$3, version=$4, updated_at=$5
                        WHERE tenant_id=$1 AND lead_id=$2 AND version=$6
                        """,
                        tenant_id,
                        lead_id,
                        to_state,
                        version,
                        occurred_at,
                        int(current["version"]),
                    )
                    if result != "UPDATE 1":
                        raise CampaignRecyclingConflict(
                            "lifecycle optimistic update lost"
                        )
                await conn.execute(
                    """
                    INSERT INTO mcr_lead_lifecycle_events
                      (tenant_id,lead_id,version,from_state,to_state,reason_code,source,
                       occurred_at,recorded_at,correlation_id,evidence_hash,evidence_ref)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),$9,$10,$11)
                    """,
                    tenant_id,
                    lead_id,
                    version,
                    from_state,
                    to_state,
                    reason_code,
                    source,
                    occurred_at,
                    correlation_id,
                    evidence_hash,
                    evidence_ref,
                )
                return version

    async def record_channel_health(
        self,
        *,
        tenant_id: str,
        lead_id: str,
        channel: Channel,
        address_ref: str,
        state: str,
        source: str,
        reason_code: str,
        occurred_at: datetime,
        evidence_hash: str,
        correlation_id: str,
        suppression_id: UUID | None = None,
        suppression_scope: str | None = None,
        suppression_reason: str | None = None,
        suppression_requested_by: str | None = None,
        campaign_id: str | None = None,
    ) -> int:
        if state not in CHANNEL_HEALTH_STATES:
            raise CampaignRecyclingConflict(f"unknown channel-health state {state}")
        if channel not in CHANNEL_ORDER:
            raise CampaignRecyclingConflict(f"unknown campaign channel {channel}")
        if state in SUPPRESSION_REQUIRED_HEALTH and not all(
            (suppression_id, suppression_scope, suppression_reason, suppression_requested_by)
        ):
            raise CampaignRecyclingConflict(
                f"channel-health state {state} requires an atomic suppression record"
            )
        occurred_at = _utc(occurred_at)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    """
                    SELECT state, health_version
                    FROM mcr_channel_health
                    WHERE tenant_id=$1 AND lead_id=$2 AND channel=$3 AND address_ref=$4
                    FOR UPDATE
                    """,
                    tenant_id,
                    lead_id,
                    channel,
                    address_ref,
                )
                version = int(current["health_version"]) + 1 if current else 1
                previous_state = current["state"] if current else None
                await conn.execute(
                    """
                    INSERT INTO mcr_channel_health
                      (tenant_id,lead_id,channel,address_ref,state,previous_state,
                       source,reason_code,occurred_at,recorded_at,evidence_hash,
                       health_version,correlation_id,updated_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10,$11,$12,now())
                    ON CONFLICT (tenant_id,lead_id,channel,address_ref)
                    DO UPDATE SET
                      state=EXCLUDED.state,
                      previous_state=mcr_channel_health.state,
                      source=EXCLUDED.source,
                      reason_code=EXCLUDED.reason_code,
                      occurred_at=EXCLUDED.occurred_at,
                      recorded_at=now(),
                      evidence_hash=EXCLUDED.evidence_hash,
                      health_version=mcr_channel_health.health_version + 1,
                      correlation_id=EXCLUDED.correlation_id,
                      updated_at=now()
                    """,
                    tenant_id,
                    lead_id,
                    channel,
                    address_ref,
                    state,
                    previous_state,
                    source,
                    reason_code,
                    occurred_at,
                    evidence_hash,
                    version,
                    correlation_id,
                )
                if state in SUPPRESSION_REQUIRED_HEALTH:
                    assert suppression_id is not None
                    assert suppression_scope is not None
                    assert suppression_reason is not None
                    assert suppression_requested_by is not None
                    await conn.execute(
                        """
                        INSERT INTO mcr_suppressions
                          (tenant_id,suppression_id,lead_id,scope,channel,campaign_id,
                           reason,source,occurred_at,evidence_hash,requested_by)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                        ON CONFLICT (tenant_id,suppression_id) DO NOTHING
                        """,
                        tenant_id,
                        suppression_id,
                        lead_id,
                        suppression_scope,
                        channel if suppression_scope in {"channel", "campaign_channel"} else None,
                        campaign_id,
                        suppression_reason,
                        source,
                        occurred_at,
                        evidence_hash,
                        suppression_requested_by,
                    )
                return version

    async def add_suppression(
        self,
        *,
        tenant_id: str,
        suppression_id: UUID,
        lead_id: str,
        scope: str,
        reason: str,
        source: str,
        occurred_at: datetime,
        evidence_hash: str,
        requested_by: str,
        channel: str | None = None,
        campaign_id: str | None = None,
    ) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO mcr_suppressions
                  (tenant_id,suppression_id,lead_id,scope,channel,campaign_id,reason,
                   source,occurred_at,evidence_hash,requested_by)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                ON CONFLICT (tenant_id,suppression_id) DO NOTHING
                RETURNING suppression_id
                """,
                tenant_id,
                suppression_id,
                lead_id,
                scope,
                channel,
                campaign_id,
                reason,
                source,
                _utc(occurred_at),
                evidence_hash,
                requested_by,
            )
        return row is not None

    async def reserve_exposure_and_command(
        self,
        *,
        tenant_id: str,
        lead_id: str,
        campaign_id: str,
        campaign_version: int,
        channel: Channel,
        touch_index: int,
        exposure_id: UUID,
        decision_id: UUID,
        policy_version: str,
        sender_identity_id: UUID | None,
        idempotency_key: str,
        command: CommandEnvelope,
        command_service: CommandService,
        authenticated_subject: str,
        authenticated_client_id: str,
        reserved_at: datetime | None = None,
    ) -> tuple[bool, CommandOperation | None]:
        command_service.validate_submission(
            command,
            authenticated_subject=authenticated_subject,
            authenticated_client_id=authenticated_client_id,
        )
        store = command_service.store
        if not isinstance(store, PostgresCommandStore) or store.pool is not self.pool:
            raise CampaignRecyclingError(
                "campaign reservation requires the shared PostgresCommandStore"
            )
        if command.tenant_id != tenant_id or command.idempotency_key != idempotency_key:
            raise CampaignRecyclingConflict(
                "exposure and command tenant/idempotency identities must match"
            )
        reserved_at = _utc(reserved_at or datetime.now(UTC))

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO mcr_exposures
                      (exposure_id,tenant_id,lead_id,campaign_id,campaign_version,
                       channel,touch_index,idempotency_key,command_id,decision_id,
                       policy_version,sender_identity_id,status,engagement_outcome,
                       negative_outcome,reserved_at,status_at,updated_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'reserved',
                            'none','none',$13,$13,$13)
                    ON CONFLICT DO NOTHING
                    RETURNING exposure_id
                    """,
                    exposure_id,
                    tenant_id,
                    lead_id,
                    campaign_id,
                    campaign_version,
                    channel,
                    touch_index,
                    idempotency_key,
                    command.command_id,
                    decision_id,
                    policy_version,
                    sender_identity_id,
                    reserved_at,
                )
                if row is None:
                    existing = await conn.fetchrow(
                        """
                        SELECT exposure_id, lead_id, campaign_id, campaign_version,
                               channel, touch_index, idempotency_key, command_id,
                               decision_id, policy_version, sender_identity_id
                        FROM mcr_exposures
                        WHERE tenant_id=$1 AND
                          ((lead_id=$2 AND campaign_id=$3 AND campaign_version=$4
                            AND channel=$5 AND touch_index=$6)
                           OR idempotency_key=$7
                           OR command_id=$8)
                        ORDER BY reserved_at
                        LIMIT 1
                        FOR UPDATE
                        """,
                        tenant_id,
                        lead_id,
                        campaign_id,
                        campaign_version,
                        channel,
                        touch_index,
                        idempotency_key,
                        command.command_id,
                    )
                    if existing is None:
                        raise CampaignRecyclingConflict(
                            "exposure conflict could not be reconciled"
                        )
                    if (
                        existing["lead_id"] != lead_id
                        or existing["campaign_id"] != campaign_id
                        or int(existing["campaign_version"]) != campaign_version
                        or existing["channel"] != channel
                        or int(existing["touch_index"]) != touch_index
                        or existing["idempotency_key"] != idempotency_key
                        or str(existing["command_id"]) != str(command.command_id)
                        or str(existing["decision_id"]) != str(decision_id)
                        or existing["policy_version"] != policy_version
                        or (
                            str(existing["sender_identity_id"])
                            if existing["sender_identity_id"] is not None
                            else None
                        )
                        != (str(sender_identity_id) if sender_identity_id is not None else None)
                    ):
                        raise CampaignRecyclingConflict(
                            "exposure idempotency identity conflicts with prior reservation"
                        )
                    return False, None

                operation = await store.submit_on_connection(
                    conn,
                    command,
                    authenticated_client_id=authenticated_client_id,
                    destination=ADAPTER_COMMAND_DESTINATION,
                    decision_evidence={
                        "decision_id": str(decision_id),
                        "policy_version": policy_version,
                        "exposure_id": str(exposure_id),
                    },
                )
                return True, operation


def _leaf_values(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        return [leaf for child in value.values() for leaf in _leaf_values(child)]
    return [value]


def _sort_reasons(reasons: Sequence[str] | Any) -> tuple[str, ...]:
    unique = {str(reason) for reason in reasons}
    return tuple(
        sorted(
            unique,
            key=lambda reason: (
                REASON_INDEX.get(reason, len(REASON_PRECEDENCE)),
                reason,
            ),
        )
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CampaignRecyclingPolicyError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _candidate_payload(candidate: CandidateDecision | None) -> Any:
    if candidate is None:
        return None
    return {
        "campaign_id": candidate.campaign_id,
        "campaign_version": candidate.campaign_version,
        "channel": candidate.channel,
        "touch_index": candidate.touch_index,
        "sender_identity_id": candidate.sender_identity_id,
        "disposition": candidate.disposition,
        "reason_codes": list(candidate.reason_codes),
        "next_eligible_at": candidate.next_eligible_at.isoformat()
        if candidate.next_eligible_at
        else None,
    }
