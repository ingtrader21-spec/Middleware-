from __future__ import annotations

import hashlib
from functools import lru_cache
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import asyncpg
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from app.commands import (
    CommandEnvelope,
    CommandOperation,
    CommandService,
)

ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _delivery_validator() -> Draft202012Validator:
    # Resolve only the frozen local schema resources; never fetch remote schemas.
    schemas = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (ROOT / "contracts/campaign-recycling").glob("*.schema.json")
    ]
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )
    schema = next(item for item in schemas if item["$id"].endswith(
        "/delivery-event.v1.schema.json"
    ))
    return Draft202012Validator(
        schema, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER
    )

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

DELIVERY_EVENT_TYPES = frozenset(
    {
        "accepted",
        "queued",
        "dispatched",
        "delivered",
        "deferred",
        "soft_bounce",
        "hard_bounce",
        "complaint",
        "unsubscribe",
        "open",
        "read",
        "click",
        "reply",
        "conversion",
    }
)
TRANSPORT_EVENT_STATUS = {
    "accepted": "accepted",
    "queued": "queued",
    "dispatched": "dispatched",
    "delivered": "delivered",
    "deferred": "indeterminate",
}
TRANSPORT_STATUS_RANK = {
    "reserved": 0,
    "accepted": 1,
    "queued": 2,
    "dispatched": 3,
    "indeterminate": 4,
    "delivered": 5,
    "failed": 100,
    "cancelled": 100,
    "suppressed": 100,
    "expired": 100,
}
TRANSPORT_TERMINAL = frozenset(
    {"delivered", "failed", "cancelled", "suppressed", "expired"}
)
ENGAGEMENT_RANK = {
    "none": 0,
    "open": 1,
    "read": 2,
    "click": 3,
    "reply": 4,
    "conversion": 5,
}
NEGATIVE_RANK = {
    "none": 0,
    "soft_bounce": 1,
    "hard_bounce": 2,
    "unsubscribe": 3,
    "complaint": 4,
}
HEALTH_EVENT_STATE = {
    "delivered": ("valid", "DELIVERY_CONFIRMED"),
    "soft_bounce": ("soft_bounce", "SOFT_BOUNCE"),
    "hard_bounce": ("hard_bounce", "HARD_BOUNCE"),
    "complaint": ("complained", "COMPLAINT"),
    "unsubscribe": ("unsubscribed", "UNSUBSCRIBE"),
}
HEALTH_SEVERITY = {
    "unknown": 0,
    "possible": 0,
    "valid": 1,
    "soft_bounce": 2,
    "invalid": 3,
    "hard_bounce": 3,
    "unsubscribed": 4,
    "complained": 5,
    "suppressed": 6,
}

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


HEALTH_UPDATE_PREDICATE = """
WHERE
                      EXCLUDED.occurred_at > mcr_channel_health.occurred_at
                      OR (
                        EXCLUDED.occurred_at = mcr_channel_health.occurred_at
                        AND CASE EXCLUDED.state
                          WHEN 'suppressed' THEN 6
                          WHEN 'complained' THEN 5
                          WHEN 'unsubscribed' THEN 4
                          WHEN 'hard_bounce' THEN 3
                          WHEN 'invalid' THEN 3
                          WHEN 'soft_bounce' THEN 2
                          WHEN 'valid' THEN 1
                          ELSE 0
                        END >= CASE mcr_channel_health.state
                          WHEN 'suppressed' THEN 6
                          WHEN 'complained' THEN 5
                          WHEN 'unsubscribed' THEN 4
                          WHEN 'hard_bounce' THEN 3
                          WHEN 'invalid' THEN 3
                          WHEN 'soft_bounce' THEN 2
                          WHEN 'valid' THEN 1
                          ELSE 0
                        END
                      )
                      OR (
                        EXCLUDED.occurred_at < mcr_channel_health.occurred_at
                        AND CASE EXCLUDED.state
                          WHEN 'suppressed' THEN 6
                          WHEN 'complained' THEN 5
                          WHEN 'unsubscribed' THEN 4
                          WHEN 'hard_bounce' THEN 3
                          WHEN 'invalid' THEN 3
                          WHEN 'soft_bounce' THEN 2
                          WHEN 'valid' THEN 1
                          ELSE 0
                        END > CASE mcr_channel_health.state
                          WHEN 'suppressed' THEN 6
                          WHEN 'complained' THEN 5
                          WHEN 'unsubscribed' THEN 4
                          WHEN 'hard_bounce' THEN 3
                          WHEN 'invalid' THEN 3
                          WHEN 'soft_bounce' THEN 2
                          WHEN 'valid' THEN 1
                          ELSE 0
                        END
                      )
"""

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
        if (
            snapshot.lifecycle_state == "REACTIVATION"
            and self._value(
                "reactivation", "requires_distinct_campaign_version", default=True
            )
            and any(
                exposure.campaign_id == candidate.campaign_id
                and exposure.campaign_version == candidate.campaign_version
                for exposure in snapshot.exposures
            )
        ):
            reasons.append("CAMPAIGN_VERSION_EXHAUSTED")

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
            if recent_window and _utc(exposure.reserved_at) > recent_cutoff
        ]
        max_recent = int(exposure_cfg.get("max_recent_all_campaigns") or 0)
        if max_recent and len(recent) >= max_recent:
            reasons.append("RECENT_WINDOW_CAP_REACHED")
            temporal_until.append(_cap_release_at(recent, max_recent, recent_window))

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
            and _utc(exposure.reserved_at) > channel_cutoff
        ]
        max_channel = int(channel_cfg.get("max_touches") or 0)
        if max_channel and len(channel_recent) >= max_channel:
            reasons.append("CHANNEL_CAP_REACHED")
            temporal_until.append(
                _cap_release_at(channel_recent, max_channel, channel_window)
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
        occurred_at = _utc(occurred_at or datetime.now(UTC))
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                return await _transition_lifecycle_on_connection(
                    conn,
                    tenant_id=tenant_id,
                    lead_id=lead_id,
                    expected_from=from_state,
                    to_state=to_state,
                    reason_code=reason_code,
                    source=source,
                    correlation_id=correlation_id,
                    evidence_hash=evidence_hash,
                    evidence_ref=evidence_ref,
                    occurred_at=occurred_at,
                )

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
        if state in {"complained", "unsubscribed"}:
            expected_reason = "complaint" if state == "complained" else "unsubscribe"
            if suppression_scope != "channel" or suppression_reason != expected_reason:
                raise CampaignRecyclingConflict(
                    f"{state} delivery evidence requires channel-scoped {expected_reason} suppression"
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
                committed = await conn.fetchrow(
                    f"""
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
                    {HEALTH_UPDATE_PREDICATE}
                    RETURNING health_version
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
                if committed is None:
                    # A stale/weaker signal is a no-op, not a failed delivery.
                    committed = await conn.fetchrow(
                        """SELECT health_version FROM mcr_channel_health
                        WHERE tenant_id=$1 AND lead_id=$2 AND channel=$3 AND address_ref=$4""",
                        tenant_id, lead_id, channel, address_ref,
                    )
                if committed is None:
                    raise CampaignRecyclingConflict(
                        "channel-health upsert returned no committed version"
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
                return int(committed["health_version"])

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

    async def apply_delivery_event(
        self,
        event: Mapping[str, Any],
        *,
        policy: PolicyProfile,
        address_ref: str | None = None,
    ) -> dict[str, Any]:
        errors = sorted(_delivery_validator().iter_errors(dict(event)), key=str)
        if errors:
            raise CampaignRecyclingConflict(
                f"invalid normalized delivery event: {errors[0].message}"
            )
        event_type = str(event["event_type"])
        source = str(event["source"])
        tenant_id = str(event["tenant_id"])
        lead_id = str(event["lead_id"])
        channel = str(event["channel"])
        if event_type not in DELIVERY_EVENT_TYPES:
            raise CampaignRecyclingConflict(
                f"unknown normalized delivery event type {event_type}"
            )
        if channel not in CHANNEL_ORDER:
            raise CampaignRecyclingConflict(f"unknown delivery channel {channel}")
        if source == "klyrow" and channel != "email":
            raise CampaignRecyclingConflict("Klyrow normalized events must be email")
        if source == "telnexa" and channel != "sms":
            raise CampaignRecyclingConflict("Telnexa normalized events must be sms")
        if source == "evolution" and channel != "whatsapp":
            raise CampaignRecyclingConflict(
                "Evolution normalized events must be whatsapp"
            )

        event_id = str(event["event_id"])
        correlation_id = str(event["correlation_id"])
        payload_hash = str(event["payload_hash"])
        if len(payload_hash) != 64 or any(
            char not in "0123456789abcdef" for char in payload_hash
        ):
            raise CampaignRecyclingConflict(
                "delivery event payload_hash must be lowercase sha256"
            )
        hash_event = {
            key: value
            for key, value in dict(event).items()
            if key not in {"received_at", "payload_hash"}
        }
        canonical_payload = json.dumps(
            hash_event,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            default=_json_default,
        ).encode("utf-8")
        expected_payload_hash = hashlib.sha256(canonical_payload).hexdigest()
        if payload_hash != expected_payload_hash:
            raise CampaignRecyclingConflict(
                "delivery event payload_hash does not match canonical event"
            )
        occurred_at = _coerce_event_datetime(event["occurred_at"])
        received_at = _coerce_event_datetime(event["received_at"])
        campaign_id = event.get("campaign_id")
        campaign_version = event.get("campaign_version")
        exposure_key = event.get("exposure_idempotency_key")
        message_id = event.get("message_id")
        provider_message_id = event.get("provider_message_id")
        origin = event.get("origin")
        origin_inbox: str | None = None
        origin_event_id: str | None = None
        if origin is not None:
            if not isinstance(origin, Mapping):
                raise CampaignRecyclingConflict("delivery event origin must be an object")
            origin_inbox = str(origin.get("inbox") or "")
            origin_event_id = str(origin.get("inbox_event_id") or "")
            if not origin_inbox or not origin_event_id:
                raise CampaignRecyclingConflict(
                    "delivery event origin requires inbox and inbox_event_id"
                )
        normalized_json = json.dumps(
            dict(event),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            default=_json_default,
        )
        health_effect = HEALTH_EVENT_STATE.get(event_type)
        if health_effect is not None and not address_ref:
            raise CampaignRecyclingConflict(
                f"delivery event {event_type} requires an opaque address_ref"
            )

        notes: list[str] = []
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                inserted = await conn.fetchrow(
                    """
                    INSERT INTO mcr_delivery_events (
                      tenant_id,source,event_id,event_type,lead_id,channel,campaign_id,
                      campaign_version,exposure_idempotency_key,address_ref,provider,
                      message_id,provider_message_id,correlation_id,causation_id,
                      payload_hash,occurred_at,received_at,origin_inbox,origin_event_id,
                      normalized_event,projection_state
                    ) VALUES (
                      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                      $16,$17,$18,$19,$20,$21::jsonb,'pending'
                    )
                    ON CONFLICT DO NOTHING
                    RETURNING id, projection_state
                    """,
                    tenant_id,
                    source,
                    event_id,
                    event_type,
                    lead_id,
                    channel,
                    campaign_id,
                    campaign_version,
                    exposure_key,
                    address_ref,
                    event.get("provider"),
                    message_id,
                    provider_message_id,
                    correlation_id,
                    event.get("causation_id"),
                    payload_hash,
                    occurred_at,
                    received_at,
                    origin_inbox,
                    origin_event_id,
                    normalized_json,
                )
                if inserted is None:
                    existing = await conn.fetchrow(
                        """
                        SELECT id, source, event_id, payload_hash, origin_inbox,
                               origin_event_id, projection_state
                        FROM mcr_delivery_events
                        WHERE tenant_id=$1
                          AND (
                            (source=$2 AND event_id=$3)
                            OR (
                              $4::text IS NOT NULL
                              AND origin_inbox=$4
                              AND origin_event_id=$5
                            )
                          )
                        ORDER BY id
                        LIMIT 1
                        FOR UPDATE
                        """,
                        tenant_id,
                        source,
                        event_id,
                        origin_inbox,
                        origin_event_id,
                    )
                    if existing is None:
                        raise CampaignRecyclingConflict(
                            "delivery event conflict could not be reconciled"
                        )
                    if (
                        existing["source"] != source
                        or existing["event_id"] != event_id
                        or existing["payload_hash"] != payload_hash
                        or existing["origin_inbox"] != origin_inbox
                        or existing["origin_event_id"] != origin_event_id
                    ):
                        raise CampaignRecyclingConflict(
                            "delivery event identity was reused with different evidence"
                        )
                    event_row_id = int(existing["id"])
                    if existing["projection_state"] == "applied":
                        return {
                            "event_id": event_id,
                            "duplicate": True,
                            "projection_state": "applied",
                            "projection_note": None,
                        }
                else:
                    event_row_id = int(inserted["id"])

                exposure = None
                if exposure_key is not None:
                    exposure = await conn.fetchrow(
                        """
                        SELECT exposure_id, lead_id, campaign_id, campaign_version,
                               channel, status, engagement_outcome, negative_outcome,
                               message_id, provider_message_id, status_at,
                               engagement_outcome_at, negative_outcome_at, ledger_version
                        FROM mcr_exposures
                        WHERE tenant_id=$1 AND idempotency_key=$2
                        FOR UPDATE
                        """,
                        tenant_id,
                        str(exposure_key),
                    )
                    if exposure is None:
                        notes.append("exposure_not_found")
                    else:
                        if exposure["lead_id"] != lead_id or exposure["channel"] != channel:
                            raise CampaignRecyclingConflict(
                                "delivery event does not match exposure lead/channel"
                            )
                        if (
                            campaign_id is not None
                            and exposure["campaign_id"] != campaign_id
                        ):
                            raise CampaignRecyclingConflict(
                                "delivery event campaign_id does not match exposure"
                            )
                        if (
                            campaign_version is not None
                            and int(exposure["campaign_version"])
                            != int(campaign_version)
                        ):
                            raise CampaignRecyclingConflict(
                                "delivery event campaign_version does not match exposure"
                            )
                        if (
                            message_id is not None
                            and exposure["message_id"] is not None
                            and str(exposure["message_id"]) != str(message_id)
                        ):
                            raise CampaignRecyclingConflict(
                                "delivery event message_id conflicts with exposure"
                            )
                        if (
                            provider_message_id is not None
                            and exposure["provider_message_id"] is not None
                            and str(exposure["provider_message_id"])
                            != str(provider_message_id)
                        ):
                            raise CampaignRecyclingConflict(
                                "delivery event provider_message_id conflicts with exposure"
                            )
                        status = str(exposure["status"])
                        new_status = status
                        mapped_status = TRANSPORT_EVENT_STATUS.get(event_type)
                        if (
                            mapped_status is not None
                            and status not in TRANSPORT_TERMINAL
                            and TRANSPORT_STATUS_RANK[mapped_status]
                            > TRANSPORT_STATUS_RANK.get(status, -1)
                        ):
                            new_status = mapped_status

                        engagement = str(exposure["engagement_outcome"])
                        new_engagement = engagement
                        if (
                            event_type in ENGAGEMENT_RANK
                            and ENGAGEMENT_RANK[event_type]
                            > ENGAGEMENT_RANK.get(engagement, -1)
                        ):
                            new_engagement = event_type

                        negative = str(exposure["negative_outcome"])
                        new_negative = negative
                        if (
                            event_type in NEGATIVE_RANK
                            and NEGATIVE_RANK[event_type]
                            > NEGATIVE_RANK.get(negative, -1)
                        ):
                            new_negative = event_type

                        status_changed = new_status != status
                        engagement_changed = new_engagement != engagement
                        negative_changed = new_negative != negative
                        await conn.execute(
                            """
                            UPDATE mcr_exposures
                            SET status=$3,
                                engagement_outcome=$4,
                                negative_outcome=$5,
                                message_id=COALESCE(message_id,$6),
                                provider_message_id=COALESCE(provider_message_id,$7),
                                dispatched_at=CASE
                                  WHEN $8='dispatched' THEN COALESCE(dispatched_at,$9)
                                  ELSE dispatched_at END,
                                accepted_at=CASE
                                  WHEN $8='accepted' THEN COALESCE(accepted_at,$9)
                                  ELSE accepted_at END,
                                delivered_at=CASE
                                  WHEN $8='delivered' THEN COALESCE(delivered_at,$9)
                                  ELSE delivered_at END,
                                status_at=CASE WHEN $10 THEN $9 ELSE status_at END,
                                engagement_outcome_at=CASE
                                  WHEN $11 THEN $9 ELSE engagement_outcome_at END,
                                negative_outcome_at=CASE
                                  WHEN $12 THEN $9 ELSE negative_outcome_at END,
                                updated_at=now(),
                                ledger_version=ledger_version + CASE
                                  WHEN $10 OR $11 OR $12 OR
                                       (message_id IS NULL AND $6 IS NOT NULL) OR
                                       (provider_message_id IS NULL AND $7 IS NOT NULL)
                                  THEN 1 ELSE 0 END
                            WHERE tenant_id=$1 AND exposure_id=$2
                            """,
                            tenant_id,
                            exposure["exposure_id"],
                            new_status,
                            new_engagement,
                            new_negative,
                            message_id,
                            provider_message_id,
                            event_type,
                            occurred_at,
                            status_changed,
                            engagement_changed,
                            negative_changed,
                        )
                elif event_type not in {"unsubscribe", "conversion"}:
                    notes.append("exposure_identity_missing")

                if health_effect is not None:
                    target_health, health_reason = health_effect
                    assert address_ref is not None
                    current_health = await conn.fetchrow(
                        """
                        SELECT state, health_version, occurred_at
                        FROM mcr_channel_health
                        WHERE tenant_id=$1 AND lead_id=$2 AND channel=$3
                          AND address_ref=$4
                        FOR UPDATE
                        """,
                        tenant_id,
                        lead_id,
                        channel,
                        address_ref,
                    )
                    if event_type == "soft_bounce":
                        escalation_count = policy.values.get(
                            "channel_health", {}
                        ).get("soft_bounce_escalation_count")
                        if escalation_count is None:
                            notes.append("soft_bounce_escalation_not_configured")
                        else:
                            # Consecutive soft bounces for this address since the
                            # last confirmed delivery, including this event.
                            streak = await conn.fetchrow(
                                """
                                SELECT count(*) AS soft_bounce_count
                                FROM mcr_delivery_events
                                WHERE tenant_id=$1 AND lead_id=$2 AND channel=$3
                                  AND address_ref=$4 AND event_type='soft_bounce'
                                  AND occurred_at > COALESCE(
                                    (SELECT max(occurred_at)
                                     FROM mcr_delivery_events
                                     WHERE tenant_id=$1 AND lead_id=$2
                                       AND channel=$3 AND address_ref=$4
                                       AND event_type='delivered'),
                                    '-infinity'::timestamptz
                                  )
                                """,
                                tenant_id,
                                lead_id,
                                channel,
                                address_ref,
                            )
                            if streak is None:
                                raise CampaignRecyclingConflict(
                                    "soft-bounce streak could not be read"
                                )
                            if int(streak["soft_bounce_count"]) >= int(
                                escalation_count
                            ):
                                target_health = "hard_bounce"
                                health_reason = "SOFT_BOUNCE_ESCALATED"
                    health_source = {
                        "klyrow": "klyrow_delivery_event",
                        "telnexa": "telnexa_delivery_event",
                        "evolution": "evolution_delivery_event",
                    }.get(source, "leads_authority")
                    await conn.execute(
                        f"""
                        INSERT INTO mcr_channel_health (
                          tenant_id,lead_id,channel,address_ref,state,previous_state,
                          source,reason_code,occurred_at,recorded_at,evidence_hash,
                          health_version,correlation_id,updated_at
                        ) VALUES (
                          $1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10,1,$11,now()
                        )
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
                    {HEALTH_UPDATE_PREDICATE}
                        """,
                        tenant_id,
                        lead_id,
                        channel,
                        address_ref,
                        target_health,
                        current_health["state"]
                        if current_health is not None
                        else None,
                        health_source,
                        health_reason,
                        occurred_at,
                        payload_hash,
                        correlation_id,
                    )
                    if event_type in {"complaint", "unsubscribe"}:
                        suppression_id = uuid5(
                            NAMESPACE_URL,
                            (
                                f"mcr:{tenant_id}:{source}:{event_id}:"
                                f"suppression:{channel}"
                            ),
                        )
                        await conn.execute(
                            """
                            INSERT INTO mcr_suppressions (
                              tenant_id,suppression_id,lead_id,scope,channel,campaign_id,
                              reason,source,occurred_at,evidence_hash,requested_by
                            ) VALUES (
                              $1,$2,$3,'channel',$4,NULL,$5,$6,$7,$8,$9
                            )
                            ON CONFLICT (tenant_id,suppression_id) DO NOTHING
                            """,
                            tenant_id,
                            suppression_id,
                            lead_id,
                            channel,
                            event_type,
                            source,
                            occurred_at,
                            payload_hash,
                            f"delivery-event:{source}",
                        )

                lifecycle_target: str | None = None
                lifecycle_reason: str | None = None
                automated = bool(event.get("automated_suspected", False))
                if event_type in {"click", "reply"} and not (
                    event_type == "click" and automated
                ):
                    lifecycle_target = "ENGAGED"
                    lifecycle_reason = "STRONG_ENGAGEMENT_RECORDED"
                elif event_type == "conversion":
                    lifecycle_target = "CONVERTED"
                    lifecycle_reason = "CONVERSION_RECORDED"

                if lifecycle_target is not None and lifecycle_reason is not None:
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
                    if current is None:
                        notes.append("lifecycle_state_missing")
                    else:
                        current_state = str(current["state"])
                        if (
                            lifecycle_target == "ENGAGED"
                            and current_state == "ELIGIBLE"
                        ):
                            await _transition_lifecycle_on_connection(
                                conn,
                                tenant_id=tenant_id,
                                lead_id=lead_id,
                                expected_from="ELIGIBLE",
                                to_state="ACTIVE_CYCLE",
                                reason_code="CYCLE_STARTED",
                                source="delivery_event",
                                correlation_id=correlation_id,
                                evidence_hash=payload_hash,
                                evidence_ref=f"delivery:{source}:{event_id}",
                                occurred_at=occurred_at,
                            )
                            current_state = "ACTIVE_CYCLE"
                        if lifecycle_target in LEGAL_TRANSITIONS.get(
                            current_state, frozenset()
                        ):
                            await _transition_lifecycle_on_connection(
                                conn,
                                tenant_id=tenant_id,
                                lead_id=lead_id,
                                expected_from=current_state,
                                to_state=lifecycle_target,
                                reason_code=lifecycle_reason,
                                source=(
                                    "odoo_conversion"
                                    if event_type == "conversion" and source == "odoo"
                                    else "delivery_event"
                                ),
                                correlation_id=correlation_id,
                                evidence_hash=payload_hash,
                                evidence_ref=f"delivery:{source}:{event_id}",
                                occurred_at=occurred_at,
                            )
                        elif current_state not in {
                            lifecycle_target,
                            "CONVERTED",
                            "SUPPRESSED",
                        }:
                            notes.append(
                                f"lifecycle_transition_not_applicable:"
                                f"{current_state}->{lifecycle_target}"
                            )

                projection_state = "partial" if notes else "applied"
                projection_note = ";".join(notes) if notes else None
                await conn.execute(
                    """
                    UPDATE mcr_delivery_events
                    SET projection_state=$2,
                        projection_note=$3,
                        projected_at=now()
                    WHERE id=$1
                    """,
                    event_row_id,
                    projection_state,
                    projection_note,
                )
                return {
                    "event_id": event_id,
                    "duplicate": False,
                    "projection_state": projection_state,
                    "projection_note": projection_note,
                }

    async def journey(
        self,
        *,
        tenant_id: str,
        lead_id: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit < 1 or limit > 200:
            raise CampaignRecyclingConflict("journey limit must be between 1 and 200")
        async with self.pool.acquire() as conn:
            current = await conn.fetchrow(
                """
                SELECT tenant_id, lead_id, state, version, updated_at
                FROM mcr_lead_lifecycle_current
                WHERE tenant_id=$1 AND lead_id=$2
                """,
                tenant_id,
                lead_id,
            )
            lifecycle = await conn.fetch(
                """
                SELECT event_id, transition_id, version, from_state, to_state, reason_code, source,
                       occurred_at, recorded_at, correlation_id, evidence_hash,
                       evidence_ref
                FROM mcr_lead_lifecycle_events
                WHERE tenant_id=$1 AND lead_id=$2
                ORDER BY version DESC
                LIMIT $3
                """,
                tenant_id,
                lead_id,
                limit,
            )
            health = await conn.fetch(
                """
                SELECT channel, address_ref, state, previous_state, source,
                       reason_code, occurred_at, recorded_at, evidence_hash,
                       health_version, correlation_id, updated_at
                FROM mcr_channel_health
                WHERE tenant_id=$1 AND lead_id=$2
                ORDER BY channel, address_ref
                """,
                tenant_id,
                lead_id,
            )
            suppressions = await conn.fetch(
                """
                SELECT suppression_id, scope, channel, campaign_id, reason, source,
                       occurred_at, evidence_hash, requested_by, created_at
                FROM mcr_suppressions
                WHERE tenant_id=$1 AND lead_id=$2
                ORDER BY occurred_at, suppression_id
                """,
                tenant_id,
                lead_id,
            )
            exposures = await conn.fetch(
                """
                SELECT exposure_id, campaign_id, campaign_version, channel, touch_index,
                       idempotency_key, command_id, correlation_id, decision_id, policy_version,
                       sender_identity_id, status, engagement_outcome, negative_outcome,
                       message_id, provider_message_id, reserved_at, dispatched_at,
                       accepted_at, delivered_at, status_at, engagement_outcome_at,
                       negative_outcome_at, updated_at, ledger_version
                FROM mcr_exposures
                WHERE tenant_id=$1 AND lead_id=$2
                ORDER BY reserved_at DESC, exposure_id
                LIMIT $3
                """,
                tenant_id,
                lead_id,
                limit,
            )
        return {
            "tenant_id": tenant_id,
            "lead_id": lead_id,
            "current": dict(current) if current is not None else None,
            "lifecycle": [dict(row) for row in reversed(lifecycle)],
            "channel_health": [dict(row) for row in health],
            "suppressions": [dict(row) for row in suppressions],
            "exposures": [dict(row) for row in reversed(exposures)],
            "truncated": len(lifecycle) == limit or len(exposures) == limit,
        }

    async def load_snapshot(
        self,
        *,
        tenant_id: str,
        lead_id: str,
        address_refs: Mapping[Channel, str],
        policy: PolicyProfile,
    ) -> LeadSnapshot:
        max_lifetime = int(
            policy.values.get("exposure", {}).get("max_lifetime_all_campaigns") or 0
        )
        exposure_limit = max(1, max_lifetime + 1 if max_lifetime else 1)
        async with self.pool.acquire() as conn:
            current = await conn.fetchrow(
                """
                SELECT state, version, updated_at
                FROM mcr_lead_lifecycle_current
                WHERE tenant_id=$1 AND lead_id=$2
                """,
                tenant_id,
                lead_id,
            )
            if current is None:
                raise CampaignRecyclingConflict("lead lifecycle state does not exist")

            health_rows = []
            for channel, address_ref in address_refs.items():
                if channel not in CHANNEL_ORDER:
                    raise CampaignRecyclingConflict(f"unknown campaign channel {channel}")
                row = await conn.fetchrow(
                    """
                    SELECT channel, address_ref, state, occurred_at
                    FROM mcr_channel_health
                    WHERE tenant_id=$1 AND lead_id=$2 AND channel=$3 AND address_ref=$4
                    """,
                    tenant_id,
                    lead_id,
                    channel,
                    address_ref,
                )
                if row is not None:
                    health_rows.append(row)

            suppression_rows = await conn.fetch(
                """
                SELECT suppression_id, scope, channel, campaign_id, reason, occurred_at
                FROM mcr_suppressions
                WHERE tenant_id=$1 AND lead_id=$2
                ORDER BY occurred_at, suppression_id
                """,
                tenant_id,
                lead_id,
            )
            exposure_rows = await conn.fetch(
                """
                SELECT campaign_id, campaign_version, channel, touch_index, status,
                       reserved_at, engagement_outcome, negative_outcome
                FROM mcr_exposures
                WHERE tenant_id=$1 AND lead_id=$2
                ORDER BY reserved_at DESC, exposure_id
                LIMIT $3
                """,
                tenant_id,
                lead_id,
                exposure_limit,
            )
            lifecycle_rows = await conn.fetch(
                """
                SELECT to_state, occurred_at
                FROM mcr_lead_lifecycle_events
                WHERE tenant_id=$1 AND lead_id=$2
                  AND to_state IN ('COOLING','REACTIVATION')
                ORDER BY version
                """,
                tenant_id,
                lead_id,
            )

        health_by_channel: dict[Channel, ChannelHealth] = {}
        for row in health_rows:
            channel = row["channel"]
            health_by_channel[channel] = ChannelHealth(
                state=row["state"],
                occurred_at=_utc(row["occurred_at"]),
                address_ref=row["address_ref"],
            )

        suppressions = tuple(
            Suppression(
                scope=row["scope"],
                reason=row["reason"],
                occurred_at=_utc(row["occurred_at"]),
                suppression_id=str(row["suppression_id"]),
                channel=row["channel"],
                campaign_id=row["campaign_id"],
            )
            for row in suppression_rows
        )
        exposures = tuple(
            Exposure(
                campaign_id=row["campaign_id"],
                campaign_version=int(row["campaign_version"]),
                channel=row["channel"],
                touch_index=int(row["touch_index"]),
                status=row["status"],
                reserved_at=_utc(row["reserved_at"]),
                engagement_outcome=row["engagement_outcome"],
                negative_outcome=row["negative_outcome"],
            )
            for row in exposure_rows
        )

        cooling_until: datetime | None = None
        reactivation_cycles = 0
        for row in lifecycle_rows:
            if row["to_state"] == "COOLING":
                seconds = int(
                    policy.values.get("cooling", {}).get("min_cooling_seconds") or 0
                )
                cooling_until = _utc(row["occurred_at"]) + timedelta(seconds=seconds)
            elif row["to_state"] == "REACTIVATION":
                reactivation_cycles += 1

        return LeadSnapshot(
            tenant_id=tenant_id,
            lead_id=lead_id,
            lifecycle_state=current["state"],
            lifecycle_version=int(current["version"]),
            channel_health=health_by_channel,
            suppressions=suppressions,
            exposures=exposures,
            cooling_until=cooling_until,
            reactivation_cycles=reactivation_cycles,
        )

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
        # MCR-C has no certified execution authority. A plan, caller-supplied
        # decision UUID, or generic command capability cannot authorize a send.
        # Keep this boundary closed even if an unrelated command policy enables
        # an adapter. Future activation requires a reviewed execution-evidence
        # contract and atomic fresh policy revalidation, not a config toggle.
        raise CampaignRecyclingConflict(
            "PRODUCTION_NOT_AUTHORIZED: MCR execution evidence boundary is not certified"
        )


async def _transition_lifecycle_on_connection(
    conn: asyncpg.Connection,
    *,
    tenant_id: str,
    lead_id: str,
    expected_from: str | None,
    to_state: str,
    reason_code: str,
    source: str,
    correlation_id: str,
    evidence_hash: str,
    evidence_ref: str | None,
    occurred_at: datetime,
) -> int:
    if to_state not in LEGAL_TRANSITIONS.get(expected_from, frozenset()):
        raise CampaignRecyclingConflict(
            f"illegal lifecycle transition {expected_from!r}->{to_state!r}"
        )
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
    if actual_from != expected_from:
        raise CampaignRecyclingConflict(
            f"lifecycle version conflict: expected {expected_from!r}, current {actual_from!r}"
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
            raise CampaignRecyclingConflict("lifecycle optimistic update lost")
    await conn.execute(
        """
        INSERT INTO mcr_lead_lifecycle_events
          (transition_id,tenant_id,lead_id,version,from_state,to_state,reason_code,source,
           occurred_at,recorded_at,correlation_id,evidence_hash,evidence_ref)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10,$11,$12)
        """,
        uuid4(),
        tenant_id,
        lead_id,
        version,
        expected_from,
        to_state,
        reason_code,
        source,
        occurred_at,
        correlation_id,
        evidence_hash,
        evidence_ref,
    )
    return version


def _leaf_values(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        return [leaf for child in value.values() for leaf in _leaf_values(child)]
    return [value]


def _cap_release_at(
    window_exposures: Sequence[Exposure], cap: int, window_seconds: int
) -> datetime:
    # The window count drops below the cap only once the oldest
    # (count - cap + 1) exposures have aged out.
    reserved = sorted(_utc(exposure.reserved_at) for exposure in window_exposures)
    return reserved[len(reserved) - cap] + timedelta(seconds=window_seconds)


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


def _coerce_event_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _utc(value)
    if not isinstance(value, str) or not value.strip():
        raise CampaignRecyclingConflict("delivery event timestamp must be ISO-8601")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise CampaignRecyclingConflict(
            "delivery event timestamp must be ISO-8601"
        ) from exc
    return _utc(parsed)


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return _utc(value).isoformat()
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


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
