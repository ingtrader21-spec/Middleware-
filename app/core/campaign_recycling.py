from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]

LifecycleState = Literal[
    "NEW",
    "VALIDATED",
    "ELIGIBLE",
    "ACTIVE_CYCLE",
    "ENGAGED",
    "COOLING",
    "REACTIVATION",
    "CONVERTED",
    "SUPPRESSED",
]
Channel = Literal["email", "sms", "whatsapp", "voice"]

CONTACTABLE_LIFECYCLE = frozenset(
    {"ELIGIBLE", "ACTIVE_CYCLE", "ENGAGED", "REACTIVATION"}
)
TERMINAL_LIFECYCLE = frozenset({"CONVERTED", "SUPPRESSED"})
CHANNEL_ORDER = {"email": 0, "sms": 1, "whatsapp": 2, "voice": 3}

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
    max_candidates_disclosed: int

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
        max_candidates_disclosed = raw["decision"]["max_candidates_disclosed"]
        if (
            not isinstance(max_candidates_disclosed, int)
            or isinstance(max_candidates_disclosed, bool)
            or max_candidates_disclosed < 1
        ):
            raise CampaignRecyclingPolicyError(
                "decision.max_candidates_disclosed must be a positive integer"
            )
        return cls(
            policy_version=raw["policy_version"],
            values=values,
            configured=configured,
            production_authorized=raw["production"]["authorized"] is True,
            channel_execution=raw["channel_execution"],
            max_candidates_disclosed=max_candidates_disclosed,
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
        if len(candidates) > self.policy.max_candidates_disclosed:
            raise CampaignRecyclingPolicyError(
                "candidate set exceeds decision.max_candidates_disclosed"
            )
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
            "hard_bounce",
            "complained",
            "unsubscribed",
            "suppressed",
            "invalid",
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
        max_campaign_lifetime = int(exposure_cfg.get("max_lifetime_per_campaign") or 0)
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
