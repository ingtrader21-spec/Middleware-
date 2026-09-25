from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

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
        decision_inputs = _decision_input_payload(
            self.policy,
            snapshot,
            ordered,
            mode=mode,
            kill_switch_open=kill_switch_open,
            evidence_stale_or_conflicting=evidence_stale_or_conflicting,
        )
        if not ordered:
            return self._decision(
                snapshot,
                (),
                None,
                ("NO_CANDIDATE",),
                None,
                mode,
                now,
                decision_inputs,
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
                decision_inputs,
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
            decision_inputs,
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
        elif (
            health.state == "possible"
            and self.policy.configured
            and not self._value("channel_health", "possible_is_contactable")
        ):
            reasons.append("CHANNEL_HEALTH_POLICY_GATED")
        elif health.state == "soft_bounce" and self.policy.configured:
            retry_at = _utc(health.occurred_at) + timedelta(
                seconds=int(
                    self._value("channel_health", "soft_bounce_retry_after_seconds")
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

        same_campaign = [
            exposure
            for exposure in snapshot.exposures
            if exposure.campaign_id == candidate.campaign_id
        ]
        if self.policy.configured:
            max_cycles = self._value("reactivation", "max_cycles")
            if (
                snapshot.lifecycle_state == "REACTIVATION"
                and snapshot.reactivation_cycles >= int(max_cycles)
            ):
                reasons.append("REACTIVATION_LIMIT_REACHED")
            if (
                snapshot.lifecycle_state == "REACTIVATION"
                and self._value(
                    "reactivation", "requires_distinct_campaign_version"
                )
                and any(
                    exposure.campaign_id == candidate.campaign_id
                    and exposure.campaign_version == candidate.campaign_version
                    for exposure in snapshot.exposures
                )
            ):
                reasons.append("CAMPAIGN_VERSION_EXHAUSTED")

            exposure_cfg = self.policy.values["exposure"]
            max_lifetime = int(exposure_cfg["max_lifetime_all_campaigns"])
            if len(snapshot.exposures) >= max_lifetime:
                reasons.append("LIFETIME_EXPOSURE_CAP_REACHED")
            max_campaign_lifetime = int(exposure_cfg["max_lifetime_per_campaign"])
            if len(same_campaign) >= max_campaign_lifetime:
                reasons.append("LIFETIME_EXPOSURE_CAP_REACHED")

            recent_window = int(exposure_cfg["recent_window_seconds"])
            recent_cutoff = now - timedelta(seconds=recent_window)
            recent = [
                exposure
                for exposure in snapshot.exposures
                if _utc(exposure.reserved_at) > recent_cutoff
            ]
            max_recent = int(exposure_cfg["max_recent_all_campaigns"])
            if len(recent) >= max_recent:
                reasons.append("RECENT_WINDOW_CAP_REACHED")
                temporal_until.append(
                    _cap_release_at(recent, max_recent, recent_window)
                )

            channel_cfg = self.policy.values["channel_caps"][candidate.channel]
            channel_window = int(channel_cfg["window_seconds"])
            channel_cutoff = now - timedelta(seconds=channel_window)
            channel_recent = [
                exposure
                for exposure in snapshot.exposures
                if exposure.channel == candidate.channel
                and _utc(exposure.reserved_at) > channel_cutoff
            ]
            max_channel = int(channel_cfg["max_touches"])
            if len(channel_recent) >= max_channel:
                reasons.append("CHANNEL_CAP_REACHED")
                temporal_until.append(
                    _cap_release_at(channel_recent, max_channel, channel_window)
                )

            campaign_cfg = self.policy.values["campaign"]
            cooldown = int(campaign_cfg["cooldown_seconds"])
            if same_campaign:
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
            max_per_version = int(campaign_cfg["max_touches_per_version"])
            if version_count >= max_per_version:
                reasons.append("CAMPAIGN_VERSION_EXHAUSTED")

        ordered = _sort_reasons(reasons)
        next_at = max(temporal_until) if temporal_until else None
        if ordered and not set(ordered) <= TEMPORAL_REASONS:
            next_at = None
        return ordered, next_at

    def _value(self, section: str, key: str) -> Any:
        value = self.policy.values.get(section, {}).get(key)
        if value is None:
            raise CampaignRecyclingPolicyError(
                f"policy value {section}.{key} is not configured"
            )
        return value

    def _decision(
        self,
        snapshot: LeadSnapshot,
        candidates: Sequence[CandidateDecision],
        selected: CandidateDecision | None,
        reasons: tuple[str, ...],
        next_eligible_at: datetime | None,
        mode: str,
        evaluated_at: datetime,
        decision_inputs: Mapping[str, Any],
    ) -> NextActionDecision:
        output = {
            "tenant_id": snapshot.tenant_id,
            "lead_id": snapshot.lead_id,
            "lifecycle_state": snapshot.lifecycle_state,
            "lifecycle_version": snapshot.lifecycle_version,
            "mode": mode,
            "policy_version": self.policy.policy_version,
            "eligible": selected is not None,
            "selected": _candidate_payload(selected),
            "next_eligible_at": _utc(next_eligible_at).isoformat()
            if next_eligible_at is not None
            else None,
            "reason_codes": list(reasons),
            "candidates": [_candidate_payload(item) for item in candidates],
        }
        digest = canonical_digest({"inputs": decision_inputs, "outputs": output})
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


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def delivery_event_payload_hash(event: Mapping[str, Any]) -> str:
    """delivery-event.v1 payload_hash: canonical JSON without received_at.

    payload_hash itself is necessarily excluded from its own digest.
    """
    return canonical_digest(
        {k: v for k, v in event.items() if k not in {"received_at", "payload_hash"}}
    )


def _decision_input_payload(
    policy: PolicyProfile,
    snapshot: LeadSnapshot,
    candidates: Sequence[Candidate],
    *,
    mode: str,
    kill_switch_open: bool,
    evidence_stale_or_conflicting: bool,
) -> dict[str, Any]:
    """Canonical material inputs for stale-plan detection.

    evaluated_at is intentionally excluded by contract. Collections whose
    ordering is not semantically meaningful are normalized before hashing.
    """

    suppressions = sorted(
        (
            {
                "scope": item.scope,
                "reason": item.reason,
                "occurred_at": _utc(item.occurred_at).isoformat(),
                "suppression_id": item.suppression_id,
                "channel": item.channel,
                "campaign_id": item.campaign_id,
            }
            for item in snapshot.suppressions
        ),
        key=lambda item: (
            item["scope"],
            item["reason"],
            item["occurred_at"],
            item["suppression_id"],
            item["channel"] or "",
            item["campaign_id"] or "",
        ),
    )
    exposures = sorted(
        (
            {
                "campaign_id": item.campaign_id,
                "campaign_version": item.campaign_version,
                "channel": item.channel,
                "touch_index": item.touch_index,
                "status": item.status,
                "reserved_at": _utc(item.reserved_at).isoformat(),
                "engagement_outcome": item.engagement_outcome,
                "negative_outcome": item.negative_outcome,
            }
            for item in snapshot.exposures
        ),
        key=lambda item: (
            item["campaign_id"],
            item["campaign_version"],
            item["channel"],
            item["touch_index"],
            item["reserved_at"],
            item["status"],
        ),
    )
    return {
        "policy": {
            "policy_version": policy.policy_version,
            "configured": policy.configured,
            "production_authorized": policy.production_authorized,
            "values": policy.values,
            "channel_execution": policy.channel_execution,
        },
        "snapshot": {
            "tenant_id": snapshot.tenant_id,
            "lead_id": snapshot.lead_id,
            "lifecycle_state": snapshot.lifecycle_state,
            "lifecycle_version": snapshot.lifecycle_version,
            "channel_health": {
                channel: {
                    "state": health.state,
                    "occurred_at": _utc(health.occurred_at).isoformat(),
                    "address_ref": health.address_ref,
                }
                for channel, health in sorted(snapshot.channel_health.items())
            },
            "suppressions": suppressions,
            "exposures": exposures,
            "cooling_until": _utc(snapshot.cooling_until).isoformat()
            if snapshot.cooling_until is not None
            else None,
            "reactivation_cycles": snapshot.reactivation_cycles,
        },
        "candidates": [
            {
                "campaign_id": item.campaign_id,
                "campaign_version": item.campaign_version,
                "channel": item.channel,
                "priority": item.priority,
                "touch_index": item.touch_index,
                "sender_identity_id": item.sender_identity_id,
                "active": item.active,
                "version_approved": item.version_approved,
                "consent_granted": item.consent_granted,
                "sender_authorized": item.sender_authorized,
                "dialing_eligible": item.dialing_eligible,
            }
            for item in candidates
        ],
        "mode": mode,
        "kill_switch_open": kill_switch_open,
        "evidence_stale_or_conflicting": evidence_stale_or_conflicting,
    }


def exposure_idempotency_key(
    snapshot: LeadSnapshot, selected: CandidateDecision
) -> str:
    natural_key = {
        "tenant_id": snapshot.tenant_id,
        "lead_id": snapshot.lead_id,
        "campaign_id": selected.campaign_id,
        "campaign_version": selected.campaign_version,
        "channel": selected.channel,
        "touch_index": selected.touch_index,
    }
    return "mcr1:" + canonical_digest(natural_key)


def next_action_document(
    decision: NextActionDecision,
    snapshot: LeadSnapshot,
    *,
    mode: Literal["plan", "read", "execute"],
    evaluated_at: datetime,
    correlation_id: str,
    candidates_redacted: bool = False,
) -> dict[str, Any]:
    """Serialize a pure decision into the frozen next-action.v1 shape."""

    selected = decision.selected
    selected_payload = None
    if selected is not None:
        selected_payload = {
            "campaign_id": selected.campaign_id,
            "campaign_version": selected.campaign_version,
            "channel": selected.channel,
            "sender_identity_id": selected.sender_identity_id,
            "touch_index": selected.touch_index,
            "exposure_idempotency_key": exposure_idempotency_key(snapshot, selected),
        }
    candidates = []
    if not candidates_redacted:
        candidates = [
            {
                "campaign_id": item.campaign_id,
                "campaign_version": item.campaign_version,
                "channel": item.channel,
                "disposition": item.disposition,
                "reason_codes": list(item.reason_codes),
            }
            for item in decision.candidates
        ]
    return {
        "schema_version": "1.0",
        "decision_id": str(uuid5(NAMESPACE_URL, f"mcr:decision:{decision.decision_hash}")),
        "tenant_id": snapshot.tenant_id,
        "lead_id": snapshot.lead_id,
        "mode": mode,
        "dry_run": mode in {"plan", "read"},
        "provider_effects": "none",
        "evaluated_at": _utc(evaluated_at).isoformat(),
        "policy_version": decision.policy_version,
        "lifecycle_state": snapshot.lifecycle_state,
        "eligible": decision.eligible,
        "selected": selected_payload,
        "next_eligible_at": _utc(decision.next_eligible_at).isoformat()
        if decision.next_eligible_at is not None
        else None,
        "reason_codes": list(decision.reason_codes),
        "candidates": candidates,
        "candidates_redacted": candidates_redacted,
        "decision_hash": decision.decision_hash,
        "correlation_id": correlation_id,
    }


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
