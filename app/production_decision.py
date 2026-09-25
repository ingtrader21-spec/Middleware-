"""Production GO/NO_GO decision engine with selective capability authorization.

The engine is a pure, deterministic function of a release, the capabilities
requested for it, the seven kinds of release evidence, the authenticated
requester and the evaluation clock. It never reads or changes runtime
capability flags and never contacts a provider: a ``GO`` is an authorization
record for a release controller, not an activation.

Fail-closed rules
-----------------
* The default decision is ``NO_GO``; ``GO`` is only reachable when every
  required evidence kind is present, well formed, ``PASS``, bound to the exact
  release, fresh, and satisfies its kind-specific invariants.
* Capabilities are authorized one by one. A capability is ``GO`` only when it
  is a known implementation capability, is not an umbrella kill switch, was
  exercised by the canary, and was explicitly approved by an approver who is
  not the requester. Everything else is denied with explicit reasons.
* Evidence that cannot be parsed is ``REJECTED``; absent evidence is
  ``MISSING``; both deny ``GO``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.capability_resolution import UMBRELLA_BY_IMPLEMENTATION, UMBRELLA_CONTROLS
from app.core.config import EXTERNAL_EFFECT_FIELDS

SCHEMA_VERSION = "1.0"
POLICY_VERSION = "production-go-no-go.v1"

EVIDENCE_KINDS: tuple[str, ...] = (
    "staging",
    "release_seal",
    "canary",
    "monitoring",
    "rollback",
    "reconciliation",
    "approval",
)

# Maximum age of the observation behind each evidence kind at evaluation time.
MAX_EVIDENCE_AGE: dict[str, timedelta] = {
    "staging": timedelta(days=7),
    "release_seal": timedelta(days=30),
    "canary": timedelta(hours=72),
    "monitoring": timedelta(hours=24),
    "rollback": timedelta(days=7),
    "reconciliation": timedelta(hours=24),
    "approval": timedelta(hours=72),
}
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_APPROVAL_VALIDITY = timedelta(days=7)
MIN_CANARY_DURATION_SECONDS = 1800
MAX_CANARY_ERROR_RATE = 0.01

# Grantable production capabilities are exactly the runtime implementation
# effect controls. Umbrella controls are kill switches and never grantable.
CAPABILITY_CATALOG: frozenset[str] = frozenset(EXTERNAL_EFFECT_FIELDS)

_SHA40 = r"^[0-9a-f]{40}$"
_SHA256 = r"^[0-9a-f]{64}$"
_IMAGE_DIGEST = r"^sha256:[0-9a-f]{64}$"
_CAPABILITY = r"^[A-Z][A-Z0-9_]{0,99}$"

Decision = Literal["GO", "NO_GO"]


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")
    return value.astimezone(UTC)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReleaseIdentity(_Strict):
    source_sha: str = Field(pattern=_SHA40)
    image_digest: str = Field(pattern=_IMAGE_DIGEST)
    schema_head: str = Field(min_length=1, max_length=200)


class _Evidence(_Strict):
    evidence_id: str = Field(min_length=1, max_length=200)
    status: Literal["PASS", "FAIL"]
    source_sha: str = Field(pattern=_SHA40)
    image_digest: str = Field(pattern=_IMAGE_DIGEST)
    observed_at: datetime
    artifact_sha256: str = Field(pattern=_SHA256)
    artifact_uri: str | None = Field(default=None, max_length=500)

    @field_validator("observed_at")
    @classmethod
    def _observed_is_aware(cls, value: datetime) -> datetime:
        return _aware(value)


class StagingEvidence(_Evidence):
    environment: Literal["staging"]
    schema_head: str = Field(min_length=1, max_length=200)
    smoke_passed: bool


class ReleaseSealEvidence(_Evidence):
    seal_sha256: str = Field(pattern=_SHA256)
    signer: str = Field(min_length=1, max_length=200)
    signature_verified: bool


class CanaryEvidence(_Evidence):
    capabilities: list[str] = Field(max_length=64)
    duration_seconds: int = Field(ge=0)
    error_rate: float = Field(ge=0.0, le=1.0)


class MonitoringEvidence(_Evidence):
    open_critical_alerts: int = Field(ge=0)
    alert_routes_verified: bool
    slo_burn_rate_ok: bool


class RollbackEvidence(_Evidence):
    rehearsed: bool
    rollback_verified: bool
    rollback_image_digest: str = Field(pattern=_IMAGE_DIGEST)


class ReconciliationEvidence(_Evidence):
    unreconciled_count: int = Field(ge=0)
    drift_count: int = Field(ge=0)


class ApprovalEvidence(_Evidence):
    approved_by: str = Field(min_length=1, max_length=200)
    expires_at: datetime
    capabilities: list[str] = Field(max_length=64)

    @field_validator("expires_at")
    @classmethod
    def _expires_is_aware(cls, value: datetime) -> datetime:
        return _aware(value)


EVIDENCE_MODELS: dict[str, type[_Evidence]] = {
    "staging": StagingEvidence,
    "release_seal": ReleaseSealEvidence,
    "canary": CanaryEvidence,
    "monitoring": MonitoringEvidence,
    "rollback": RollbackEvidence,
    "reconciliation": ReconciliationEvidence,
    "approval": ApprovalEvidence,
}


class DecisionRequest(_Strict):
    """A release, the capabilities requested for it, and raw evidence.

    Evidence values stay untyped here so that one malformed document is
    reported as ``REJECTED`` for its kind instead of failing the whole call.
    """

    release: ReleaseIdentity
    requested_capabilities: list[str] = Field(min_length=1, max_length=32)
    evidence: dict[str, dict[str, Any] | None] = Field(default_factory=dict)

    @field_validator("requested_capabilities")
    @classmethod
    def _capabilities_are_names(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.fullmatch(_CAPABILITY, item):
                raise ValueError(f"invalid capability name: {item!r}")
        if len(set(value)) != len(value):
            raise ValueError("requested_capabilities must be unique")
        return value

    @field_validator("evidence")
    @classmethod
    def _known_kinds(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(value) - set(EVIDENCE_KINDS))
        if unknown:
            raise ValueError(f"unknown evidence kinds: {', '.join(unknown)}")
        return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def evidence_digest(raw: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(dict(raw))).hexdigest()


def _assess(
    kind: str,
    raw: Mapping[str, Any] | None,
    release: ReleaseIdentity,
    now: datetime,
) -> tuple[dict[str, Any], _Evidence | None]:
    if raw is None:
        return {"kind": kind, "status": "MISSING", "reasons": [f"{kind}_evidence_missing"], "digest": None}, None
    digest = evidence_digest(raw)
    try:
        evidence = EVIDENCE_MODELS[kind].model_validate(dict(raw))
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in err["loc"]) or "document" for err in exc.errors()})
        return {
            "kind": kind,
            "status": "REJECTED",
            "reasons": [f"{kind}_evidence_invalid"],
            "invalid_fields": fields,
            "digest": digest,
        }, None

    reasons: list[str] = []
    if evidence.status != "PASS":
        reasons.append(f"{kind}_status_not_pass")
    if evidence.source_sha != release.source_sha:
        reasons.append(f"{kind}_source_sha_mismatch")
    if evidence.image_digest != release.image_digest:
        reasons.append(f"{kind}_image_digest_mismatch")
    if evidence.observed_at > now + MAX_CLOCK_SKEW:
        reasons.append(f"{kind}_observed_in_future")
    elif now - evidence.observed_at > MAX_EVIDENCE_AGE[kind]:
        reasons.append(f"{kind}_evidence_stale")

    if isinstance(evidence, StagingEvidence):
        if evidence.schema_head != release.schema_head:
            reasons.append("staging_schema_head_mismatch")
        if not evidence.smoke_passed:
            reasons.append("staging_smoke_failed")
    elif isinstance(evidence, ReleaseSealEvidence):
        if not evidence.signature_verified:
            reasons.append("release_seal_signature_unverified")
    elif isinstance(evidence, CanaryEvidence):
        if evidence.duration_seconds < MIN_CANARY_DURATION_SECONDS:
            reasons.append("canary_duration_insufficient")
        if evidence.error_rate > MAX_CANARY_ERROR_RATE:
            reasons.append("canary_error_rate_exceeded")
    elif isinstance(evidence, MonitoringEvidence):
        if evidence.open_critical_alerts:
            reasons.append("monitoring_critical_alerts_open")
        if not evidence.alert_routes_verified:
            reasons.append("monitoring_alert_routes_unverified")
        if not evidence.slo_burn_rate_ok:
            reasons.append("monitoring_slo_burn_rate_exceeded")
    elif isinstance(evidence, RollbackEvidence):
        if not evidence.rehearsed:
            reasons.append("rollback_not_rehearsed")
        if not evidence.rollback_verified:
            reasons.append("rollback_not_verified")
        if evidence.rollback_image_digest == release.image_digest:
            reasons.append("rollback_target_is_candidate")
    elif isinstance(evidence, ReconciliationEvidence):
        if evidence.unreconciled_count:
            reasons.append("reconciliation_unreconciled_records")
        if evidence.drift_count:
            reasons.append("reconciliation_drift_detected")
    elif isinstance(evidence, ApprovalEvidence):
        if evidence.expires_at <= now:
            reasons.append("approval_expired")
        if evidence.expires_at - evidence.observed_at > MAX_APPROVAL_VALIDITY:
            reasons.append("approval_validity_too_long")

    return {
        "kind": kind,
        "status": "REJECTED" if reasons else "ACCEPTED",
        "reasons": reasons,
        "evidence_id": evidence.evidence_id,
        "artifact_sha256": evidence.artifact_sha256,
        "observed_at": evidence.observed_at.isoformat(),
        "digest": digest,
    }, (None if reasons else evidence)


def _capability_decision(
    capability: str,
    *,
    evidence_ok: bool,
    canary: CanaryEvidence | None,
    approval: ApprovalEvidence | None,
    requested_by: str,
) -> dict[str, Any]:
    reasons: list[str] = []
    if capability in UMBRELLA_CONTROLS:
        reasons.append("umbrella_control_not_grantable")
    elif capability not in CAPABILITY_CATALOG:
        reasons.append("capability_unknown")
    if not evidence_ok:
        reasons.append("release_evidence_incomplete")
    if canary is None or capability not in canary.capabilities:
        reasons.append("capability_not_canaried")
    if approval is None or capability not in approval.capabilities:
        reasons.append("capability_not_approved")
    elif approval.approved_by == requested_by:
        reasons.append("approval_not_independent")
    return {
        "capability": capability,
        "decision": "NO_GO" if reasons else "GO",
        "reasons": reasons,
        "required_umbrella_control": UMBRELLA_BY_IMPLEMENTATION.get(capability),
    }


def _activation_block() -> dict[str, Any]:
    return {
        "performed": False,
        "capabilities_activated": [],
        "provider_effects_enabled": False,
        "note": "decision only; activation is owned by the release controller",
    }


def evaluate(
    request: DecisionRequest,
    *,
    requested_by: str,
    now: datetime,
    source: Literal["request", "evidence_store"],
) -> dict[str, Any]:
    """Evaluate a release decision. Never raises for evidence content."""

    now = _aware(now)
    assessments: dict[str, dict[str, Any]] = {}
    accepted: dict[str, _Evidence] = {}
    for kind in EVIDENCE_KINDS:
        assessment, evidence = _assess(kind, request.evidence.get(kind), request.release, now)
        assessments[kind] = assessment
        if evidence is not None:
            accepted[kind] = evidence

    evidence_ok = len(accepted) == len(EVIDENCE_KINDS)
    canary = accepted.get("canary")
    approval = accepted.get("approval")
    capabilities = [
        _capability_decision(
            name,
            evidence_ok=evidence_ok,
            canary=canary if isinstance(canary, CanaryEvidence) else None,
            approval=approval if isinstance(approval, ApprovalEvidence) else None,
            requested_by=requested_by,
        )
        for name in sorted(request.requested_capabilities)
    ]
    authorized = [item["capability"] for item in capabilities if item["decision"] == "GO"]
    denied = [item["capability"] for item in capabilities if item["decision"] != "GO"]

    reasons = sorted({reason for item in assessments.values() for reason in item["reasons"]})
    if not authorized:
        reasons.append("no_capability_authorized")
    decision: Decision = "GO" if evidence_ok and authorized else "NO_GO"

    release = request.release.model_dump()
    identity = {
        "policy_version": POLICY_VERSION,
        "release": release,
        "requested_by": requested_by,
        "requested_capabilities": sorted(request.requested_capabilities),
        "evidence": {kind: assessments[kind]["digest"] for kind in EVIDENCE_KINDS},
        "evaluated_at": now.isoformat(),
        "decision": decision,
        "authorized_capabilities": authorized,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "decision_id": hashlib.sha256(_canonical(identity)).hexdigest(),
        "decision": decision,
        "authoritative": source == "evidence_store",
        "source": source,
        "evaluated_at": now.isoformat(),
        "requested_by": requested_by,
        "release": release,
        "reasons": reasons,
        "evidence": [assessments[kind] for kind in EVIDENCE_KINDS],
        "capabilities": capabilities,
        "authorized_capabilities": authorized if decision == "GO" else [],
        "denied_capabilities": denied if decision == "GO" else sorted(request.requested_capabilities),
        "partial": decision == "GO" and bool(denied),
        "activation": _activation_block(),
    }


def default_no_go(*, now: datetime, reason: str, requested_by: str | None = None) -> dict[str, Any]:
    """The decision when no well-formed decision request is available."""

    now = _aware(now)
    identity = {"policy_version": POLICY_VERSION, "evaluated_at": now.isoformat(), "reason": reason}
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "decision_id": hashlib.sha256(_canonical(identity)).hexdigest(),
        "decision": "NO_GO",
        "authoritative": False,
        "source": "evidence_store",
        "evaluated_at": now.isoformat(),
        "requested_by": requested_by,
        "release": None,
        "reasons": [reason],
        "evidence": [
            {"kind": kind, "status": "MISSING", "reasons": [f"{kind}_evidence_missing"], "digest": None}
            for kind in EVIDENCE_KINDS
        ],
        "capabilities": [],
        "authorized_capabilities": [],
        "denied_capabilities": [],
        "partial": False,
        "activation": _activation_block(),
    }


def policy_document() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "default_decision": "NO_GO",
        "required_evidence": list(EVIDENCE_KINDS),
        "max_evidence_age_seconds": {
            kind: int(age.total_seconds()) for kind, age in MAX_EVIDENCE_AGE.items()
        },
        "max_clock_skew_seconds": int(MAX_CLOCK_SKEW.total_seconds()),
        "max_approval_validity_seconds": int(MAX_APPROVAL_VALIDITY.total_seconds()),
        "min_canary_duration_seconds": MIN_CANARY_DURATION_SECONDS,
        "max_canary_error_rate": MAX_CANARY_ERROR_RATE,
        "grantable_capabilities": sorted(CAPABILITY_CATALOG),
        "non_grantable_umbrella_controls": sorted(UMBRELLA_CONTROLS),
        "activation_performed_by_this_service": False,
    }


class EvidenceAssessment(BaseModel):
    kind: str
    status: Literal["ACCEPTED", "MISSING", "REJECTED"]
    reasons: list[str]
    digest: str | None
    evidence_id: str | None = None
    artifact_sha256: str | None = None
    observed_at: str | None = None
    invalid_fields: list[str] | None = None


class CapabilityDecision(BaseModel):
    capability: str
    decision: Decision
    reasons: list[str]
    required_umbrella_control: str | None


class ActivationState(BaseModel):
    performed: Literal[False]
    capabilities_activated: list[str] = Field(max_length=0)
    provider_effects_enabled: Literal[False]
    note: str


class DecisionReadback(BaseModel):
    """Response of every decision endpoint; ``activation`` is always inert."""

    schema_version: Literal["1.0"]
    policy_version: Literal["production-go-no-go.v1"]
    decision_id: str
    decision: Decision
    authoritative: bool
    source: Literal["request", "evidence_store"]
    evaluated_at: str
    requested_by: str | None
    release: ReleaseIdentity | None
    reasons: list[str]
    evidence: list[EvidenceAssessment]
    capabilities: list[CapabilityDecision]
    authorized_capabilities: list[str]
    denied_capabilities: list[str]
    partial: bool
    activation: ActivationState


class DecisionPolicy(BaseModel):
    schema_version: Literal["1.0"]
    policy_version: Literal["production-go-no-go.v1"]
    default_decision: Literal["NO_GO"]
    required_evidence: list[str]
    max_evidence_age_seconds: dict[str, int]
    max_clock_skew_seconds: int
    max_approval_validity_seconds: int
    min_canary_duration_seconds: int
    max_canary_error_rate: float
    grantable_capabilities: list[str]
    non_grantable_umbrella_controls: list[str]
    activation_performed_by_this_service: Literal[False]
