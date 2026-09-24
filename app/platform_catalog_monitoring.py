"""Monitoring state of a catalog service: expected release identity versus runtime evidence.

Pure functions and request models for the ``platform_services`` monitoring
extension (Alembic ``0067``). The catalog is desired state from approved Git
descriptors; observed state comes only from authorized collectors; the state
machine below never reports ``synced`` or ``certified`` from a Git descriptor
or an HTTP 200 alone.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

MonitoringState = Literal[
    "unregistered",
    "registered",
    "pending",
    "applying",
    "synced",
    "drifted",
    "failed",
    "unknown",
    "certified",
]
MONITORING_STATES: tuple[str, ...] = MonitoringState.__args__  # type: ignore[attr-defined]
STALE_AFTER = timedelta(minutes=15)
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CONFIG_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MIGRATION_HEAD = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")
EXPECTED_FIELDS = ("git_sha", "image_digest", "config_digest", "migration_head")
PROFILES = ("prometheus", "otel", "alloy", "not-applicable")


def safe_path(value: str) -> str:
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "?" in value
        or "#" in value
    ):
        raise ValueError("contract paths must be absolute and query-free")
    return value


class MonitoringDescriptor(BaseModel):
    """Desired monitoring descriptor fields a registration or patch may carry."""

    model_config = ConfigDict(extra="forbid")

    deployment_id: str | None = Field(default=None, pattern=IDENTIFIER.pattern)
    host_id: str | None = Field(default=None, pattern=IDENTIFIER.pattern)
    instance_id: str | None = Field(default=None, pattern=IDENTIFIER.pattern)
    public_origin: str | None = Field(default=None, pattern=ORIGIN.pattern)
    private_origin: str | None = Field(default=None, pattern=ORIGIN.pattern)
    liveness_path: str | None = None
    readiness_path: str | None = None
    metrics_profile: Literal["prometheus", "otel", "not-applicable"] | None = None
    logs_profile: Literal["alloy", "otel", "not-applicable"] | None = None
    traces_profile: Literal["otel", "not-applicable"] | None = None
    prometheus_target_id: str | None = Field(default=None, pattern=IDENTIFIER.pattern)
    blackbox_target_id: str | None = Field(default=None, pattern=IDENTIFIER.pattern)
    grafana_dashboard_ids: list[str] | None = Field(default=None, max_length=20)
    expected_git_sha: str | None = Field(default=None, pattern=GIT_SHA.pattern)
    expected_image_digest: str | None = Field(
        default=None, pattern=IMAGE_DIGEST.pattern
    )
    expected_config_digest: str | None = Field(
        default=None, pattern=CONFIG_DIGEST.pattern
    )
    expected_migration_head: str | None = Field(
        default=None, pattern=MIGRATION_HEAD.pattern
    )
    secret_references: list[dict[str, Any]] | None = Field(default=None, max_length=64)

    @field_validator("liveness_path", "readiness_path")
    @classmethod
    def paths_are_safe(cls, value: str | None) -> str | None:
        return None if value is None else safe_path(value)

    @field_validator("grafana_dashboard_ids")
    @classmethod
    def dashboards_are_identifiers(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if len(value) != len(set(value)) or not all(
            IDENTIFIER.fullmatch(item) for item in value
        ):
            raise ValueError("grafana_dashboard_ids must be unique identifiers")
        return value

    @field_validator("public_origin", "private_origin")
    @classmethod
    def origins_are_declared_not_derived(cls, value: str | None) -> str | None:
        if value is not None and value.rstrip("/") != value:
            raise ValueError("origins carry no trailing slash")
        return value


class ObservedState(BaseModel):
    """What an authorized collector read from the running service."""

    model_config = ConfigDict(extra="forbid")

    observed_git_sha: str | None = Field(default=None, pattern=GIT_SHA.pattern)
    observed_image_digest: str | None = Field(
        default=None, pattern=IMAGE_DIGEST.pattern
    )
    observed_config_digest: str | None = Field(
        default=None, pattern=CONFIG_DIGEST.pattern
    )
    observed_migration_head: str | None = Field(
        default=None, pattern=MIGRATION_HEAD.pattern
    )
    observed_at: AwareDatetime
    source: str = Field(pattern=IDENTIFIER.pattern)
    status: Literal["observed", "applying", "failed"] = "observed"
    detail: str | None = Field(default=None, max_length=512)

    @field_validator("observed_at")
    @classmethod
    def not_in_the_future(cls, value: datetime) -> datetime:
        if value > datetime.now(timezone.utc) + timedelta(seconds=60):
            raise ValueError("observed_at must not be in the future")
        return value


class CertificationEvidence(BaseModel):
    """Runtime proof required before a service may be marked certified."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=20, max_length=1000)
    health_endpoints: bool
    metrics_scraped: bool
    logs_received: bool
    traces_received: bool
    alert_route_test: bool
    dashboards_bound: bool
    secret_references_reconciled: bool

    def gaps(self, not_applicable: set[str]) -> list[str]:
        """Evidence fields that are false and not declared not-applicable by profile."""
        return [
            name
            for name, value in self.model_dump(exclude={"reason"}).items()
            if value is False and name not in not_applicable
        ]


def not_applicable_evidence(row: dict[str, Any]) -> set[str]:
    skip: set[str] = set()
    if row.get("metrics_profile") == "not-applicable":
        skip.add("metrics_scraped")
    if row.get("logs_profile") == "not-applicable":
        skip.add("logs_received")
    if row.get("traces_profile") == "not-applicable":
        skip.add("traces_received")
    if not row.get("secret_references"):
        skip.add("secret_references_reconciled")
    return skip


def declared_expectations(row: dict[str, Any]) -> dict[str, str]:
    return {
        name: row[f"expected_{name}"]
        for name in EXPECTED_FIELDS
        if row.get(f"expected_{name}")
    }


def compare(row: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Return (matching, drifted, unobserved) expected fields."""
    matching: list[str] = []
    drifted: list[str] = []
    unobserved: list[str] = []
    for name, expected in declared_expectations(row).items():
        observed = row.get(f"observed_{name}")
        if observed is None:
            unobserved.append(name)
        elif observed == expected:
            matching.append(name)
        else:
            drifted.append(name)
    return matching, drifted, unobserved


def freshness(
    row: dict[str, Any], now: datetime, stale_after: timedelta = STALE_AFTER
) -> str:
    observed_at = row.get("last_observed_at")
    if observed_at is None:
        return "unknown"
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    return "fresh" if now - observed_at <= stale_after else "stale"


def derive_state(
    row: dict[str, Any],
    now: datetime,
    *,
    reporter_status: str | None = None,
    stale_after: timedelta = STALE_AFTER,
) -> tuple[str, str]:
    """Derive ``monitoring_state`` from desired identity, runtime evidence and freshness.

    ``certified`` is never derived here; it is granted by the certification
    endpoint and survives only while evidence stays synced and fresh.
    """
    current = row.get("monitoring_state") or "unregistered"
    if current == "unregistered":
        return "unregistered", "service is not registered in the catalog"
    if reporter_status == "failed":
        return "failed", "collector reported a failed apply or readback"
    if reporter_status == "applying":
        return "applying", "collector reported an apply in progress"
    expected = declared_expectations(row)
    if not expected:
        return (
            "registered",
            "no expected release identity is declared; runtime evidence cannot be compared",
        )
    if row.get("last_observed_at") is None:
        return (
            "pending",
            "expected release identity declared; no runtime observation yet",
        )
    if freshness(row, now, stale_after) == "stale":
        return (
            "unknown",
            f"last observation is older than {int(stale_after.total_seconds())}s",
        )
    matching, drifted, unobserved = compare(row)
    if drifted:
        return "drifted", "observed differs from expected: " + ", ".join(
            sorted(drifted)
        )
    if unobserved:
        return "unknown", "expected fields without an observation: " + ", ".join(
            sorted(unobserved)
        )
    if current == "certified":
        return (
            "certified",
            "certification evidence remains valid; runtime identity synced and fresh",
        )
    return (
        "synced",
        "every expected field matches fresh runtime evidence: "
        + ", ".join(sorted(matching)),
    )


def certification_blockers(
    row: dict[str, Any], evidence: CertificationEvidence, now: datetime
) -> list[str]:
    """Why a service may not be certified right now; empty means certifiable."""
    blockers: list[str] = []
    state, reason = derive_state(row, now)
    if state not in {"synced", "certified"}:
        blockers.append(f"monitoring_state is {state}: {reason}")
    if freshness(row, now) != "fresh":
        blockers.append("runtime evidence is not fresh")
    if not declared_expectations(row):
        blockers.append("no expected release identity is declared")
    if (
        not row.get("prometheus_target_id")
        and row.get("metrics_profile") != "not-applicable"
    ):
        blockers.append("prometheus_target_id is not bound")
    if not row.get("grafana_dashboard_ids"):
        blockers.append("no Grafana dashboard is bound")
    gaps = evidence.gaps(not_applicable_evidence(row))
    if gaps:
        blockers.append("evidence missing: " + ", ".join(gaps))
    return blockers
