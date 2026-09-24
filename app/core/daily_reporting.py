"""Immutable, scoped daily reporting primitives."""

from __future__ import annotations

import hashlib
import html
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable
from zoneinfo import ZoneInfo

UNITS = {"TL", "DEV", "SCP"}


@dataclass(frozen=True)
class Recipient:
    reference: str
    role: str
    business_units: frozenset[str]
    campaigns: frozenset[str]
    customer_data_access: bool = False


@dataclass(frozen=True)
class Metric:
    code: str
    display_name: str
    source: str
    unit: str
    aggregation: str
    owner: str
    target: float | None = None
    warning: float | None = None
    critical: float | None = None


METRICS = tuple(
    Metric(*row)
    for row in [
        (
            "leads_received",
            "Leads received",
            "odoo",
            "count",
            "sum",
            "campaign_manager",
        ),
        (
            "pipeline_conversion",
            "Pipeline conversion",
            "odoo",
            "percent",
            "ratio",
            "sales",
        ),
        (
            "calls_completed",
            "Calls completed",
            "vicidial",
            "count",
            "sum",
            "operations",
        ),
        (
            "agent_occupancy",
            "Agent occupancy",
            "vicidial",
            "percent",
            "ratio",
            "workforce",
        ),
        (
            "callbacks_overdue",
            "Callbacks overdue",
            "odoo",
            "count",
            "sum",
            "supervisor",
        ),
        ("sales_won", "Sales won", "odoo", "count", "sum", "sales"),
        ("fulfillment_open", "Fulfillment open", "odoo", "count", "sum", "fulfillment"),
        ("retention_risk", "Retention risk", "odoo", "count", "sum", "retention"),
        ("upsell_value", "Upsell value", "odoo", "currency", "sum", "sales"),
        ("ai_tasks", "AI tasks", "middleware", "count", "sum", "ai"),
        ("ai_fit_average", "Average Fit Score", "middleware", "score", "average", "ai"),
        (
            "ai_review_rate",
            "AI human review rate",
            "middleware",
            "percent",
            "ratio",
            "compliance",
        ),
        (
            "ai_adoption_rate",
            "AI adoption rate",
            "middleware",
            "percent",
            "ratio",
            "operations",
        ),
        ("ai_qa_score", "AI QA score", "odoo", "score", "average", "qa"),
        (
            "ai_compliance_findings",
            "AI compliance findings",
            "odoo",
            "count",
            "sum",
            "compliance",
        ),
        ("ai_provider_cost", "AI provider cost", "middleware", "currency", "sum", "ai"),
        (
            "middleware_health",
            "Middleware health",
            "prometheus",
            "status",
            "last",
            "technical",
        ),
        ("n8n_health", "n8n health", "prometheus", "status", "last", "technical"),
        ("odoo_health", "Odoo health", "prometheus", "status", "last", "technical"),
        (
            "vicidial_health",
            "VICIdial health",
            "prometheus",
            "status",
            "last",
            "technical",
        ),
        (
            "reconciliation_gaps",
            "Reconciliation gaps",
            "middleware",
            "count",
            "sum",
            "technical",
        ),
        ("dlq_depth", "DLQ depth", "middleware", "count", "last", "technical"),
        (
            "security_alerts",
            "Security alerts",
            "monitoring",
            "count",
            "sum",
            "security",
        ),
        ("required_actions", "Required actions", "reporting", "count", "sum", "owner"),
    ]
)


def safe_ratio(numerator: float, denominator: float) -> float | None:
    return None if denominator == 0 else round(100 * numerator / denominator, 2)


def report_key(report_date: str, scope: str, scope_id: str, version: int) -> str:
    return hashlib.sha256(
        f"{report_date}|{scope}|{scope_id}|{version}".encode()
    ).hexdigest()


def authorized(
    recipient: Recipient, unit: str, campaign: str, detail: bool = False
) -> bool:
    if unit not in UNITS:
        return False
    if recipient.role == "platform_superuser":
        return not detail or recipient.customer_data_access
    if unit not in recipient.business_units:
        return False
    if recipient.role == "business_unit_director":
        return True
    if recipient.role == "technical_admin":
        return not detail
    return campaign in recipient.campaigns


def previous_local_day(now: datetime, timezone: str) -> tuple[datetime, datetime]:
    local = now.astimezone(ZoneInfo(timezone))
    end = local.replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=1)
    return start, end


def quality_status(reconciliation_ok: bool, missing_sources: Iterable[str]) -> str:
    missing = tuple(missing_sources)
    if not reconciliation_ok:
        return "blocked"
    return "partial" if missing else "complete"


def render_html(
    title: str, unit: str, campaign: str, metrics: dict[str, object], secure_link: str
) -> str:
    if not secure_link.startswith("https://"):
        raise ValueError("secure report links must use HTTPS")
    rows = "".join(
        f"<tr><th>{html.escape(code)}</th><td>{html.escape(str(value))}</td></tr>"
        for code, value in sorted(metrics.items())
    )
    return (
        f"<html><body><h1>{html.escape(title)}</h1>"
        f"<p>{html.escape(unit)} / {html.escape(campaign)}</p>"
        f'<table>{rows}</table><a href="{html.escape(secure_link)}">Secure report</a>'
        "</body></html>"
    )
