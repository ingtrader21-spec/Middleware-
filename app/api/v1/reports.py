import csv
import html
import io
from typing import Any
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Response

from app.core.kpis import calculate_kpis

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])
REPORTS = {
    "executive-summary",
    "campaign-performance",
    "agent-performance",
    "disposition-funnel",
    "callback-performance",
    "lead-pipeline",
    "qa",
    "automation-health",
    "data-integrity",
}


@router.get("/{report_name}")
async def report(
    report_name: str,
    from_: datetime | None = Query(None, alias="from"),
    to: datetime | None = None,
    timezone: str = "America/Santo_Domingo",
    campaign_id: str | None = None,
    list_id: str | None = None,
    agent_id: str | None = None,
    supervisor_id: str | None = None,
    team_id: str | None = None,
    disposition: str | None = None,
    format: Literal["json", "csv", "html"] = "json",
):
    if report_name not in REPORTS:
        from fastapi import HTTPException

        raise HTTPException(404, "unknown report")
    filters = {
        key: value
        for key, value in locals().items()
        if key not in {"format"} and value is not None
    }
    values: dict[str, Any] = {
        "dialed_calls": 0,
        "answered_calls": 0,
        "human_contacts": 0,
        "sales": 0,
    }
    kpis = calculate_kpis(values)
    payload = {
        "report": report_name,
        "filters": filters,
        "values": values,
        "kpis": kpis,
        "rows": [],
    }
    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["metric", "value"])
        for key, value in kpis.items():
            writer.writerow([key, value])
        return Response(output.getvalue(), media_type="text/csv")
    if format == "html":
        rows = "".join(
            f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
            for key, value in kpis.items()
        )
        return Response(
            "<!doctype html><html><body>"
            f"<h1>{html.escape(report_name)}</h1><table>{rows}</table></body></html>",
            media_type="text/html",
        )
    return payload
