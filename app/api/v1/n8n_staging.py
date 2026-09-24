import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from app.core.config import settings

router = APIRouter(prefix="/v1/n8n", tags=["n8n-staging-compatibility"])


def require_staging() -> None:
    if settings.environment not in {"staging", "test", "integration"}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "route unavailable")


@router.post("/runs/{run_id}/callback", status_code=202)
async def callback(run_id: str, body: dict[str, Any]) -> dict[str, Any]:
    require_staging()
    if body.get("run_id") not in {None, run_id}:
        raise HTTPException(409, "run identifier conflict")
    return {"accepted": True, "duplicate": False, "run_id": run_id, "dry_run": True}


@router.get("/calls/{event_id}/media")
async def media(event_id: str) -> dict[str, Any]:
    require_staging()
    return {
        "event_id": event_id,
        "recording_available": False,
        "transcript_status": "unavailable",
        "synthetic": True,
    }


@router.post("/calls/{event_id}/transcription-request", status_code=202)
async def transcription(event_id: str, body: dict[str, Any]) -> dict[str, Any]:
    require_staging()
    return {"accepted": True, "event_id": event_id, "dry_run": True}


@router.post("/follow-up-proposals", status_code=202)
async def follow_up(body: dict[str, Any]) -> dict[str, Any]:
    require_staging()
    return {
        "accepted": True,
        "proposal_id": body.get("proposal_id", "SYNTHETIC-PROPOSAL"),
        "dry_run": True,
    }


@router.post("/qa-reviews", status_code=202)
async def qa_review(body: dict[str, Any]) -> dict[str, Any]:
    require_staging()
    return {
        "accepted": True,
        "review_id": body.get("review_id", "SYNTHETIC-QA-REVIEW"),
        "dry_run": True,
    }


@router.post("/internal-alerts", status_code=202)
async def internal_alert(body: dict[str, Any]) -> dict[str, Any]:
    require_staging()
    return {
        "accepted": True,
        "alert_id": body.get("alert_id", "SYNTHETIC-INTERNAL-ALERT"),
        "delivery": "disabled",
        "dry_run": True,
    }


@router.get("/reconciliation")
async def reconciliation(
    lookback_minutes: int = Query(ge=1, le=1440),
    stale_after_minutes: int = Query(ge=1, le=1440),
) -> dict[str, Any]:
    require_staging()
    return {
        "generated_at": datetime.now(timezone.utc),
        "exceptions": [],
        "summary": {
            "lookback_minutes": lookback_minutes,
            "stale_after_minutes": stale_after_minutes,
        },
    }


@router.get("/jobs/{job_id}")
async def job(job_id: str) -> dict[str, Any]:
    require_staging()
    return {
        "job_id": job_id,
        "status": "dead_lettered",
        "replay_allowed": True,
        "synthetic": True,
    }


@router.post("/jobs/{job_id}/replay", status_code=202)
async def replay(job_id: str, body: dict[str, Any]) -> dict[str, Any]:
    require_staging()
    return {"accepted": True, "job_id": job_id, "dry_run": True}


@router.get("/test/fault/{status_code}")
async def test_fault(status_code: int) -> None:
    require_staging()
    if status_code not in {500, 503}:
        raise HTTPException(400, "unsupported synthetic fault")
    raise HTTPException(status_code, "synthetic staging fault")


@router.get("/test/delay/{milliseconds}")
async def test_delay(milliseconds: int) -> dict[str, Any]:
    require_staging()
    if milliseconds < 1 or milliseconds > 5000:
        raise HTTPException(400, "invalid synthetic delay")
    await asyncio.sleep(milliseconds / 1000)
    return {"completed": True, "milliseconds": milliseconds, "synthetic": True}
