#!/usr/bin/env python3
"""Reproduce pre-persistence ingress responses in an isolated image."""
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from pydantic import ValidationError

sys.path.insert(0, "/app")
from app.schemas.registry import parse_event


def main() -> int:
    rows = json.loads(Path("/events.json").read_text())
    body = json.dumps(
        rows[0]["payload"], sort_keys=True, separators=(",", ":")
    ).encode()
    secret = "synthetic-offline-http422-secret"
    timestamp = str(int(time.time()))
    signature = hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    app = FastAPI()

    @app.post("/api/v1/events/vicidial")
    async def ingress(request: Request):
        request_body = await request.body()
        supplied = request.headers["X-Signature"].removeprefix("sha256=")
        signed_at = request.headers["X-Timestamp"]
        expected = hmac.new(
            secret.encode(), signed_at.encode() + b"." + request_body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(401, "request authentication failed")
        try:
            parse_event(request_body, frozenset({
                "vicidial.call.started",
                "vicidial.call.connected",
                "vicidial.call.ended",
            }))
        except (ValidationError, ValueError) as exc:
            raise HTTPException(422, "event schema validation failed") from exc
        return {"accepted": True}
    response = TestClient(app).post(
        "/api/v1/events/vicidial",
        content=body,
        headers={
            "Content-Type": "application/json",
            "Idempotency-Key": rows[0]["payload"]["event_id"],
            "X-Signature": f"sha256={signature}",
            "X-Timestamp": timestamp,
            "X-Client-Instance-ID": "vicidial-server-b",
            "X-Nonce": "offline-http422-probe",
        },
    )
    print(json.dumps({
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "status": response.status_code,
        "response": response.json(),
    }, sort_keys=True))
    return 0 if response.status_code == 422 else 1


if __name__ == "__main__":
    sys.exit(main())
