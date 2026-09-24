#!/usr/bin/env python3
"""Fail-closed four-submission lifecycle replay tool."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

from target_identity import IdentityError, NoRedirect, discover, verify_health

EVENT_ORDER = (
    "vicidial.call.started",
    "vicidial.call.connected",
    "vicidial.call.ended",
)
INGRESS_PATH = "/api/v1/events/vicidial"
CLIENT = "vicidial-server-b"


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def contains_test_evidence_marker(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            "test_evidence_id" in str(key).lower()
            or contains_test_evidence_marker(nested)
            for key, nested in value.items()
        )
    if isinstance(value, list):
        return any(contains_test_evidence_marker(item) for item in value)
    return False


def load_events(path: Path, linked_id: str) -> list[tuple[dict[str, Any], bytes]]:
    if path.is_symlink() or not path.is_file():
        fail("events input must be a regular non-symlink file")
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("events input must contain valid UTF-8 JSON")
    if not isinstance(rows, list) or len(rows) != 3:
        fail("exactly three outbox rows are required")
    result = []
    seen = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("payload"), dict):
            fail("each outbox row must contain one envelope in payload")
        event = row["payload"]
        if event.get("event_type") != EVENT_ORDER[index]:
            fail("events are not in started, connected, ended order")
        if event.get("asterisk_linked_id") != linked_id:
            fail("event LinkedID does not match the authorized tuple")
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id or event_id in seen:
            fail("event IDs must be non-empty and unique")
        seen.add(event_id)
        payload = event.get("payload")
        expected_hash = event.get("payload_sha256")
        if not isinstance(payload, dict) or hashlib.sha256(canonical(payload)).hexdigest() != expected_hash:
            fail("payload integrity hash mismatch")
        if contains_test_evidence_marker(event):
            fail("test evidence markers are forbidden in envelopes")
        result.append((event, canonical(event)))
    return result


def protected_secret(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail("secret must be a regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        fail("secret file permissions are too broad")
    value = path.read_text().strip()
    if not value or any(ord(char) < 32 for char in value):
        fail("secret is empty or contains control characters")
    return value


def request(url: str, body: bytes, secret: str, event_id: str, response_log: Path) -> int:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(24)
    signature = hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Idempotency-Key": event_id,
            "X-Signature": f"sha256={signature}",
            "X-Timestamp": timestamp,
            "X-Client-Instance-ID": CLIENT,
            "X-Nonce": nonce,
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            status_code = response.status
            response_body = response.read(16384)
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        response_body = exc.read(16384)
    with response_log.open() as existing_log:
        attempt = sum(1 for _ in existing_log) + 1
    record = {
        "attempt": attempt,
        "event_id": event_id,
        "request_body_sha256": hashlib.sha256(body).hexdigest(),
        "status": status_code,
        "response_sha256": hashlib.sha256(response_body).hexdigest(),
    }
    with response_log.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return status_code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--expected-linked-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--response-log", type=Path)
    parser.add_argument("--maximum-submissions", type=int, default=4)
    args = parser.parse_args()
    if args.maximum_submissions != 4:
        fail("maximum submissions must equal four")
    events = load_events(args.events, args.expected_linked_id)
    plan = [
        {"event_type": event["event_type"], "event_id": event["event_id"],
         "body_sha256": hashlib.sha256(body).hexdigest()}
        for event, body in (*events, events[-1])
    ]
    try:
        target = discover()
        verify_health(target)
    except IdentityError as exc:
        fail(f"target identity check failed: {exc}")
    identity = target.redacted_evidence()
    if not args.execute:
        print(json.dumps({
            "mode": "dry-run",
            "submission_count": 4,
            "target": identity,
            "plan": plan,
        }, sort_keys=True))
        return 0
    if not args.secret_file or not args.response_log:
        fail("execute requires secret-file and response-log")
    if args.response_log.exists():
        fail("response log must not already exist")
    args.response_log.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.response_log.touch(mode=0o600, exist_ok=False)
    secret = protected_secret(args.secret_file)
    attempts = 0
    for event, body in (*events, events[-1]):
        attempts += 1
        status_code = request(
            target.ingress_url, body, secret, event["event_id"], args.response_log
        )
        if status_code not in {200, 201, 202}:
            fail(f"submission {attempts} failed; automatic retry is disabled")
    if attempts != 4:
        fail("submission count invariant failed")
    print("HTTP_SUBMISSION_COUNT=4")
    return 0


if __name__ == "__main__":
    sys.exit(main())
