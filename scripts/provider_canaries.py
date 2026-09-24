#!/usr/bin/env python3
"""Run the four approved staging provider canaries through Middleware.

Submission is attempted exactly once per channel. Read-only operation polling may
repeat. Any ambiguous submit or missing provider evidence is INDETERMINATE, never
an automatic resubmission.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.provider_canary import (  # noqa: E402
    canonical_fingerprint,
    provider_evidence_digest,
    validate_provider_canary_evidence,
)

RUN_SCHEMA = ROOT / "contracts" / "provider-canary-run.v1.schema.json"
TERMINAL_STATES = {"completed", "failed", "reconciliation_required", "dead_lettered"}
CANARIES: dict[str, dict[str, str]] = {
    "email": {
        "target": "klyrow-email",
        "command_type": "email.message.send.v1",
        "capability": "EMAIL_DELIVERY",
    },
    "sms": {
        "target": "telnexa-sms",
        "command_type": "sms.message.submit.v1",
        "capability": "SMS_DELIVERY",
    },
    "voice": {
        "target": "vicidial-restricted",
        "command_type": "telephony.call.dial.v1",
        "capability": "PRODUCTION_DIALING",
    },
    "social": {
        "target": "postly-social",
        "command_type": "social.publication.publish.v1",
        "capability": "SOCIAL_PUBLISH",
    },
}


class CanaryConfigurationError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def validate_base_url(value: object) -> str:
    if not isinstance(value, str):
        raise CanaryConfigurationError("middleware_base_url must be a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname.endswith(".invalid")
    ):
        raise CanaryConfigurationError(
            "middleware_base_url must be a deployed HTTPS origin without credentials"
        )
    return value.rstrip("/")


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CanaryConfigurationError(f"{label} could not be loaded") from exc
    if not isinstance(value, dict):
        raise CanaryConfigurationError(f"{label} must contain a JSON object")
    return value


def _resolve_file(config_path: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise CanaryConfigurationError(f"{label} must name a file")
    path = Path(value)
    if not path.is_absolute():
        path = config_path.parent / path
    path = path.resolve()
    if not path.is_file():
        raise CanaryConfigurationError(f"{label} does not exist")
    return path


def _json_pointer(value: object, pointer: object) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise CanaryConfigurationError("destination_pointer must be a JSON pointer")
    current = value
    for raw in pointer.split("/")[1:]:
        segment = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        elif (
            isinstance(current, list)
            and segment.isdigit()
            and int(segment) < len(current)
        ):
            current = current[int(segment)]
        else:
            raise CanaryConfigurationError("destination_pointer does not resolve")
    return current


def _bounded_number(value: object, label: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CanaryConfigurationError(f"{label} must be numeric")
    result = float(value)
    if result < low or result > high:
        raise CanaryConfigurationError(f"{label} must be between {low} and {high}")
    return result


def load_configuration(path: Path) -> dict[str, Any]:
    config_path = path.resolve()
    raw = _load_object(config_path, "provider canary configuration")
    required = {
        "schema_version",
        "enabled",
        "environment",
        "middleware_base_url",
        "token_file",
        "tenant_id",
        "requested_by",
        "approval_reference",
        "poll_interval_seconds",
        "timeout_seconds",
        "canaries",
    }
    if set(raw) != required:
        raise CanaryConfigurationError(
            "provider canary configuration keys do not match the locked contract"
        )
    if raw["schema_version"] != "1.0" or raw["enabled"] is not True:
        raise CanaryConfigurationError("provider canaries are not explicitly enabled")
    if raw["environment"] != "staging":
        raise CanaryConfigurationError("provider canaries may run only in staging")
    base_url = validate_base_url(raw["middleware_base_url"])
    try:
        tenant_id = str(uuid.UUID(str(raw["tenant_id"])))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CanaryConfigurationError("tenant_id must be a UUID") from exc
    requested_by = raw["requested_by"]
    if not isinstance(requested_by, str) or not 1 <= len(requested_by) <= 300:
        raise CanaryConfigurationError("requested_by is invalid")
    approval = raw["approval_reference"]
    if (
        not isinstance(approval, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}", approval) is None
        or any(
            word in approval.lower() for word in ("placeholder", "example", "change-me")
        )
    ):
        raise CanaryConfigurationError("approval_reference is missing or a placeholder")
    token_path = _resolve_file(config_path, raw["token_file"], "token_file")
    token = token_path.read_text(encoding="utf-8").strip()
    if len(token) < 16:
        raise CanaryConfigurationError("token_file does not contain a usable token")
    poll_interval = _bounded_number(
        raw["poll_interval_seconds"], "poll_interval_seconds", 0.001, 30
    )
    timeout = _bounded_number(raw["timeout_seconds"], "timeout_seconds", 0.01, 1800)
    entries = raw["canaries"]
    if not isinstance(entries, dict) or set(entries) != set(CANARIES):
        raise CanaryConfigurationError(
            "exactly email, sms, voice, and social are required"
        )

    canaries: dict[str, dict[str, Any]] = {}
    for channel in CANARIES:
        entry = entries[channel]
        if not isinstance(entry, dict) or set(entry) != {
            "payload_file",
            "destination_pointer",
            "approved_destination_reference",
        }:
            raise CanaryConfigurationError(f"{channel} canary keys are invalid")
        approval_ref = entry["approved_destination_reference"]
        if (
            not isinstance(approval_ref, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}", approval_ref) is None
            or any(
                word in approval_ref.lower()
                for word in ("placeholder", "example", "change-me")
            )
        ):
            raise CanaryConfigurationError(
                f"{channel} approved_destination_reference is missing or a placeholder"
            )
        payload_path = _resolve_file(
            config_path, entry["payload_file"], f"{channel} payload_file"
        )
        payload = _load_object(payload_path, f"{channel} payload")
        if "canary" in payload:
            raise CanaryConfigurationError(
                f"{channel} payload must not supply reserved canary metadata"
            )
        destination = _json_pointer(payload, entry["destination_pointer"])
        canaries[channel] = {
            "payload": payload,
            "destination_fingerprint": canonical_fingerprint(destination),
            "payload_fingerprint": canonical_fingerprint(payload),
            "approved_destination_reference": approval_ref,
        }

    return {
        "environment": "staging",
        "middleware_base_url": base_url,
        "token": token,
        "tenant_id": tenant_id,
        "requested_by": requested_by,
        "approval_reference": approval,
        "poll_interval_seconds": poll_interval,
        "timeout_seconds": timeout,
        "canaries": canaries,
    }


def _response_json(response: httpx.Response) -> dict[str, Any] | None:
    try:
        value = response.json()
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _result(
    *,
    channel: str,
    spec: Mapping[str, str],
    outcome: str,
    command_id: str,
    correlation_id: str,
    idempotency_key: str,
    approval_reference: str,
    approved_destination_reference: str,
    destination_fingerprint: str,
    payload_fingerprint: str,
    submitted_at: datetime,
    terminal_at: datetime,
    terminal_status: str,
    reason: str | None = None,
    provider_reference: str | None = None,
    readback_evidence: dict[str, Any] | None = None,
    readback_evidence_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "name": f"{spec['target']}-canary",
        "channel": channel,
        "target": spec["target"],
        "outcome": outcome,
        "command_id": command_id,
        "correlation_id": correlation_id,
        "idempotency_key_fingerprint": canonical_fingerprint(idempotency_key),
        "approval_reference": approval_reference,
        "approved_destination_reference": approved_destination_reference,
        "destination_fingerprint": destination_fingerprint,
        "payload_fingerprint": payload_fingerprint,
        "submitted_at": _iso(submitted_at),
        "terminal_at": _iso(terminal_at),
        "latency_ms": max(0, int((terminal_at - submitted_at).total_seconds() * 1000)),
        "terminal_status": terminal_status,
        "provider_reference": provider_reference,
        "readback_evidence": readback_evidence,
        "readback_evidence_sha256": readback_evidence_sha256,
        "reason": reason,
    }


def _require_evidence_time_window(
    evidence: Any,
    *,
    submitted_at: datetime,
    terminal_at: datetime,
) -> None:
    occurred_at = datetime.fromisoformat(
        evidence.facts["occurred_at"].replace("Z", "+00:00")
    )
    lower = submitted_at - timedelta(minutes=5)
    upper = terminal_at + timedelta(minutes=5)
    if not lower <= occurred_at <= upper:
        raise ValueError("provider event time is outside the canary run window")
    if not lower <= evidence.observed_at <= upper:
        raise ValueError("provider observation time is outside the canary run window")


def _run_one(
    client: httpx.Client,
    *,
    run_id: str,
    channel: str,
    config: Mapping[str, Any],
    sleep: Any,
) -> dict[str, Any]:
    spec = CANARIES[channel]
    item = config["canaries"][channel]
    command_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    idempotency_key = f"provider-canary:{run_id}:{channel}"
    submitted_at = _utc_now()
    payload = dict(item["payload"])
    payload["canary"] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "approval_reference": config["approval_reference"],
        "approved_destination_reference": item["approved_destination_reference"],
        "destination_fingerprint": item["destination_fingerprint"],
        "payload_fingerprint": item["payload_fingerprint"],
    }
    body = {
        "command_id": command_id,
        "command_type": spec["command_type"],
        "command_version": "1.0",
        "target": spec["target"],
        "tenant_id": config["tenant_id"],
        "requested_by": config["requested_by"],
        "correlation_id": correlation_id,
        "idempotency_key": idempotency_key,
        "capability": spec["capability"],
        "payload": payload,
    }
    write_headers = {
        "Authorization": f"Bearer {config['token']}",
        "Content-Type": "application/json",
        "X-Tenant-ID": config["tenant_id"],
        "X-Correlation-ID": correlation_id,
        "Idempotency-Key": idempotency_key,
    }
    try:
        response = client.post("/v1/commands", json=body, headers=write_headers)
    except httpx.TransportError:
        terminal_at = _utc_now()
        return _result(
            channel=channel,
            spec=spec,
            outcome="INDETERMINATE",
            command_id=command_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            approval_reference=config["approval_reference"],
            approved_destination_reference=item["approved_destination_reference"],
            destination_fingerprint=item["destination_fingerprint"],
            payload_fingerprint=item["payload_fingerprint"],
            submitted_at=submitted_at,
            terminal_at=terminal_at,
            terminal_status="submit_outcome_unknown",
            reason="submit transport failed; command was not resubmitted",
        )
    accepted = _response_json(response)
    if response.status_code not in {200, 202} or accepted is None:
        terminal_at = _utc_now()
        outcome = "FAIL" if 400 <= response.status_code < 500 else "INDETERMINATE"
        return _result(
            channel=channel,
            spec=spec,
            outcome=outcome,
            command_id=command_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            approval_reference=config["approval_reference"],
            approved_destination_reference=item["approved_destination_reference"],
            destination_fingerprint=item["destination_fingerprint"],
            payload_fingerprint=item["payload_fingerprint"],
            submitted_at=submitted_at,
            terminal_at=terminal_at,
            terminal_status=f"submit_http_{response.status_code}",
            reason="Middleware did not return canonical command acceptance",
        )
    if str(accepted.get("command_id")) != command_id:
        terminal_at = _utc_now()
        return _result(
            channel=channel,
            spec=spec,
            outcome="INDETERMINATE",
            command_id=command_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            approval_reference=config["approval_reference"],
            approved_destination_reference=item["approved_destination_reference"],
            destination_fingerprint=item["destination_fingerprint"],
            payload_fingerprint=item["payload_fingerprint"],
            submitted_at=submitted_at,
            terminal_at=terminal_at,
            terminal_status="acceptance_identity_mismatch",
            reason="accepted command identity did not match submitted intent",
        )

    read_headers = {
        "Authorization": f"Bearer {config['token']}",
        "X-Tenant-ID": config["tenant_id"],
    }
    deadline = time.monotonic() + config["timeout_seconds"]
    latest_state = str(accepted.get("state") or "accepted")
    operation: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            current = client.get(f"/v1/operations/{command_id}", headers=read_headers)
        except httpx.TransportError:
            sleep(config["poll_interval_seconds"])
            continue
        operation = _response_json(current) if current.status_code == 200 else None
        if operation is not None:
            latest_state = str(operation.get("state") or latest_state)
            if latest_state in TERMINAL_STATES:
                break
        sleep(config["poll_interval_seconds"])

    terminal_at = _utc_now()
    if operation is None or latest_state not in TERMINAL_STATES:
        return _result(
            channel=channel,
            spec=spec,
            outcome="INDETERMINATE",
            command_id=command_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            approval_reference=config["approval_reference"],
            approved_destination_reference=item["approved_destination_reference"],
            destination_fingerprint=item["destination_fingerprint"],
            payload_fingerprint=item["payload_fingerprint"],
            submitted_at=submitted_at,
            terminal_at=terminal_at,
            terminal_status=latest_state,
            reason="provider read-back did not reach a terminal state before timeout",
        )
    if latest_state != "completed":
        return _result(
            channel=channel,
            spec=spec,
            outcome=(
                "INDETERMINATE" if latest_state == "reconciliation_required" else "FAIL"
            ),
            command_id=command_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            approval_reference=config["approval_reference"],
            approved_destination_reference=item["approved_destination_reference"],
            destination_fingerprint=item["destination_fingerprint"],
            payload_fingerprint=item["payload_fingerprint"],
            submitted_at=submitted_at,
            terminal_at=terminal_at,
            terminal_status=latest_state,
            provider_reference=operation.get("provider_operation_id"),
            reason="provider command did not complete with matched read-back",
        )

    evidence_raw = operation.get("readback_evidence")
    try:
        evidence = validate_provider_canary_evidence(
            evidence_raw,
            target=spec["target"],
            destination_fingerprint=item["destination_fingerprint"],
            payload_fingerprint=item["payload_fingerprint"],
            require_success=True,
        )
        _require_evidence_time_window(
            evidence,
            submitted_at=submitted_at,
            terminal_at=terminal_at,
        )
        evidence_value = evidence.model_dump(mode="json")
        digest = provider_evidence_digest(evidence_value)
        if operation.get("readback_evidence_sha256") != digest:
            raise ValueError("persisted read-back evidence digest does not match")
        if operation.get("provider_operation_id") != evidence.provider_reference:
            raise ValueError("provider operation identity does not match evidence")
    except (TypeError, ValueError) as exc:
        return _result(
            channel=channel,
            spec=spec,
            outcome="FAIL",
            command_id=command_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            approval_reference=config["approval_reference"],
            approved_destination_reference=item["approved_destination_reference"],
            destination_fingerprint=item["destination_fingerprint"],
            payload_fingerprint=item["payload_fingerprint"],
            submitted_at=submitted_at,
            terminal_at=terminal_at,
            terminal_status="completed_without_valid_provider_evidence",
            provider_reference=operation.get("provider_operation_id"),
            reason=str(exc),
        )
    return _result(
        channel=channel,
        spec=spec,
        outcome="PASS",
        command_id=command_id,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        approval_reference=config["approval_reference"],
        approved_destination_reference=item["approved_destination_reference"],
        destination_fingerprint=item["destination_fingerprint"],
        payload_fingerprint=item["payload_fingerprint"],
        submitted_at=submitted_at,
        terminal_at=terminal_at,
        terminal_status=evidence.terminal_status,
        provider_reference=evidence.provider_reference,
        readback_evidence=evidence_value,
        readback_evidence_sha256=digest,
    )


def validate_run_evidence(value: object) -> None:
    schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(value)


def run(
    config: Mapping[str, Any],
    *,
    transport: httpx.BaseTransport | None = None,
    sleep: Any = time.sleep,
) -> dict[str, Any]:
    run_uuid = uuid.uuid4()
    run_id = f"provider-canary-{run_uuid.hex}"
    started = _utc_now()
    with httpx.Client(
        base_url=config["middleware_base_url"],
        timeout=httpx.Timeout(15.0),
        follow_redirects=False,
        transport=transport,
    ) as client:
        results = [
            _run_one(
                client,
                run_id=run_id,
                channel=channel,
                config=config,
                sleep=sleep,
            )
            for channel in CANARIES
        ]
    outcomes = {item["outcome"] for item in results}
    overall = (
        "PASS"
        if outcomes == {"PASS"}
        else "FAIL"
        if "FAIL" in outcomes
        else "INDETERMINATE"
    )
    document = {
        "schema_version": "1.0",
        "run_id": run_id,
        "environment": config["environment"],
        "middleware_origin": config["middleware_base_url"],
        "approval_reference": config["approval_reference"],
        "started_at": _iso(started),
        "completed_at": _iso(_utc_now()),
        "overall_status": overall,
        "canaries": results,
    }
    validate_run_evidence(document)
    return document


def write_evidence(path: Path, value: Mapping[str, Any]) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, destination)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run provider canaries and persist redacted read-back evidence"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = load_configuration(args.config)
        evidence = run(config)
        write_evidence(args.evidence, evidence)
    except (CanaryConfigurationError, OSError, httpx.HTTPError) as exc:
        print(f"PROVIDER_CANARIES=BLOCKED reason={exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(
        json.dumps(
            {
                "run_id": evidence["run_id"],
                "overall_status": evidence["overall_status"],
                "outcomes": {
                    item["channel"]: item["outcome"] for item in evidence["canaries"]
                },
                "evidence": str(args.evidence.resolve()),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    raise SystemExit(0 if evidence["overall_status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
