from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from app.provider_canary import (
    ProviderReadbackEvidence,
    provider_evidence_digest,
)
from scripts.provider_canaries import (
    CANARIES,
    CanaryConfigurationError,
    load_configuration,
    run,
    validate_base_url,
)

TENANT_ID = "00000000-0000-4000-8000-000000000042"
EVIDENCE_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "provider-canary-evidence.v1.schema.json"
)


def config() -> dict[str, Any]:
    return {
        "environment": "staging",
        "middleware_base_url": "https://middleware-staging.example.test",
        "token": "secret-token-that-must-never-appear-in-evidence",
        "tenant_id": TENANT_ID,
        "requested_by": "staging-provider-canary",
        "approval_reference": "CAB-2026-00042",
        "poll_interval_seconds": 0.001,
        "timeout_seconds": 0.02,
        "canaries": {
            "email": {
                "payload": {
                    "from": "canary@codestra.test",
                    "to": ["email-canary@example.test"],
                    "content": {"text": "email canary private marker"},
                },
                "destination_fingerprint": "sha256:" + "1" * 64,
                "payload_fingerprint": "sha256:" + "2" * 64,
                "approved_destination_reference": "CAB-EMAIL-00042",
            },
            "sms": {
                "payload": {
                    "destination": "+15550000042",
                    "content": "sms canary private marker",
                },
                "destination_fingerprint": "sha256:" + "3" * 64,
                "payload_fingerprint": "sha256:" + "4" * 64,
                "approved_destination_reference": "CAB-SMS-00042",
            },
            "voice": {
                "payload": {
                    "destination": "+15550000043",
                    "campaign_id": "TEST_SYN",
                },
                "destination_fingerprint": "sha256:" + "5" * 64,
                "payload_fingerprint": "sha256:" + "6" * 64,
                "approved_destination_reference": "CAB-VOICE-00042",
            },
            "social": {
                "payload": {
                    "account_reference": "staging-social-account",
                    "content": "social canary private marker",
                },
                "destination_fingerprint": "sha256:" + "7" * 64,
                "payload_fingerprint": "sha256:" + "8" * 64,
                "approved_destination_reference": "CAB-SOCIAL-00042",
            },
        },
    }


def evidence(channel: str, command: dict[str, Any]) -> dict[str, Any]:
    canary = command["payload"]["canary"]
    destination = canary["destination_fingerprint"]
    payload = canary["payload_fingerprint"]
    provider_reference = f"{channel}-provider-reference"
    occurred_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if channel == "email":
        facts: dict[str, Any] = {
            "delivery_event_id": "postal-event-42",
            "delivery_status": "delivered",
            "provider_message_id": provider_reference,
            "recipient_fingerprint": destination,
            "occurred_at": occurred_at,
        }
        source = "provider_webhook"
        provider = "postal"
        terminal = "delivered"
    elif channel == "sms":
        facts = {
            "delivery_receipt_id": "jasmin-dlr-42",
            "delivery_status": "delivered",
            "provider_message_id": provider_reference,
            "destination_fingerprint": destination,
            "occurred_at": occurred_at,
        }
        source = "provider_webhook"
        provider = "jasmin"
        terminal = "delivered"
    elif channel == "voice":
        provider_reference = "vicidial-cdr-42"
        facts = {
            "cdr_id": provider_reference,
            "disposition": "ANSWER",
            "duration_seconds": 12,
            "hangup_cause": "NORMAL_CLEARING",
            "destination_fingerprint": destination,
            "occurred_at": occurred_at,
        }
        source = "provider_cdr"
        provider = "vicidial"
        terminal = "completed"
    else:
        provider_reference = "social-post-42"
        facts = {
            "post_id": provider_reference,
            "account_reference_fingerprint": destination,
            "content_fingerprint": payload,
            "publication_state": "published",
            "occurred_at": occurred_at,
        }
        source = "provider_api"
        provider = "mastodon"
        terminal = "published"
    value = {
        "schema_version": "1.0",
        "channel": channel,
        "provider": provider,
        "provider_reference": provider_reference,
        "terminal_status": terminal,
        "observed_at": occurred_at,
        "source": source,
        "destination_fingerprint": destination,
        "payload_fingerprint": payload,
        "facts": facts,
    }
    return ProviderReadbackEvidence.model_validate(value).model_dump(mode="json")


def test_all_four_canaries_require_and_preserve_provider_readback_evidence() -> None:
    submitted: dict[str, dict[str, Any]] = {}
    post_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal post_count
        if request.method == "POST":
            post_count += 1
            command = json.loads(request.content)
            channel = next(
                name
                for name, spec in CANARIES.items()
                if spec["target"] == command["target"]
            )
            submitted[command["command_id"]] = command
            assert request.headers["Authorization"].startswith("Bearer ")
            return httpx.Response(
                202,
                json={"command_id": command["command_id"], "state": "persisted"},
            )
        command_id = request.url.path.rsplit("/", 1)[-1]
        command = submitted[command_id]
        channel = next(
            name
            for name, spec in CANARIES.items()
            if spec["target"] == command["target"]
        )
        proof = evidence(channel, command)
        return httpx.Response(
            200,
            json={
                "command_id": command_id,
                "state": "completed",
                "provider_operation_id": proof["provider_reference"],
                "readback_evidence": proof,
                "readback_evidence_sha256": provider_evidence_digest(proof),
            },
        )

    result = run(config(), transport=httpx.MockTransport(handler))

    assert result["overall_status"] == "PASS"
    assert post_count == 4
    assert {item["channel"] for item in result["canaries"]} == set(CANARIES)
    assert all(item["outcome"] == "PASS" for item in result["canaries"])
    assert all(item["readback_evidence"] for item in result["canaries"])
    serialized = json.dumps(result)
    for secret in (
        "secret-token-that-must-never-appear-in-evidence",
        "email-canary@example.test",
        "+15550000042",
        "+15550000043",
        "private marker",
    ):
        assert secret not in serialized


def test_all_channel_evidence_matches_the_published_json_schema() -> None:
    schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    command = {
        "payload": {
            "canary": {
                "destination_fingerprint": "sha256:" + "1" * 64,
                "payload_fingerprint": "sha256:" + "2" * 64,
            }
        }
    }
    for channel in CANARIES:
        validator.validate(evidence(channel, command))


def test_request_accepted_never_counts_as_a_canary_pass() -> None:
    submitted = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal submitted
        if request.method == "POST":
            submitted += 1
            command = json.loads(request.content)
            return httpx.Response(
                202,
                json={"command_id": command["command_id"], "state": "accepted"},
            )
        return httpx.Response(200, json={"state": "accepted"})

    result = run(config(), transport=httpx.MockTransport(handler))

    assert result["overall_status"] == "INDETERMINATE"
    assert submitted == 4
    assert all(item["outcome"] == "INDETERMINATE" for item in result["canaries"])
    assert all(item["readback_evidence"] is None for item in result["canaries"])


def test_ambiguous_submit_is_not_retried() -> None:
    posts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal posts
        assert request.method == "POST"
        posts += 1
        raise httpx.ReadTimeout(
            "ambiguous provider command submission", request=request
        )

    result = run(config(), transport=httpx.MockTransport(handler))

    assert posts == 4
    assert result["overall_status"] == "INDETERMINATE"
    assert all(
        item["reason"] == "submit transport failed; command was not resubmitted"
        for item in result["canaries"]
    )


def test_stale_provider_evidence_cannot_pass() -> None:
    submitted: dict[str, dict[str, Any]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            command = json.loads(request.content)
            submitted[command["command_id"]] = command
            return httpx.Response(
                202,
                json={"command_id": command["command_id"], "state": "accepted"},
            )
        command_id = request.url.path.rsplit("/", 1)[-1]
        command = submitted[command_id]
        channel = next(
            name
            for name, spec in CANARIES.items()
            if spec["target"] == command["target"]
        )
        proof = evidence(channel, command)
        old = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        proof["observed_at"] = old
        proof["facts"]["occurred_at"] = old
        proof = ProviderReadbackEvidence.model_validate(proof).model_dump(mode="json")
        return httpx.Response(
            200,
            json={
                "command_id": command_id,
                "state": "completed",
                "provider_operation_id": proof["provider_reference"],
                "readback_evidence": proof,
                "readback_evidence_sha256": provider_evidence_digest(proof),
            },
        )

    result = run(config(), transport=httpx.MockTransport(handler))

    assert result["overall_status"] == "FAIL"
    assert all(item["outcome"] == "FAIL" for item in result["canaries"])
    assert all("outside the canary run window" in item["reason"] for item in result["canaries"])


def test_channel_evidence_contract_rejects_local_acceptance_disguised_as_readback() -> (
    None
):
    command = {
        "payload": {
            "canary": {
                "destination_fingerprint": "sha256:" + "1" * 64,
                "payload_fingerprint": "sha256:" + "2" * 64,
            }
        }
    }
    value = evidence("email", command)
    value["source"] = "provider_cdr"
    with pytest.raises(ValueError):
        ProviderReadbackEvidence.model_validate(value)


@pytest.mark.parametrize(
    ("channel", "mutation"),
    [
        ("email", lambda value: value["facts"].update(delivery_status="failed")),
        ("sms", lambda value: value.update(provider="simulator")),
        ("voice", lambda value: value["facts"].update(disposition="NO ANSWER")),
        ("social", lambda value: value.update(provider="local")),
    ],
)
def test_evidence_rejects_mismatched_or_non_provider_proof(
    channel: str,
    mutation: Any,
) -> None:
    command = {
        "payload": {
            "canary": {
                "destination_fingerprint": "sha256:" + "1" * 64,
                "payload_fingerprint": "sha256:" + "2" * 64,
            }
        }
    }
    value = evidence(channel, command)
    mutation(value)
    with pytest.raises(ValueError):
        ProviderReadbackEvidence.model_validate(value)


def test_live_configuration_is_explicit_and_fail_closed(tmp_path: Path) -> None:
    assert validate_base_url("https://middleware-staging.example.test/") == (
        "https://middleware-staging.example.test"
    )
    for unsafe in (
        "http://middleware-staging.example.test",
        "https://user:secret@middleware-staging.example.test",
        "https://middleware-staging.example.invalid",
        "https://middleware-staging.example.test/path",
    ):
        with pytest.raises(CanaryConfigurationError):
            validate_base_url(unsafe)

    config_path = tmp_path / "canaries.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "enabled": False,
                "environment": "staging",
                "middleware_base_url": "https://middleware-staging.example.test",
                "token_file": "token",
                "tenant_id": TENANT_ID,
                "requested_by": "staging-provider-canary",
                "approval_reference": "CAB-2026-00042",
                "poll_interval_seconds": 1,
                "timeout_seconds": 60,
                "canaries": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(CanaryConfigurationError, match="not explicitly enabled"):
        load_configuration(config_path)
