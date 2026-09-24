import hashlib
import importlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).with_name("replay_v3.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("replay_v3", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)
Target = importlib.import_module("target_identity").Target


def rows():
    result = []
    for event_type, status in zip(replay.EVENT_ORDER, ("STARTED", "CONNECTED", "ENDED")):
        payload = {"lifecycle_status": status, "disposition": None, "hangup_cause": None}
        event = {
            "schema_version": "1.0",
            "event_id": hashlib.md5(event_type.encode()).hexdigest(),
            "event_type": event_type,
            "occurred_at": "2026-07-28T01:06:49Z",
            "correlation_id": "1785200809.1",
            "client_instance": replay.CLIENT,
            "source_system": "asterisk-ami",
            "producer_instance_id": "server-b",
            "producer_boot_id": "boot",
            "payload_sha256": hashlib.sha256(replay.canonical(payload)).hexdigest(),
            "asterisk_unique_id": "1785200809.1",
            "asterisk_linked_id": "1785200809.1",
            "channel": "PJSIP/endpoint-6198-test",
            "source_extension": "6198",
            "destination": "*43",
            "dialplan_context": "cs-synth-6198",
            "payload": payload,
        }
        result.append({"payload": event})
    return result


def write(tmp_path, value):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(value))
    return path


def test_exact_three_events_and_byte_identical_terminal_replay(tmp_path):
    events = replay.load_events(write(tmp_path, rows()), "1785200809.1")
    plan = (*events, events[-1])
    assert len(plan) == 4
    assert plan[2][1] == plan[3][1]
    assert [item[0]["event_type"] for item in events] == list(replay.EVENT_ORDER)


@pytest.mark.parametrize(
    "mutation",
    ["extra", "order", "linked", "hash", "marker", "nested-marker", "empty-id"],
)
def test_selection_fails_closed(tmp_path, mutation):
    value = rows()
    if mutation == "extra":
        value.append(value[-1])
    elif mutation == "order":
        value[0], value[1] = value[1], value[0]
    elif mutation == "linked":
        value[0]["payload"]["asterisk_linked_id"] = "other"
    elif mutation == "hash":
        value[0]["payload"]["payload_sha256"] = "0" * 64
    elif mutation == "nested-marker":
        value[0]["payload"]["payload"]["TEST_EVIDENCE_ID"] = "forbidden"
    elif mutation == "empty-id":
        value[0]["payload"]["event_id"] = ""
    else:
        value[0]["payload"]["TEST_EVIDENCE_ID"] = "forbidden"
    with pytest.raises(SystemExit):
        replay.load_events(write(tmp_path, value), "1785200809.1")


def fake_target():
    return Target(
        container_id="a" * 64,
        container_name="compose-middleware-event-gateway-1",
        image="codestra/middleware@sha256:" + "8" * 64,
        image_id="sha256:" + "8" * 64,
        project="compose",
        service="middleware-event-gateway",
        network="codestra_backend",
        address="172.18.0.15",
        ingress_url="http://172.18.0.15:8095/api/v1/events/vicidial",
    )


def test_dry_run_verifies_identity_and_sends_zero_post(tmp_path, monkeypatch, capsys):
    event_file = write(tmp_path, rows())
    verified = []
    posts = []
    monkeypatch.setattr(replay, "discover", fake_target)
    monkeypatch.setattr(replay, "verify_health", lambda target: verified.append(target))
    monkeypatch.setattr(replay, "request", lambda *_args: posts.append(_args))
    monkeypatch.setattr(sys, "argv", [
        "replay_v3.py", "--events", str(event_file),
        "--expected-linked-id", "1785200809.1",
    ])
    assert replay.main() == 0
    assert len(verified) == 1
    assert posts == []
    assert json.loads(capsys.readouterr().out)["submission_count"] == 4


def test_execute_has_exactly_four_posts_no_retry(tmp_path, monkeypatch, capsys):
    event_file = write(tmp_path, rows())
    secret = tmp_path / "secret"
    secret.write_text("synthetic-secret")
    secret.chmod(0o600)
    response_log = tmp_path / "responses.jsonl"
    posts = []
    monkeypatch.setattr(replay, "discover", fake_target)
    monkeypatch.setattr(replay, "verify_health", lambda _target: None)
    monkeypatch.setattr(
        replay, "request",
        lambda _url, body, _secret, event_id, _log: posts.append((body, event_id)) or 202,
    )
    monkeypatch.setattr(sys, "argv", [
        "replay_v3.py", "--events", str(event_file),
        "--expected-linked-id", "1785200809.1", "--execute",
        "--secret-file", str(secret), "--response-log", str(response_log),
        "--maximum-submissions", "4",
    ])
    assert replay.main() == 0
    assert len(posts) == 4
    assert posts[2] == posts[3]
    assert "HTTP_SUBMISSION_COUNT=4" in capsys.readouterr().out
