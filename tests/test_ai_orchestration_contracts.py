from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.v1 import ai_commands
from app.core.ai_contracts import AICommand
from app.main import app

ROOT = Path(__file__).resolve().parents[1]


def command(command_type: str, profile: str, *, approval: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "command_id": str(uuid4()), "command_type": command_type, "schema_version": "1.0",
        "tenant_id": str(uuid4()), "actor_id": "synthetic-user", "actor_type": "user",
        "correlation_id": f"corr-{uuid4()}", "idempotency_key": f"fixture-{uuid4()}",
        "priority": 5, "requested_at": now.isoformat(),
        "deadline_at": (now + timedelta(minutes=10)).isoformat(),
        "input": {"text": "synthetic example.invalid content"},
        "model_policy": {"profile": profile, "temperature": 0.2, "max_tokens": 512},
        "resource_limits": {"runtime_seconds": 60, "output_bytes": 65536,
                            "retry_count": 2, "token_budget": 1024},
        "data_classification": "synthetic",
        "approval_policy": {"required": approval, "action_types": ["proposal"] if approval else []},
        "callback_policy": {"mode": "poll"}, "metadata": {"fixture": "true"},
    }


@pytest.mark.parametrize(("kind", "profile", "approval"), [
    ("ai.chat.v1", "fast-chat", False),
    ("ai.coding.v1", "coding-default", False),
    ("ai.crm.v1", "crm-analysis", True),
    ("ai.voice.v1", "voice-summary", True),
    ("ai.embeddings.v1", "embedding-default", False),
])
def test_all_versioned_command_contracts(kind, profile, approval):
    parsed = AICommand.model_validate(command(kind, profile, approval=approval))
    assert parsed.command_type.value == kind
    assert parsed.model_policy.profile == profile


def test_contracts_reject_unknown_schema_model_deadline_privileged_input_and_unapproved_business():
    cases = []
    value = command("ai.chat.v1", "fast-chat")
    value["schema_version"] = "2.0"
    cases.append(value)
    cases.append(command("ai.chat.v1", "coding-default"))
    value = command("ai.chat.v1", "fast-chat")
    value["deadline_at"] = value["requested_at"]
    cases.append(value)
    value = command("ai.chat.v1", "fast-chat")
    value["input"] = {"shell": "id"}
    cases.append(value)
    cases.append(command("ai.crm.v1", "crm-analysis", approval=False))
    for invalid in cases:
        with pytest.raises(ValidationError):
            AICommand.model_validate(invalid)


def test_command_router_is_auth_bound_and_never_anonymous():
    assert ai_commands.router.dependencies
    assert any(item.dependency is ai_commands.tenant for item in ai_commands.router.dependencies)


def test_ai_route_contract_drift():
    actual = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }
    expected = {
        ("POST", "/api/v1/ai/commands"),
        ("GET", "/api/v1/ai/commands/{command_id}"),
        ("POST", "/api/v1/ai/commands/{command_id}/cancel"),
        ("GET", "/api/v1/ai/commands/{command_id}/result"),
        ("POST", "/api/v1/ai/commands/{command_id}/approve"),
        ("POST", "/api/v1/ai/commands/{command_id}/reject"),
        ("GET", "/api/v1/ai/capabilities"),
        ("GET", "/api/v1/ai/usage"),
        ("POST", "/internal/api/v1/ai/worker/jobs/claim"),
        ("POST", "/internal/api/v1/ai/worker/register"),
        ("POST", "/internal/api/v1/ai/worker/heartbeat"),
        ("GET", "/internal/api/v1/ai/worker/config"),
    }
    assert expected <= actual


def test_inactive_n8n_templates_use_middleware_only():
    directory = ROOT / "deploy/n8n/ai-orchestration"
    manifest = json.loads((directory / "manifest-v1.json").read_text())
    assert manifest["activation_permitted"] is False
    for name in manifest["workflows"]:
        raw = (directory / name).read_text()
        workflow = json.loads(raw)
        assert workflow["active"] is False
        assert "middleware-staging.internal.codestra.agency/api/v1/ai/" in raw
        for forbidden in ("10.40.0.4", "127.0.0.1:4000", "127.0.0.1:11434", "ollama", "litellm"):
            assert forbidden not in raw.lower()


def test_worker_is_outbound_only_and_model_endpoints_are_loopback():
    path = ROOT / "worker/qwen_polling_worker.py"
    source = path.read_text()
    assert "socket.create_connection" in source
    assert "socket.bind" not in source and ".listen(" not in source
    assert "http://127.0.0.1:4000" in source
    assert "http://127.0.0.1:11434" in source
    assert "10.40.0.1" in source
    assert "10.40.0.4:" not in source
    spec = importlib.util.spec_from_file_location("qwen_polling_worker", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert set(module.MODEL_REGISTRY) == {
        "fast-chat", "quality-chat", "coding-default", "coding-large",
        "crm-analysis", "voice-summary", "embedding-default",
    }


def test_systemd_worker_is_hardened_activation_gated_and_has_no_listener():
    unit = (ROOT / "deploy/qwen-worker/qwen-middleware-polling-worker.service").read_text()
    for required in ("NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict",
                     "ProtectHome=yes", "IPAddressDeny=any", "IPAddressAllow=10.40.0.1/32",
                     "ConditionPathExists=/etc/codestra/qwen-worker/activation-approved"):
        assert required in unit
    assert "ListenStream" not in unit


def test_synthetic_business_flows_are_proposal_only_and_complete():
    fixture = json.loads((ROOT / "tests/fixtures/ai/synthetic-business-flows.json").read_text())
    assert {item["operation"] for item in fixture["vicidial"]} == {
        "transcription", "summary", "qa", "disposition", "callback", "coaching"
    }
    assert {item["operation"] for item in fixture["odoo"]} == {
        "lead_score", "lead_summary", "email_draft", "activity_proposal",
        "follow_up_proposal", "automation_recommendation", "call_note_draft",
    }
    assert fixture["invariants"] == {
        "approval_required": True, "dispatch_enabled": False,
        "real_odoo_writes": 0, "real_vicidial_commands": 0,
    }
    for item in fixture["vicidial"]:
        value = command("ai.voice.v1", "voice-summary", approval=True)
        value["input"] = item
        assert AICommand.model_validate(value).approval_policy.required
    for item in fixture["odoo"]:
        value = command("ai.crm.v1", "crm-analysis", approval=True)
        value["input"] = item
        assert AICommand.model_validate(value).approval_policy.required
