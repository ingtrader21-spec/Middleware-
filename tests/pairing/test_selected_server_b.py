"""Paired-source test against an exact checked-out Server B implementation.

The test imports Server B itself. Only its AMI transport is synthetic; HTTP
authentication, routes, policy enforcement, idempotency, audit, and SQLite
persistence are the selected source's real implementations.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.vicidial_internal_call_adapter import (
    VicidialInternalCallAdapter,
    VicidialInternalCallPreDispatchRejected,
)
from app.calling_contract import CallPrincipal, CallingGrant
from tests.test_vicidial_internal_call_adapter import (
    SECRET, SOURCE_SHA, command, environment, hangup_command,
)


SERVER_B_SHA = "9ac8ef4840f78ba4ad9b816e4e409298505103ce"
SERVER_B_ROOT_VALUE = os.environ.get("CODESTRA_SELECTED_SERVER_B_ROOT")
SERVER_B_ROOT = Path(SERVER_B_ROOT_VALUE) if SERVER_B_ROOT_VALUE else None

pytestmark = pytest.mark.skipif(
    SERVER_B_ROOT is None or not SERVER_B_ROOT.is_dir(),
    reason="set CODESTRA_SELECTED_SERVER_B_ROOT to the exact Server B checkout",
)


@pytest.mark.asyncio
async def test_real_selected_server_b_hmac_routes_policy_and_persistence(
    tmp_path, monkeypatch,
):
    assert os.environ.get("CODESTRA_SELECTED_SERVER_B_SHA") == SERVER_B_SHA
    assert SERVER_B_ROOT is not None
    sys.path.insert(0, str(SERVER_B_ROOT / "vicidial" / "src"))
    sys.path.insert(0, str(SERVER_B_ROOT / "vicidial" / "tests"))
    try:
        # The selected module constructs its default ASGI app at import time.
        # Keep that real initialization inside the disposable test directory.
        monkeypatch.setenv(
            "CODESTRA_ADAPTER_STATE", str(tmp_path / "import-state.sqlite3"),
        )
        # These modules belong to the separately pinned optional checkout.
        from importlib import import_module

        create_app = import_module("codestra_vicidial.app").create_app
        ami_module = import_module("codestra_vicidial.ami_gateway")
        AgentBinding = ami_module.AgentBinding
        AgentDirectory = ami_module.AgentDirectory
        LifecycleStore = ami_module.LifecycleStore
        parse_ami_block = ami_module.parse_ami_block
        MemoryRepository = import_module("codestra_vicidial.repository").MemoryRepository
        RequestAuthenticator = import_module("codestra_vicidial.security").RequestAuthenticator
        service_module = import_module("codestra_vicidial.service")
        AdapterService = service_module.AdapterService
        FeatureFlags = service_module.FeatureFlags
        StateStore = import_module("codestra_vicidial.state").StateStore
        calling_tests = import_module("test_internal_calling")
        executor = calling_tests.executor
        seed_connected = calling_tests.seed_connected

        server_root = tmp_path / "server-b"
        middleware_root = tmp_path / "middleware"
        server_root.mkdir()
        middleware_root.mkdir()
        server, ami, lifecycle = executor(server_root)
        auth = RequestAuthenticator(
            "codestra-middleware", SECRET, frozenset({"127.0.0.1"}),
        )
        app = create_app(
            AdapterService(
                MemoryRepository(),
                StateStore(tmp_path / "adapter-state.sqlite3"),
                FeatureFlags(),
            ),
            auth,
            internal_call_executor=server,
        )

        _, env = environment(middleware_root)
        actor = CallPrincipal(
            tenant_id="tenant-test", subject="subject-appolon",
            employee_id="employee-appolon", campaign_id="TEST_SYN",
            business_unit="synthetic-unit", extension="6901",
        )
        now = datetime.now(UTC)
        grant = CallingGrant(
            authorization_reference="CHG-APPOLON-INTERNAL-0001",
            principal=actor, destination="internal:TEST_ECHO",
            caller_id="+12025550123", lead_id=17,
            not_before=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=10), source_sha=SOURCE_SHA,
        )
        Path(env["CODESTRA_INTERNAL_CALL_POLICY_FILE"]).write_text(
            grant.model_dump_json()
        )
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 50000)),
            base_url="https://server-b.internal",
        )
        adapter = VicidialInternalCallAdapter(
            SimpleNamespace(source_sha=SOURCE_SHA), env, client,
        )

        base = command(grant)
        request = type(base)(**{
            **base.__dict__,
            "payload": {
                **base.payload,
                "actor": actor.model_dump(mode="json"),
                "originate": {
                    **base.payload["originate"],
                    "business_unit": "synthetic-unit",
                },
            },
        })
        accepted = await adapter.execute(request)
        assert accepted.status == "accepted"
        assert len(ami.actions) == 1
        duplicate = await adapter.execute(request)
        assert duplicate.status == "accepted"
        assert len(ami.actions) == 1

        seed_connected(lifecycle, accepted.provider_operation_id)
        pending = await adapter.readback(request)
        assert pending.status == "mismatch"

        server.policy_provider = lambda: server.policy.model_copy(
            update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
        )
        second = type(request)(**{
            **request.__dict__,
            "command_id": "33333333-3333-5333-8333-333333333333",
            "idempotency_key": "originate-appolon-expired-0002",
        })
        with pytest.raises(
            VicidialInternalCallPreDispatchRejected,
            match="conclusively rejected",
        ):
            await adapter.execute(second)
        assert len(ami.actions) == 1

        hangup_base = hangup_command(grant)
        hangup = type(hangup_base)(**{
            **hangup_base.__dict__,
            "payload": {
                **hangup_base.payload,
                "actor": actor.model_dump(mode="json"),
                "originate": {
                    **hangup_base.payload["originate"],
                    "business_unit": "synthetic-unit",
                },
                "origin_operation_id": request.command_id,
                "call_id": accepted.provider_operation_id,
            },
        })
        ended = await adapter.execute(hangup)
        assert ended.status == "accepted"
        assert [action["Action"] for action in ami.actions] == ["Originate", "Hangup"]

        directory = AgentDirectory([
            AgentBinding(
                extension="6901", tenant_id="tenant-test",
                business_unit_id="synthetic-unit", campaign_id="TEST_SYN",
                agent_id="appolon", keycloak_subject="subject-appolon",
            )
        ])
        terminal_event = parse_ami_block((
            f"Event: Hangup\r\nUniqueid: {accepted.provider_operation_id}\r\n"
            f"Linkedid: {accepted.provider_operation_id}\r\n"
            "Channel: PJSIP/6901-00000001\r\nCause: 16\r\n"
            "Cause-txt: Normal Clearing\r\nDuration: 3\r\nBillableSeconds: 2"
        ).encode())
        LifecycleStore(lifecycle).process(terminal_event, directory)
        terminal = await adapter.readback(hangup)
        assert terminal.status == "matched"
        assert terminal.readback_evidence is not None
        assert terminal.readback_evidence["terminal"] is True
        assert terminal.readback_evidence["call_state"] == "completed"
        assert terminal.readback_evidence["hangup_cause_code"] == 16
        assert len(ami.actions) == 2

        with sqlite3.connect(server.state_path) as db:
            call = db.execute(
                "SELECT operation_id,state,hangup_state FROM internal_calls"
            ).fetchone()
            call_count = db.execute("SELECT count(*) FROM internal_calls").fetchone()[0]
        assert call == (request.command_id, "accepted", "requested")
        assert call_count == 1
        with sqlite3.connect(server.audit_path) as db:
            outcomes = db.execute(
                "SELECT outcome FROM audit WHERE operation='internal-call.originate' "
                "ORDER BY sequence"
            ).fetchall()
            hangup_outcomes = db.execute(
                "SELECT outcome FROM audit WHERE operation='internal-call.hangup' "
                "ORDER BY sequence"
            ).fetchall()
        assert outcomes == [
            ("requested",), ("accepted",), ("requested",), ("duplicate",),
            ("requested",), ("denied",),
        ]
        assert hangup_outcomes == [("requested",), ("requested",)]
        await client.aclose()
    finally:
        del sys.path[:2]
