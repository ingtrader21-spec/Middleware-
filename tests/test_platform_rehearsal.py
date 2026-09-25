"""The production no-effect rehearsal: runner verdicts per environment and
failure mode, the two /platform/v1/rehearsals routes (identity, idempotent
replay, read-back) and the zero-effect guarantee against the live ledger."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.commands import CommandConflict, CommandNotFound, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.core.config import CANONICAL_SCHEMA_HEAD, Settings
from app.core.runtime import RuntimeContainer
from app.platform.rehearsal import NoEffectRehearsal, RehearsalLedger, RehearsalRequest
from app.platform.runtime import build_platform_runtime, command_policies
from app.replay import MemoryReplayGuard
from app.storage import MemoryInboxStore
from tests.test_platform_api import ClaimsVerifier, token

SOURCE_SHA = "0606b0db9ff59802f8da3824d209d2effc13f87d"
OPERATOR_SCOPE = "platform.command platform.command.read platform.command.replay"
LIVE_CHECKS = {
    "source_identity",
    "schema_identity",
    "api_health",
    "adapter_readiness",
    "effect_capabilities_disabled",
    "safety_denials",
    "worker_backlog",
    "reconciler_health",
    "kill_switch_denial",
    "zero_provider_effects",
}


class Stack:
    def __init__(self, settings: Settings, *, capabilities: dict[str, bool] | None = None) -> None:
        self.store = MemoryCommandStore()
        policies = command_policies(settings)
        if capabilities:
            # Simulate a mis-configured capability file that enabled an effect.
            policies = CommandPolicyRegistry(policies.policies, {**policies.capabilities, **capabilities})
        commands = CommandService(store=self.store, policies=policies)
        self.runtime = RuntimeContainer(settings=settings, inbox=MemoryInboxStore(), replay=MemoryReplayGuard(), tokens=ClaimsVerifier(), commands=commands)
        self.runtime.platform = build_platform_runtime(settings, commands=commands, http=None, pool=None, service_id="middleware-integration-api")

    def runner(self) -> NoEffectRehearsal:
        return NoEffectRehearsal(self.runtime, runtime_schema_version=11, contract_digest="a" * 64)

    def app(self):
        from app.application import AppProfile, create_app

        return create_app(settings=self.runtime.settings, runtime=self.runtime, profile=AppProfile.INTEGRATION)


def request(**updates: Any) -> RehearsalRequest:
    value: dict[str, Any] = {"requested_by": "operator-1", "correlation_id": "corr-rehearsal", "reason": "release rehearsal"}
    value.update(updates)
    return RehearsalRequest(**value)


def checks(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["name"]: row for row in report["checks"]}


def live_effects(stack: Stack) -> int:
    return sum(adapter.provider_effects for adapter in (stack.runtime.platform.registry.adapter(i) for i in stack.runtime.platform.registry.ids()))  # type: ignore[union-attr, attr-defined]


@pytest.fixture
def stack(test_settings: Settings) -> Stack:
    return Stack(test_settings.model_copy(update={"source_sha": SOURCE_SHA}))


# ----------------------------------------------------------------------------
# runner
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rehearsal_passes_every_stage_without_touching_the_live_process(stack: Stack) -> None:
    report = await stack.runner().run(request(expected_source_sha=SOURCE_SHA, expected_schema_head=CANONICAL_SCHEMA_HEAD))
    by_name = checks(report)
    assert report["verdict"] == "PASS", report["failed_checks"]
    assert set(by_name) == LIVE_CHECKS | {"synthetic_lifecycle", "restart_reconciliation"}
    assert all(row["status"] == "pass" for row in report["checks"])
    assert report["provider_effects"] == 0
    assert report["identity"]["source_sha"] == SOURCE_SHA and report["identity"]["alembic_schema_head"] == CANONICAL_SCHEMA_HEAD

    lifecycle = by_name["synthetic_lifecycle"]["detail"]
    assert lifecycle["final_state"] == "completed" and lifecycle["readback_status"] == "matched"
    assert lifecycle["exact_replay_duplicate"] is True and lifecycle["outbox_intents"] == 1 and lifecycle["executions"] == 1

    restart = by_name["restart_reconciliation"]["detail"]
    assert restart["state_after_crash"] == "reconciliation_required"
    assert restart["restarted_process_generation"] == restart["crashed_process_generation"] + 1
    assert restart["worker_reclaimed_quarantined_row"] is False
    assert restart["reconciler_action"] == "complete" and restart["final_state"] == "completed"
    assert restart["executions"] == 1  # reconciled from read-back, never resent

    denials = by_name["safety_denials"]["detail"]
    assert denials["evaluated"] and denials["admitted"] == []
    assert all(row["denied"] for row in denials["evaluated"])
    assert {"ODOO_WRITE", "SMS_DELIVERY", "EMAIL_DELIVERY"} <= {row["capability"] for row in denials["evaluated"]}
    assert "global_kill_switch" in by_name["kill_switch_denial"]["detail"]["kernel_reason"]

    # Nothing reached the live ledger, the live adapters or the live gate.
    assert stack.store._outbox == [] and stack.store._commands == {}
    assert live_effects(stack) == 0
    assert stack.runtime.platform.safety.global_kill is False  # type: ignore[union-attr]
    zero = by_name["zero_provider_effects"]["detail"]
    assert zero["live_provider_effect_attempts_delta"] == 0 and zero["sandbox_external_effect_adapters"] == [] and zero["sandbox_http_client"] is False


@pytest.mark.asyncio
async def test_report_digest_covers_the_canonical_report(stack: Stack) -> None:
    from app.platform.rehearsal import _canonical_digest

    report = await stack.runner().run(request())
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    assert report["report_sha256"] == _canonical_digest(body)


@pytest.mark.asyncio
async def test_identity_pins_fail_the_rehearsal_on_mismatch(stack: Stack) -> None:
    report = await stack.runner().run(request(expected_source_sha="deadbeef", expected_schema_head="0001_initial"))
    by_name = checks(report)
    assert report["verdict"] == "FAIL"
    assert {"source_identity", "schema_identity"} <= set(report["failed_checks"])
    assert "source_sha_mismatch" in by_name["source_identity"]["detail"]["problems"]
    assert "schema_head_mismatch" in by_name["schema_identity"]["detail"]["problems"]


@pytest.mark.asyncio
async def test_production_proves_the_synthetic_denial_instead_of_running_the_lane(stack: Stack) -> None:
    stack.runtime.settings = stack.runtime.settings.model_copy(update={"app_env": "production"})
    report = await stack.runner().run(request())
    by_name = checks(report)
    assert report["verdict"] == "PASS", report["failed_checks"]
    assert "synthetic_lifecycle" not in by_name
    denial = by_name["synthetic_production_denial"]
    assert denial["status"] == "pass" and "synthetic_command_in_production" in denial["detail"]["reason"]
    assert denial["detail"]["outbox_intents"] == 0
    assert by_name["restart_reconciliation"]["status"] == "skipped"
    kill = by_name["kill_switch_denial"]
    assert kill["status"] == "pass" and "kernel_reason" not in kill["detail"]
    assert "global_kill_switch" in kill["detail"]["gate_reason_codes"]


@pytest.mark.asyncio
async def test_production_without_a_source_sha_fails_identity(stack: Stack) -> None:
    stack.runtime.settings = stack.runtime.settings.model_copy(update={"app_env": "production", "source_sha": "unknown"})
    report = await stack.runner().run(request())
    assert "source_identity" in report["failed_checks"]


@pytest.mark.asyncio
async def test_an_enabled_effect_capability_fails_the_rehearsal(test_settings: Settings) -> None:
    stack = Stack(test_settings.model_copy(update={"source_sha": SOURCE_SHA}), capabilities={"ODOO_WRITE": True})
    report = await stack.runner().run(request())
    by_name = checks(report)
    assert report["verdict"] == "FAIL"
    assert by_name["effect_capabilities_disabled"]["status"] == "fail"
    assert by_name["effect_capabilities_disabled"]["detail"]["external_effect_capabilities_enabled"] == ["ODOO_WRITE"]
    # The Settings effect gates still deny it: the gate layer holds on its own.
    assert by_name["safety_denials"]["status"] == "pass"


@pytest.mark.asyncio
async def test_a_tripped_live_kill_switch_is_inherited_by_the_sandbox(stack: Stack) -> None:
    stack.runtime.platform.safety.trip()  # type: ignore[union-attr]
    report = await stack.runner().run(request())
    by_name = checks(report)
    assert by_name["synthetic_lifecycle"]["status"] == "fail"
    assert by_name["restart_reconciliation"]["status"] == "fail"
    assert report["verdict"] == "FAIL" and report["provider_effects"] == 0


@pytest.mark.asyncio
async def test_an_invalid_adapter_registry_fails_adapter_readiness(stack: Stack) -> None:
    stack.runtime.platform.registry_error = "enabled capability has no adapter"  # type: ignore[union-attr]
    report = await stack.runner().run(request())
    assert "adapter_readiness" in report["failed_checks"]
    assert "api_health" in report["failed_checks"]  # readiness reports the registry too


def test_ledger_is_bounded_and_keys_never_run_twice() -> None:
    ledger = RehearsalLedger(limit=2)
    for index in range(3):
        ledger.record("op", f"key-{index:04d}", "digest", {"rehearsal_id": f"id-{index}"})
    with pytest.raises(CommandNotFound):
        ledger.get("id-0")
    assert ledger.latest() == {"rehearsal_id": "id-2"}
    assert ledger.replayed("op", "key-0002", "digest") == {"rehearsal_id": "id-2"}
    assert ledger.replayed("other", "key-0002", "digest") is None
    with pytest.raises(CommandConflict):
        ledger.replayed("op", "key-0002", "different")
    with pytest.raises(CommandConflict):
        ledger.replayed("op", "key-0000", "digest")  # aged out: refuse instead of re-running


# ----------------------------------------------------------------------------
# API
# ----------------------------------------------------------------------------
def rehearsal_headers(bearer: str, *, key: str = "rehearsal-key-0001") -> dict[str, str]:
    return {"Authorization": f"Bearer {bearer}", "X-Correlation-ID": "corr-api-rehearsal", "Idempotency-Key": key, "Content-Type": "application/json"}


def test_rehearsal_routes_require_operator_identity(stack: Stack) -> None:
    body = {"reason": "release rehearsal"}
    with TestClient(stack.app()) as client:
        assert client.post("/platform/v1/rehearsals/no-effect", json=body).status_code == 401
        read_only = client.post("/platform/v1/rehearsals/no-effect", json=body, headers=rehearsal_headers(token(scope="platform.command platform.command.read")))
        assert read_only.status_code == 401
        no_role = client.post("/platform/v1/rehearsals/no-effect", json=body, headers=rehearsal_headers(token(scope=OPERATOR_SCOPE)))
        assert no_role.status_code == 403
        operator = token(scope=OPERATOR_SCOPE, roles=("platform-operator",))
        missing_key = client.post("/platform/v1/rehearsals/no-effect", json=body, headers={k: v for k, v in rehearsal_headers(operator).items() if k != "Idempotency-Key"})
        assert missing_key.status_code == 400
        bad_body = client.post("/platform/v1/rehearsals/no-effect", json={**body, "expected_source_sha": "not-a-sha"}, headers=rehearsal_headers(operator))
        assert bad_body.status_code == 400
        assert client.get("/platform/v1/rehearsals/00000000-0000-0000-0000-000000000000").status_code == 401
    assert stack.runtime.platform.rehearsals.latest() is None  # type: ignore[union-attr]


def test_rehearsal_run_replay_and_readback(stack: Stack) -> None:
    operator = token(scope=OPERATOR_SCOPE, roles=("platform-operator",), sub="operator-1")
    body = {"reason": "release rehearsal", "expected_source_sha": SOURCE_SHA, "expected_schema_head": CANONICAL_SCHEMA_HEAD}
    with TestClient(stack.app()) as client:
        created = client.post("/platform/v1/rehearsals/no-effect", json=body, headers=rehearsal_headers(operator))
        assert created.status_code == 201, created.text
        report = created.json()
        assert report["verdict"] == "PASS", report["failed_checks"]
        assert report["requested_by"] == "operator-1" and report["correlation_id"] == "corr-api-rehearsal"
        assert report["provider_effects"] == 0
        assert created.headers["Location"] == f"/platform/v1/rehearsals/{report['rehearsal_id']}"
        assert created.headers["X-Correlation-ID"] == "corr-api-rehearsal"

        replay = client.post("/platform/v1/rehearsals/no-effect", json=body, headers=rehearsal_headers(operator))
        assert replay.status_code == 200 and replay.json() == report

        conflict = client.post("/platform/v1/rehearsals/no-effect", json={**body, "reason": "another"}, headers=rehearsal_headers(operator))
        assert conflict.status_code == 409

        reader = token(scope="platform.command.read")
        read = client.get(created.headers["Location"], headers={"Authorization": f"Bearer {reader}"})
        assert read.status_code == 200 and read.json() == report
        missing = client.get("/platform/v1/rehearsals/00000000-0000-0000-0000-000000000000", headers={"Authorization": f"Bearer {reader}"})
        assert missing.status_code == 404

        text = read.text.lower()
        for forbidden in ("password", "client_secret", "bearer ", "private_key", "hvs."):
            assert forbidden not in text
    assert stack.store._outbox == [] and stack.store._commands == {}
    assert live_effects(stack) == 0
