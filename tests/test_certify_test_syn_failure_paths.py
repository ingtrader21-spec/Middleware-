"""TEST_SYN failure-path certification: runtime evidence API, 8080 refusal and the certifier."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import n8n_runtime as api
from app.core.config import settings
from app.core.n8n_runtime import (
    DispatchRequest,
    ResultContract,
    canonical_bytes,
    dispatch_target_posture,
    sha256,
    verify_fresh,
    verify_runtime,
)
from app.db.models import AuditEvent, N8nRuntimeExecution, N8nRuntimeResult
from app.runtime_safety import runtime_safety_readback
from app.workers import n8n_runtime as worker
from scripts import certify_test_syn_failure_paths as cert

SOURCE_SHA = "c" * 40
IMAGE_DIGEST = "sha256:" + ("d" * 64)
BEARER = "testsyn-middleware-shared-bearer-0123456789"
MONITORING = "testsyn-monitoring-readonly-0123456789abcdef"
HMAC = "testsyn-n8n-runtime-hmac-secret-at-least-32-bytes"
TENANT = "TEST_SYN_TENANT"


# -- dispatch target posture / worker ------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "environment", "allowed", "reason"),
    [
        ("https://n8n.internal.example", "production", True, None),
        ("http://n8n-webhook-staging:5678", "staging", True, None),
        ("http://n8n-webhook-staging:8080", "staging", False, "LEGACY_PORT_8080"),
        ("https://n8n.internal.example:8080", "production", False, "LEGACY_PORT_8080"),
        (
            "http://n8n-webhook-staging:5678",
            "production",
            False,
            "TARGET_NOT_PRIVATE_HTTPS",
        ),
        (
            "https://user:pw@n8n.internal.example",
            "staging",
            False,
            "TARGET_NOT_PRIVATE_HTTPS",
        ),
        ("", "staging", False, "TARGET_NOT_CONFIGURED"),
    ],
)
def test_dispatch_target_posture(url, environment, allowed, reason):
    posture = dispatch_target_posture(url, environment)
    assert posture["allowed"] is allowed
    assert posture["reason"] == reason
    assert posture["legacy_8080"] is (reason == "LEGACY_PORT_8080")
    assert "pw" not in json.dumps(posture)


@pytest.mark.asyncio
async def test_worker_refuses_legacy_8080_target_without_sending(monkeypatch):
    monkeypatch.setattr(
        settings, "n8n_runtime_base_url", "https://n8n.internal.example:8080"
    )
    monkeypatch.setattr(settings, "n8n_runtime_environment", "staging")
    execution = execution_row(status="DISPATCHING", attempt_count=1)
    session = AsyncMock()
    session.get.return_value = execution
    session.scalar.return_value = SimpleNamespace(
        tenant_scope=[TENANT], webhook_path="/webhook/codestra-runtime/test-syn/v1"
    )
    client = AsyncMock()
    assert await worker.dispatch_one(session, execution, client) is False
    client.post.assert_not_called()
    assert execution.last_error_code == "LEGACY_PORT_8080"
    assert execution.status == "DEAD_LETTER"


# -- API: process identity and execution evidence ------------------------------------------


def execution_row(**overrides) -> N8nRuntimeExecution:
    values = {
        "execution_id": uuid4(),
        "tenant_id": TENANT,
        "event_id": "TEST_SYN_FP_EVENT_1",
        "event_type": "test.synthetic.failure_path",
        "source_event_id": "TEST_SYN_FP_SOURCE_1",
        "workflow_code": "TEST_SYN_ROUTER",
        "workflow_version": "1",
        "correlation_id": "TEST_SYN_FP_CORR_1",
        "causation_id": "TEST_SYN_FP_CAUSE_1",
        "trace_id": "0123456789abcdef0123456789abcdef",
        "idempotency_key_hash": "a" * 64,
        "payload_hash": "b" * 64,
        "payload_json": {"synthetic": True},
        "status": "PENDING",
        "attempt_count": 0,
        "timeout_at": datetime.now(UTC) + timedelta(minutes=10),
        "created_at": datetime.now(UTC),
    }
    values.update(overrides)
    return N8nRuntimeExecution(**values)


def result_row(
    execution: N8nRuntimeExecution, status: str, **document
) -> N8nRuntimeResult:
    body = {
        "execution_id": str(execution.execution_id),
        "tenant_id": execution.tenant_id,
        "correlation_id": execution.correlation_id,
        **document,
    }
    return N8nRuntimeResult(
        result_id=uuid4(),
        execution_id=execution.execution_id,
        tenant_id=execution.tenant_id,
        workflow_code=execution.workflow_code,
        result_hash=hashlib.sha256(json.dumps([status, body]).encode()).hexdigest(),
        status=status,
        result_json=body,
        occurred_at=datetime.now(UTC),
    )


def audit_row(
    execution: N8nRuntimeExecution, action: str, correlation: str | None = None
):
    return AuditEvent(
        action=action,
        subject=str(execution.execution_id),
        correlation_id=correlation or execution.correlation_id,
        decision="accepted",
        redacted_payload={},
    )


def test_evidence_reports_reconciled_and_continuous_lifecycle():
    execution = execution_row(status="COMPLETED")
    results = [result_row(execution, "RUNNING"), result_row(execution, "COMPLETED")]
    audits = [
        audit_row(execution, "n8n.runtime.created"),
        audit_row(execution, "n8n.runtime.result"),
    ]
    evidence = api.certification_evidence(execution, results, audits, 2, [])
    assert evidence["checks"] == {
        "correlation_continuous": True,
        "result_binding_intact": True,
        "result_hashes_unique": True,
        "reconciliation": "reconciled",
        "synthetic_odoo_binding": False,
        "odoo_result_deliveries": 0,
    }
    assert [r["status"] for r in evidence["results"]] == ["RUNNING", "COMPLETED"]
    assert evidence["process"]["process_instance_id"] == api.PROCESS_INSTANCE_ID
    assert "payload_json" not in json.dumps(
        evidence
    ) and "result_json" not in json.dumps(evidence)


@pytest.mark.parametrize(
    ("status", "results", "expected"),
    [
        ("PENDING", [], "awaiting_result"),
        ("TIMED_OUT", [], "terminal_without_result"),
        ("FAILED", ["COMPLETED"], "divergent"),
    ],
)
def test_evidence_reconciliation_states(status, results, expected):
    execution = execution_row(status=status)
    rows = [result_row(execution, value) for value in results]
    assert (
        api.certification_evidence(execution, rows, [], 0, [])["checks"][
            "reconciliation"
        ]
        == expected
    )


def test_evidence_detects_correlation_break_and_foreign_binding():
    execution = execution_row(status="COMPLETED")
    broken = api.certification_evidence(
        execution,
        [result_row(execution, "COMPLETED", tenant_id="OTHER")],
        [audit_row(execution, "n8n.runtime.result", "OTHER_CORRELATION")],
        1,
        [],
    )
    assert broken["checks"]["correlation_continuous"] is False
    assert broken["checks"]["result_binding_intact"] is False


class ScalarRows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


@pytest.mark.asyncio
async def test_evidence_endpoint_is_tenant_scoped_and_reads_durable_rows():
    execution = execution_row(status="COMPLETED")
    result = result_row(execution, "COMPLETED")
    session = AsyncMock()
    session.get.return_value = execution
    session.scalars.side_effect = [
        ScalarRows([result]),
        ScalarRows([audit_row(execution, "n8n.runtime.created")]),
        ScalarRows([]),
    ]
    session.scalar.return_value = 1
    evidence = await api.execution_evidence(execution.execution_id, TENANT, session)
    assert evidence["execution"]["execution_id"] == str(execution.execution_id)
    assert evidence["accepted_callback_nonces"] == 1
    assert evidence["checks"]["reconciliation"] == "reconciled"
    with pytest.raises(api.HTTPException) as denied:
        session.get.return_value = execution
        await api.execution_evidence(execution.execution_id, "OTHER_TENANT", session)
    assert denied.value.status_code == 404


def test_process_route_is_bearer_guarded_and_reports_posture(monkeypatch):
    from app.entrypoints.runtime import add_api_runtime

    monkeypatch.setattr(
        settings, "middleware_secret", "fixture-bearer-secret-0123456789"
    )
    monkeypatch.setattr(
        settings, "n8n_runtime_base_url", "http://n8n-webhook-staging:8080"
    )
    monkeypatch.setattr(settings, "n8n_runtime_environment", "staging")
    app = FastAPI()
    app.include_router(api.router)
    add_api_runtime(app, "test-service")
    client = TestClient(app)
    assert client.get("/api/v1/n8n-runtime/process").status_code == 401
    response = client.get(
        "/api/v1/n8n-runtime/process",
        headers={"Authorization": "Bearer fixture-bearer-secret-0123456789"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["process_instance_id"] == api.PROCESS_INSTANCE_ID
    assert body["dispatch_target"]["legacy_8080"] is True
    assert body["dispatch_target"]["allowed"] is False
    assert "n8n-webhook-staging" not in response.text


# -- certifier against a simulated staging runtime -----------------------------------------


@pytest.fixture
def safety(test_settings) -> dict:
    staging = test_settings.replace(
        app_env="staging",
        runtime_profile_id="codestra-middleware-staging-v1",
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        build_time="2026-09-25T12:00:00Z",
        allow_in_memory_storage=False,
    )
    return runtime_safety_readback(staging)


class Runtime:
    """Canonical n8n runtime semantics behind one MockTransport, using the real
    contracts, signature verification and evidence builder."""

    def __init__(self, safety: dict):
        self.safety = safety
        self.executions: dict[UUID, N8nRuntimeExecution] = {}
        self.results: list[N8nRuntimeResult] = []
        self.audits: list[AuditEvent] = []
        self.nonces: dict[tuple[str, str], UUID] = {}
        self.target = "http://n8n-webhook-staging:5678"
        self.instance = str(uuid4())
        self.started_at = datetime.now(UTC)
        self.accept_bad_signatures = False
        self.dedupe_dispatch = True
        self.calls: list[str] = []

    def restart(self) -> None:
        self.instance = str(uuid4())
        self.started_at = datetime.now(UTC) + timedelta(seconds=1)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(f"{request.method} {path}")
        assert request.url.port != 8080
        auth = request.headers.get("Authorization")
        if path == "/v1/runtime/safety":
            assert auth == "Bearer " + MONITORING
            return httpx.Response(200, json=self.safety)
        if path == "/api/v1/n8n-runtime/results":
            return self.result(request)
        if auth != "Bearer " + BEARER:
            return httpx.Response(401, json={"detail": "unauthorized"})
        if path == "/api/v1/n8n-runtime/process":
            return httpx.Response(
                200,
                json={
                    "process_instance_id": self.instance,
                    "started_at": self.started_at.isoformat(),
                    "environment": "staging",
                    "runtime_enabled": True,
                    "dispatch_target": dispatch_target_posture(self.target, "staging"),
                },
            )
        if path == "/api/v1/n8n-runtime/dispatch":
            return self.dispatch(DispatchRequest.model_validate_json(request.content))
        if path.endswith("/evidence"):
            execution = self.executions.get(UUID(path.split("/")[-2]))
            if (
                execution is None
                or execution.tenant_id != request.url.params["tenant_id"]
            ):
                return httpx.Response(404)
            evidence = api.certification_evidence(
                execution,
                [r for r in self.results if r.execution_id == execution.execution_id],
                [a for a in self.audits if a.subject == str(execution.execution_id)],
                sum(1 for e in self.nonces.values() if e == execution.execution_id),
                [],
            )
            evidence["process"] = {"process_instance_id": self.instance}
            return httpx.Response(200, json=evidence)
        return httpx.Response(404)

    def dispatch(self, body: DispatchRequest) -> httpx.Response:
        payload_hash = sha256(canonical_bytes(body.payload))
        key = hashlib.sha256(body.idempotency_key.encode()).hexdigest()
        for existing in self.executions.values():
            if self.dedupe_dispatch and existing.idempotency_key_hash == key:
                if existing.payload_hash != payload_hash:
                    return httpx.Response(409)
                return httpx.Response(200, json=api._safe_execution(existing, True))
        execution = execution_row(
            execution_id=uuid4(),
            event_id=body.event_id,
            event_type=body.event_type,
            source_event_id=body.source_event_id,
            correlation_id=body.correlation_id,
            causation_id=body.causation_id,
            trace_id=body.trace_id,
            idempotency_key_hash=key,
            payload_hash=payload_hash,
            payload_json=body.payload,
        )
        self.executions[execution.execution_id] = execution
        self.audits.append(audit_row(execution, "n8n.runtime.created"))
        return httpx.Response(202, json=api._safe_execution(execution))

    def result(self, request: httpx.Request) -> httpx.Response:
        h = request.headers
        raw = request.content
        body_hash = sha256(raw)
        try:
            verify_fresh(h["X-Codestra-Timestamp"], 300)
            if body_hash != h["X-Codestra-Body-SHA256"].removeprefix("sha256:"):
                raise ValueError("hash")
            if not self.accept_bad_signatures:
                verify_runtime(
                    h["X-Codestra-Signature"],
                    HMAC.encode(),
                    identity=h["X-Codestra-Identity"],
                    tenant_id=h["X-Codestra-Tenant"],
                    workflow_code=h["X-Codestra-Workflow"],
                    execution_id=h["X-Codestra-Execution"],
                    correlation_id=h["X-Codestra-Correlation-ID"],
                    timestamp=h["X-Codestra-Timestamp"],
                    nonce=h["X-Codestra-Nonce"],
                    body_hash=body_hash,
                )
            body = ResultContract.model_validate_json(raw)
        except ValueError:
            return httpx.Response(401)
        execution = self.executions.get(UUID(h["X-Codestra-Execution"]))
        if (
            execution is None
            or execution.tenant_id != h["X-Codestra-Tenant"]
            or execution.correlation_id != h["X-Codestra-Correlation-ID"]
            or body.tenant_id != execution.tenant_id
            or body.correlation_id != execution.correlation_id
            or body.execution_id != str(execution.execution_id)
        ):
            return httpx.Response(409)
        nonce_key = (h["X-Codestra-Identity"], h["X-Codestra-Nonce"])
        if nonce_key in self.nonces:
            return httpx.Response(409)
        self.nonces[nonce_key] = execution.execution_id
        result_hash = sha256(canonical_bytes(body))
        if any(r.result_hash == result_hash for r in self.results):
            return httpx.Response(200, json={"accepted": True, "duplicate": True})
        status = body.status.upper()
        execution.status = status
        self.results.append(
            N8nRuntimeResult(
                result_id=uuid4(),
                execution_id=execution.execution_id,
                tenant_id=execution.tenant_id,
                workflow_code=execution.workflow_code,
                result_hash=result_hash,
                status=status,
                result_json=body.model_dump(mode="json"),
                occurred_at=body.occurred_at,
            )
        )
        self.audits.append(audit_row(execution, "n8n.runtime.result"))
        return httpx.Response(
            202, json={"accepted": True, "duplicate": False, "status": status}
        )


def environment(tmp_path, **overrides) -> dict[str, str]:
    files = {}
    for name, value in (("bearer", BEARER), ("monitoring", MONITORING), ("hmac", HMAC)):
        path = tmp_path / f"{name}.secret"
        path.write_text(value, encoding="utf-8")
        files[name] = str(path)
    env = {
        "TEST_SYN_MIDDLEWARE_BASE_URL": "http://middleware-n8n-runtime-canary:8095",
        "TEST_SYN_TENANT_ID": TENANT,
        "TEST_SYN_EVENT_TYPE": "test.synthetic.failure_path",
        "EXPECTED_SOURCE_SHA": SOURCE_SHA,
        "EXPECTED_IMAGE_DIGEST": IMAGE_DIGEST,
        "TEST_SYN_MIDDLEWARE_BEARER_FILE": files["bearer"],
        "TEST_SYN_MONITORING_TOKEN_FILE": files["monitoring"],
        "TEST_SYN_N8N_RUNTIME_HMAC_SECRET_FILE": files["hmac"],
    }
    env.update(overrides)
    return env


def run(tmp_path, runtime: Runtime, phase: str = "certify", **env) -> tuple[int, dict]:
    output = tmp_path / "evidence"
    code = cert.main(
        ["--output", str(output), "--phase", phase],
        env=environment(tmp_path, **env),
        transport=httpx.MockTransport(runtime.handler),
    )
    name = cert.EVIDENCE_FILE if phase == "certify" else cert.RESTART_EVIDENCE_FILE
    path = output / name
    return code, json.loads(path.read_text()) if path.exists() else {}


def steps(report: dict) -> dict[str, str]:
    return {s["step"]: s["status"] for s in report["steps"]}


def test_certify_then_restart_continuity_is_go(tmp_path, safety, capsys):
    runtime = Runtime(safety)
    code, report = run(tmp_path, runtime)
    assert code == 0, report
    assert report["verdict"] == {"GO": "YES", "steps_passed": 7, "steps_total": 7}
    rejected = next(s for s in report["steps"] if s["step"] == "result-auth-negative")
    assert rejected["details"]["rejected"] == {
        "bad_signature": 401,
        "body_hash_mismatch": 401,
        "stale_timestamp": 401,
        "contract_violation": 401,
        "unknown_execution": 409,
        "tenant_mismatch": 409,
        "correlation_mismatch": 409,
    }
    (execution,) = runtime.executions.values()
    assert execution.status == "COMPLETED"
    assert [r.status for r in runtime.results] == ["RUNNING", "COMPLETED"]
    assert (tmp_path / "evidence" / cert.STATE_FILE).exists()
    serialized = "".join(p.read_text() for p in (tmp_path / "evidence").iterdir())
    assert (
        BEARER not in serialized
        and MONITORING not in serialized
        and HMAC not in serialized
    )

    runtime.restart()
    code, restart = run(tmp_path, runtime, "after-restart")
    assert code == 0, restart
    assert steps(restart) == {
        "restart-observed": "pass",
        "durable-evidence": "pass",
        "idempotency-after-restart": "pass",
        "no-provider-effect": "pass",
    }
    assert len(runtime.executions) == 1 and len(runtime.results) == 2
    assert "TEST_SYN_FAILURE_PATH_GO=YES phase=after-restart" in capsys.readouterr().out


def test_after_restart_without_a_restart_fails_closed(tmp_path, safety):
    runtime = Runtime(safety)
    assert run(tmp_path, runtime)[0] == 0
    code, report = run(tmp_path, runtime, "after-restart")
    assert code == 2
    assert steps(report)["restart-observed"] == "fail"
    assert steps(report)["idempotency-after-restart"] == "skipped"


def test_after_restart_requires_a_passing_certify_state(tmp_path, safety):
    assert run(tmp_path, Runtime(safety), "after-restart")[0] == 3


def test_legacy_8080_dispatch_target_sends_no_synthetic_traffic(tmp_path, safety):
    runtime = Runtime(safety)
    runtime.target = "http://n8n-webhook-staging:8080"
    code, report = run(tmp_path, runtime)
    assert code == 2
    assert "8080" in report["steps"][0]["error"]
    assert not any("/dispatch" in call or "/results" in call for call in runtime.calls)
    assert not (tmp_path / "evidence" / cert.STATE_FILE).exists()


def test_legacy_8080_middleware_base_url_is_refused(tmp_path, safety):
    code, _ = run(
        tmp_path,
        Runtime(safety),
        TEST_SYN_MIDDLEWARE_BASE_URL="http://middleware-integration-api:8080",
    )
    assert code == 3


def test_non_test_syn_tenant_is_refused(tmp_path, safety):
    assert run(tmp_path, Runtime(safety), TEST_SYN_TENANT_ID="MBL")[0] == 3


def test_runtime_accepting_forged_results_is_no_go(tmp_path, safety):
    runtime = Runtime(safety)
    runtime.accept_bad_signatures = True
    code, report = run(tmp_path, runtime)
    assert code == 2
    assert steps(report)["result-auth-negative"] == "fail"


def test_runtime_without_dispatch_idempotency_is_no_go(tmp_path, safety):
    runtime = Runtime(safety)
    runtime.dedupe_dispatch = False
    code, report = run(tmp_path, runtime)
    assert code == 2
    assert steps(report)["command-dispatch"] == "fail"
    assert steps(report)["result-auth-positive"] == "skipped"
