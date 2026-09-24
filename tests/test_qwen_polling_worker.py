from __future__ import annotations

import hashlib
import hmac
import importlib.util
import sys
import threading
import time
from contextlib import AbstractContextManager
from pathlib import Path

import pytest

from app.core import ai_jobs

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "worker/qwen_polling_worker.py"
SPEC = importlib.util.spec_from_file_location("qwen_polling_worker_test", PATH)
assert SPEC and SPEC.loader
worker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = worker
SPEC.loader.exec_module(worker)


def test_signer_uses_authoritative_canonical_contract(tmp_path, monkeypatch):
    secret = tmp_path / "hmac"
    secret.write_bytes(b"a" * 64)
    secret.chmod(0o600)
    monkeypatch.setattr(worker.time, "time", lambda: 1_786_000_000)
    monkeypatch.setattr(
        worker.secrets, "token_urlsafe", lambda _: "fixture-nonce-1234567890"
    )
    body = b'{"fixture":true}'
    headers = worker.signed_headers(
        "post", "/internal/api/v1/ai/worker/jobs/claim", body, secret
    )
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        (
            "POST",
            "/internal/api/v1/ai/worker/jobs/claim",
            "1786000000",
            "fixture-nonce-1234567890",
            digest,
            headers["X-Request-ID"],
            headers["X-Correlation-ID"],
            "qwen-ai-01-worker",
            headers["X-Tenant-ID"],
            headers["X-Workspace-ID"],
        )
    ).encode("ascii")
    assert (
        headers["X-Signature"]
        == hmac.new(b"a" * 64, canonical, hashlib.sha256).hexdigest()
    )
    assert headers["X-HMAC-Key-ID"] == "qwen-polling-worker-hmac-v1"
    assert headers["X-Service-ID"] == "qwen-polling-worker"
    assert headers["X-Signature-Version"] == "v2"


def test_litellm_worker_policy_matrix():
    allowed = frozenset({"qwen-coder-primary", "qwen-coder-fast"})
    assert (
        worker.litellm_policy_status(
            "dedicated", "dedicated", "qwen-coder-primary", allowed
        )
        == 200
    )
    assert (
        worker.litellm_policy_status(
            "wrong", "dedicated", "qwen-coder-primary", allowed
        )
        == 401
    )
    assert (
        worker.litellm_policy_status(None, "dedicated", "qwen-coder-primary", allowed)
        == 401
    )
    assert (
        worker.litellm_policy_status("dedicated", "dedicated", "other-model", allowed)
        == 403
    )


def test_non_loopback_model_destination_fails_closed():
    with pytest.raises(worker.WorkerError, match="non-loopback"):
        worker.loopback_json("http://10.40.0.4:11434/api/generate", {}, 1)


class FakeResponse(AbstractContextManager):
    def read(self, _limit):
        return b'{"choices":[]}'

    def __exit__(self, *_args):
        return None


def test_litellm_request_uses_dedicated_projected_bearer(tmp_path, monkeypatch):
    credential = tmp_path / "litellm.key"
    credential.write_text("fixture-value")
    credential.chmod(0o600)
    captured = {}

    def fake_open(request, timeout):
        captured["authorization"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(worker.urllib.request, "urlopen", fake_open)
    assert worker.loopback_json(
        "http://127.0.0.1:4000/v1/chat/completions", {}, 7, credential
    ) == {"choices": []}
    assert captured == {"authorization": "Bearer fixture-value", "timeout": 7}


def test_protected_build_selects_middleware_runtime_stage():
    workflow = (ROOT / ".github/workflows/staging-candidate-build-sign.yml").read_text()
    build = workflow.split("- name: Build and publish staging-only candidate", 1)[1]
    build = build.split("- name: Resolve immutable candidate identity", 1)[0]
    assert "docker build" in build
    assert "--target runtime" in build


class FakeAPI:
    def __init__(self, job=None, completion_status=200):
        self.job = job
        self.completion_status = completion_status
        self.calls = []

    def request(self, method, path, value):
        self.calls.append((method, path, value))
        if path.endswith("/claim"):
            return 200, {"job": self.job}
        if path.endswith("/complete"):
            return self.completion_status, {"state": "completed"}
        return 200, {"state": "retry_wait"}


def fixture_job(command_type="ai.chat.v1", profile="fast-chat"):
    return {
        "id": "00000000-0000-4000-8000-000000000001",
        "command_type": command_type,
        "command_payload": {
            "input": {"text": "synthetic"},
            "model_policy": {"max_tokens": 10},
        },
        "model_profile": profile,
        "resource_limits": {"runtime_seconds": 10},
        "fencing_token": 1,
    }


@pytest.mark.parametrize(
    ("task_type", "expected_model", "project_key"),
    [
        ("chat", "qwen-runtime-fast", None),
        ("coding", "qwen-coder-fallback", "codestra-ai-console"),
    ],
)
def test_worker_accepts_server_generated_browser_contract(
    task_type, expected_model, project_key, monkeypatch
):
    from uuid import uuid4

    job_id = uuid4()
    contract = ai_jobs.build_browser_worker_contract(
        job_id=job_id,
        conversation_id=uuid4(),
        organization_id=uuid4(),
        user_id="synthetic-user",
        content="safe browser request",
        task_type=task_type,
        project_key=project_key,
        idempotency_key=f"worker-browser-{task_type}",
        correlation_id=f"corr-worker-browser-{task_type}",
        max_attempts=2,
    )
    observed = {}

    def fake_loopback(url, payload, timeout, bearer_file=None):
        observed.update({"url": url, "payload": payload, "timeout": timeout})
        return {"choices": [{"message": {"content": "synthetic result"}}]}

    monkeypatch.setattr(worker, "loopback_json", fake_loopback)
    result = worker.execute(
        {
            "id": str(job_id),
            "command_type": contract.command_type.value,
            "command_payload": contract.model_dump(mode="json"),
            "model_profile": contract.model_policy.profile,
            "resource_limits": contract.resource_limits.model_dump(mode="json"),
            "fencing_token": 1,
        }
    )
    assert result["status"] == "SUCCEEDED"
    assert result["model_used"] == expected_model
    assert observed["payload"]["model"] == expected_model


def test_worker_empty_completion_duplicate_and_failure_paths(monkeypatch):
    empty = FakeAPI()
    assert worker.run_once(empty) == "empty"
    successful = FakeAPI(fixture_job())
    monkeypatch.setattr(
        worker,
        "execute",
        lambda job: {
            "command_id": job["id"],
            "job_id": job["id"],
            "status": "SUCCEEDED",
            "result_schema_version": "1.0",
            "model_used": "fixture",
            "provider_used": "mock",
            "started_at": "2026-08-06T00:00:00Z",
            "completed_at": "2026-08-06T00:00:01Z",
            "latency_ms": 1,
            "token_usage": {},
            "resource_usage": {},
            "output": {"fixture": True},
            "structured_artifacts": [],
            "warnings": [],
            "policy_decisions": [],
            "error": None,
            "retryability": "none",
            "audit_reference": "audit-fixture",
        },
    )
    assert worker.run_once(successful) == "completed"
    duplicate = FakeAPI(fixture_job(), completion_status=409)
    assert worker.run_once(duplicate) == "lease-lost"
    failed = FakeAPI(fixture_job("ai.embeddings.v1", "embedding-default"))
    monkeypatch.setattr(
        worker,
        "execute",
        lambda _job: (_ for _ in ()).throw(worker.WorkerError("model")),
    )
    assert worker.run_once(failed) == "failed-retryable"
    assert failed.calls[-1][1].endswith("/fail")


def test_all_worker_command_families_are_allowlisted():
    assert worker.ALLOWED_TYPES == {
        "ai.chat.v1",
        "ai.coding.v1",
        "ai.crm.v1",
        "ai.voice.v1",
        "ai.embeddings.v1",
    }
    assert worker.MODEL_REGISTRY["embedding-default"] is None


class ConcurrentAPI:
    def __init__(self, jobs, registration_limit=2):
        self.jobs = list(jobs)
        self.registration_limit = registration_limit
        self.claim_count = 0
        self.claim_bodies = []
        self.release_count = 0
        self._lock = threading.Lock()

    def request(self, method, path, value):
        del method
        if path.endswith("/config"):
            return 200, {
                "registration_max_concurrency": self.registration_limit,
                "model_runtime_classes": {
                    "fast-chat": "chat-light",
                    "crm-analysis": "chat-light",
                    "coding-default": "coding-fallback",
                    "quality-chat": "single-admission",
                    "coding-large": "single-admission",
                    "voice-summary": "single-admission",
                    "embedding-default": "unavailable",
                },
                "runtime_class_compatibility": {
                    "chat-light": ["chat-light"],
                    "coding-fallback": ["coding-fallback"],
                    "single-admission": [],
                    "unavailable": [],
                },
            }
        if path.endswith("/claim"):
            with self._lock:
                self.claim_count += 1
                self.claim_bodies.append(value)
                allowed = value.get("allowed_model_profiles")
                job = next(
                    (
                        candidate
                        for candidate in self.jobs
                        if allowed is None or candidate.get("model_profile") in allowed
                    ),
                    None,
                )
                if job is not None:
                    self.jobs.remove(job)
            return 200, {"job": job}
        if path.endswith("/release"):
            self.release_count += 1
            return 200, {"state": "retry_wait"}
        raise AssertionError(path)


def distinct_job(job_id):
    job = fixture_job()
    job["id"] = job_id
    return job


@pytest.mark.parametrize(
    ("local_limit", "registration_limit", "expected"),
    [(1, 2, 1), (2, 1, 1), (2, 2, 2), (2, 99, 2)],
)
def test_effective_concurrency_is_bounded_by_local_registration_and_hard_cap(
    local_limit, registration_limit, expected
):
    runtime = worker.BoundedWorkerRuntime(
        ConcurrentAPI([], registration_limit), local_limit
    )
    try:
        assert runtime.effective_limit() == expected
    finally:
        runtime.shutdown()


def test_invalid_local_concurrency_fails_closed(monkeypatch):
    monkeypatch.setenv("QWEN_MAX_IN_PROCESS_JOBS", "0")
    with pytest.raises(worker.WorkerError, match="configured concurrency"):
        worker.configured_concurrency()
    monkeypatch.setenv("QWEN_MAX_IN_PROCESS_JOBS", "99")
    assert worker.configured_concurrency() == 2


def test_two_slots_run_in_parallel_without_claiming_a_third(monkeypatch):
    first = distinct_job("00000000-0000-4000-8000-000000000001")
    second = distinct_job("00000000-0000-4000-8000-000000000002")
    third = distinct_job("00000000-0000-4000-8000-000000000003")
    api = ConcurrentAPI([first, second, third])
    started = set()
    release = threading.Event()
    lock = threading.Lock()

    def run_slot(_api, job, **_kwargs):
        with lock:
            started.add(job["id"])
        assert release.wait(2)
        return "completed"

    monkeypatch.setattr(worker, "run_claimed_job", run_slot)
    runtime = worker.BoundedWorkerRuntime(api, 2)
    try:
        assert runtime.poll() == "claimed"
        assert runtime.poll() == "claimed"
        deadline = time.monotonic() + 2
        while len(started) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(started) == 2
        assert runtime.poll() == "capacity"
        assert api.claim_count == 2
        assert api.claim_bodies == [
            {"worker_id": worker.WORKER_ID},
            {
                "worker_id": worker.WORKER_ID,
                "allowed_model_profiles": ["crm-analysis", "fast-chat"],
            },
        ]
        assert runtime.metrics.snapshot()["codestra_ai_worker_active_jobs"] == 2
        release.set()
    finally:
        release.set()
        runtime.shutdown()


def test_registration_one_preserves_serial_behavior(monkeypatch):
    api = ConcurrentAPI(
        [
            distinct_job("00000000-0000-4000-8000-000000000001"),
            distinct_job("00000000-0000-4000-8000-000000000002"),
        ],
        registration_limit=1,
    )
    release = threading.Event()
    monkeypatch.setattr(
        worker,
        "run_claimed_job",
        lambda *_args, **_kwargs: "completed" if release.wait(2) else "timeout",
    )
    runtime = worker.BoundedWorkerRuntime(api, 2)
    try:
        assert runtime.poll() == "claimed"
        assert runtime.poll() == "capacity"
        assert api.claim_count == 1
    finally:
        release.set()
        runtime.shutdown()


def test_mixed_runtime_models_are_not_claimed_into_second_slot(monkeypatch):
    first = distinct_job("00000000-0000-4000-8000-000000000001")
    first["model_profile"] = "coding-default"
    second = distinct_job("00000000-0000-4000-8000-000000000002")
    second["model_profile"] = "fast-chat"
    api = ConcurrentAPI([first, second])
    release = threading.Event()
    monkeypatch.setattr(
        worker,
        "run_claimed_job",
        lambda *_args, **_kwargs: "completed" if release.wait(2) else "timeout",
    )
    runtime = worker.BoundedWorkerRuntime(api, 2)
    try:
        assert runtime.poll() == "claimed"
        assert runtime.poll() == "empty"
        assert api.claim_bodies[-1]["allowed_model_profiles"] == ["coding-default"]
    finally:
        release.set()
        runtime.shutdown()


def test_worker_releases_mismatched_claim_response(monkeypatch, capsys):
    coding = distinct_job("00000000-0000-4000-8000-000000000001")
    coding["model_profile"] = "coding-default"
    incompatible = distinct_job("00000000-0000-4000-8000-000000000002")
    incompatible["model_profile"] = "fast-chat"

    class BuggyController(ConcurrentAPI):
        def request(self, method, path, value):
            if path.endswith("/claim") and value.get("allowed_model_profiles"):
                self.claim_count += 1
                self.claim_bodies.append(value)
                return 200, {"job": incompatible}
            return super().request(method, path, value)

    api = BuggyController([coding])
    release = threading.Event()
    inference_started: set[str] = set()

    def run_slot(_api, job, **_kwargs):
        inference_started.add(job["id"])
        release.wait(2)
        return "completed"

    monkeypatch.setattr(worker, "run_claimed_job", run_slot)
    runtime = worker.BoundedWorkerRuntime(api, 2)
    try:
        assert runtime.poll() == "claimed"
        assert runtime.poll() == "profile-mismatch"
        assert incompatible["id"] not in inference_started
        assert api.release_count == 1
        snapshot = runtime.metrics.snapshot()
        assert snapshot["codestra_ai_worker_profile_mismatch_total"] == 1
        assert '"event": "worker_profile_admission_mismatch"' in capsys.readouterr().out
    finally:
        release.set()
        runtime.shutdown()


@pytest.mark.parametrize("profile", ["quality-chat", "coding-large", "voice-summary"])
def test_unproven_runtime_profile_remains_single_admission(monkeypatch, profile):
    first = distinct_job("00000000-0000-4000-8000-000000000001")
    first["model_profile"] = profile
    api = ConcurrentAPI([first, distinct_job("00000000-0000-4000-8000-000000000002")])
    release = threading.Event()
    monkeypatch.setattr(
        worker,
        "run_claimed_job",
        lambda *_args, **_kwargs: "completed" if release.wait(2) else "timeout",
    )
    runtime = worker.BoundedWorkerRuntime(api, 2)
    try:
        assert runtime.poll() == "claimed"
        assert runtime.poll() == "capacity"
        assert api.claim_count == 1
    finally:
        release.set()
        runtime.shutdown()


def test_job_state_and_shutdown_are_isolated(monkeypatch):
    jobs = [
        distinct_job("00000000-0000-4000-8000-00000000000a"),
        distinct_job("00000000-0000-4000-8000-00000000000b"),
    ]
    api = ConcurrentAPI(jobs)
    observed = {}
    both_started = threading.Barrier(2)

    def run_slot(_api, job, *, shutdown_requested, metrics):
        del metrics
        both_started.wait(timeout=2)
        observed[job["id"]] = shutdown_requested.wait(2)
        return "shutdown"

    monkeypatch.setattr(worker, "run_claimed_job", run_slot)
    runtime = worker.BoundedWorkerRuntime(api, 2)
    assert runtime.poll() == "claimed"
    assert runtime.poll() == "claimed"
    runtime.shutdown(timeout_seconds=2)
    assert set(observed) == {job["id"] for job in jobs}
    assert all(observed.values())
    assert api.claim_count == 2


def test_parallel_heartbeat_failure_and_cancellation_are_isolated():
    class LeaseAPI:
        def request(self, _method, path, _value):
            if "00000000000a" in path:
                raise worker.WorkerError("job A transport failed")
            if path.endswith("/heartbeat"):
                return 200, {"accepted": True}
            return 200, {"cancel_requested": True}

    api = LeaseAPI()
    states = []
    for suffix in ("a", "b"):
        cancellation = threading.Event()
        lease_lost = threading.Event()
        worker.maintain_lease(
            api,
            f"00000000-0000-4000-8000-00000000000{suffix}",
            {"worker_id": worker.WORKER_ID, "fencing_token": 1},
            threading.Event(),
            cancellation,
            lease_lost,
            interval_seconds=0,
        )
        states.append((cancellation.is_set(), lease_lost.is_set()))
    assert states == [(False, True), (True, False)]


def test_metric_snapshot_has_bounded_names_and_no_job_labels():
    metrics = worker.WorkerMetrics(configured_concurrency=2)
    metrics.update_limit(2)
    metrics.claimed()
    metrics.cancelled()
    metrics.heartbeat_failed()
    metrics.finished(1.25)
    snapshot = metrics.snapshot()
    assert snapshot["codestra_ai_worker_active_jobs"] == 0
    assert snapshot["codestra_ai_worker_available_slots"] == 2
    assert snapshot["codestra_ai_worker_cancellations_total"] == 1
    assert snapshot["codestra_ai_worker_heartbeat_failures_total"] == 1
    assert all("00000000" not in name for name in snapshot)
