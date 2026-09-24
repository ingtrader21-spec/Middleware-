#!/usr/bin/env python3
"""Outbound-only Qwen worker; it never opens a listening socket."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import http.client
import json
import multiprocessing
import os
import secrets
import signal
import socket
import ssl
import time
import threading
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MIDDLEWARE_IP = "10.40.0.1"
MIDDLEWARE_NAME = "middleware.internal.codestra.agency"
SERVICE_ID = "qwen-polling-worker"
KEY_ID = "qwen-polling-worker-hmac-v1"
BASE = Path("/run/codestra-qwen-worker")
WORKER_ID = "qwen-ai-01-worker"
HARD_SAFETY_CAP = 2
ALLOWED_TYPES = frozenset(
    {"ai.chat.v1", "ai.coding.v1", "ai.crm.v1", "ai.voice.v1", "ai.embeddings.v1"}
)
MODEL_REGISTRY = {
    "fast-chat": ("litellm", "qwen-runtime-fast"),
    "quality-chat": ("litellm", "qwen-coder-review"),
    "coding-default": ("litellm", "qwen-coder-fallback"),
    "coding-large": ("litellm", "qwen-coder-primary"),
    "crm-analysis": ("litellm", "qwen-runtime-fast"),
    "voice-summary": ("litellm", "qwen-voice-fast"),
    "embedding-default": None,
}


class WorkerError(RuntimeError):
    pass


@dataclass(slots=True)
class WorkerMetrics:
    """Thread-safe, bounded-cardinality worker concurrency metrics."""

    configured_concurrency: int
    effective_concurrency: int = 1
    active_jobs: int = 0
    claims_total: int = 0
    over_capacity_claim_attempts: int = 0
    heartbeat_failures_total: int = 0
    cancellations_total: int = 0
    admission_rejections_total: int = 0
    profile_mismatch_total: int = 0
    compatibility_rejections_total: int = 0
    completed_jobs: int = 0
    total_job_latency_seconds: float = 0.0
    _active_profile_classes: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def update_limit(self, effective: int) -> None:
        with self._lock:
            self.effective_concurrency = effective

    def claimed(self, profile_class: str = "unknown") -> None:
        with self._lock:
            self.claims_total += 1
            self.active_jobs += 1
            self._active_profile_classes[profile_class] = (
                self._active_profile_classes.get(profile_class, 0) + 1
            )

    def finished(self, elapsed: float, profile_class: str = "unknown") -> None:
        with self._lock:
            self.active_jobs -= 1
            self.completed_jobs += 1
            self.total_job_latency_seconds += elapsed
            remaining = self._active_profile_classes.get(profile_class, 0) - 1
            if remaining > 0:
                self._active_profile_classes[profile_class] = remaining
            else:
                self._active_profile_classes.pop(profile_class, None)

    def heartbeat_failed(self) -> None:
        with self._lock:
            self.heartbeat_failures_total += 1

    def cancelled(self) -> None:
        with self._lock:
            self.cancellations_total += 1

    def admission_rejected(self, *, mismatch: bool = False) -> None:
        with self._lock:
            self.admission_rejections_total += 1
            if mismatch:
                self.profile_mismatch_total += 1

    def compatibility_rejected(self) -> None:
        with self._lock:
            self.compatibility_rejections_total += 1

    def snapshot(self) -> dict[str, int | float | str]:
        with self._lock:
            active_classes = sorted(self._active_profile_classes)
            return {
                "codestra_ai_worker_active_jobs": self.active_jobs,
                "codestra_ai_worker_available_slots": max(
                    self.effective_concurrency - self.active_jobs, 0
                ),
                "codestra_ai_worker_configured_concurrency": self.configured_concurrency,
                "codestra_ai_worker_effective_concurrency": self.effective_concurrency,
                "codestra_ai_worker_claims_total": self.claims_total,
                "codestra_ai_worker_over_capacity_claim_attempts": (
                    self.over_capacity_claim_attempts
                ),
                "codestra_ai_worker_job_latency_seconds": (
                    self.total_job_latency_seconds
                ),
                "codestra_ai_worker_heartbeat_failures_total": (
                    self.heartbeat_failures_total
                ),
                "codestra_ai_worker_cancellations_total": self.cancellations_total,
                "codestra_ai_worker_admission_rejections_total": (
                    self.admission_rejections_total
                ),
                "codestra_ai_worker_profile_mismatch_total": (
                    self.profile_mismatch_total
                ),
                "codestra_ai_worker_active_profile_class": (
                    active_classes[0]
                    if len(active_classes) == 1
                    else "none"
                    if not active_classes
                    else "mixed"
                ),
                "codestra_ai_worker_compatibility_rejections_total": (
                    self.compatibility_rejections_total
                ),
            }


def protected(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise WorkerError("required credential file is unavailable")
    if path.stat().st_mode & 0o077:
        raise WorkerError("credential permissions are unsafe")
    return path


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def signed_headers(
    method: str,
    path: str,
    body: bytes,
    secret_file: Path,
    tenant_id: str = "00000000-0000-4000-8000-000000000001",
    workspace_id: str = "00000000-0000-4000-8000-000000000002",
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    digest = hashlib.sha256(body).hexdigest()
    request_id = f"qwen-request-{uuid.uuid4()}"
    correlation_id = f"qwen-worker-{uuid.uuid4()}"
    canonical = "\n".join(
        (
            method.upper(),
            path,
            timestamp,
            nonce,
            digest,
            request_id,
            correlation_id,
            WORKER_ID,
            tenant_id,
            workspace_id,
        )
    ).encode("ascii")
    secret = protected(secret_file).read_bytes().strip()
    if len(secret) != 64:
        raise WorkerError("HMAC enrollment is invalid")
    return {
        "Content-Type": "application/json",
        "X-Service-ID": SERVICE_ID,
        "X-HMAC-Key-ID": KEY_ID,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Body-SHA256": digest,
        "X-Signature": hmac.new(secret, canonical, hashlib.sha256).hexdigest(),
        "X-Correlation-ID": correlation_id,
        "X-Request-ID": request_id,
        "X-Worker-ID": WORKER_ID,
        "X-Signature-Version": "v2",
        "X-Tenant-ID": tenant_id,
        "X-Workspace-ID": workspace_id,
    }


def litellm_policy_status(
    supplied_key: str | None,
    expected_key: str,
    model: str,
    allowed_models: frozenset[str],
) -> int:
    """Fail-closed policy contract used by the loopback gateway configuration."""
    if not supplied_key or not hmac.compare_digest(supplied_key, expected_key):
        return 401
    if model not in allowed_models:
        return 403
    return 200


class PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(MIDDLEWARE_NAME, 443, context=context, timeout=10)
        self._context = context

    def connect(self) -> None:
        raw = socket.create_connection((MIDDLEWARE_IP, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=MIDDLEWARE_NAME)


@dataclass(slots=True)
class Middleware:
    context: ssl.SSLContext
    secret_file: Path
    tenant_id: str
    workspace_id: str

    @classmethod
    def create(cls) -> Middleware:
        context = ssl.create_default_context(
            cafile=str(protected(BASE / "private-ca.crt"))
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            str(protected(BASE / "client.crt")), str(protected(BASE / "client.key"))
        )
        tenant_id = protected(BASE / "tenant-id").read_text().strip()
        workspace_id = protected(BASE / "workspace-id").read_text().strip()
        try:
            uuid.UUID(tenant_id)
            uuid.UUID(workspace_id)
        except ValueError as exc:
            raise WorkerError("worker tenant binding is invalid") from exc
        return cls(context, protected(BASE / "hmac.key"), tenant_id, workspace_id)

    def request(
        self, method: str, path: str, value: object
    ) -> tuple[int, dict[str, Any]]:
        body = encode(value)
        connection = PinnedConnection(self.context)
        try:
            connection.request(
                method,
                path,
                body,
                signed_headers(
                    method,
                    path,
                    body,
                    self.secret_file,
                    self.tenant_id,
                    self.workspace_id,
                ),
            )
            response = connection.getresponse()
            payload = response.read(1_048_577)
            if len(payload) > 1_048_576:
                raise WorkerError("middleware response exceeds bound")
            document = json.loads(payload) if payload else {}
            if not isinstance(document, dict):
                raise WorkerError("middleware response schema is invalid")
            return response.status, document
        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
            json.JSONDecodeError,
        ) as exc:
            raise WorkerError("bounded middleware request failed") from exc
        finally:
            connection.close()


def loopback_json(
    url: str,
    payload: dict[str, Any],
    timeout: int,
    bearer_file: Path | None = None,
) -> dict[str, Any]:
    if not (url.startswith("http://127.0.0.1:") or url.startswith("http://[::1]:")):
        raise WorkerError("non-loopback model endpoint rejected")
    headers = {"Content-Type": "application/json"}
    if bearer_file is not None:
        bearer = protected(bearer_file).read_text().strip()
        if not bearer or "\n" in bearer or "\r" in bearer:
            raise WorkerError("model credential is invalid")
        headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(url, data=encode(payload), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read(1_048_577)
    except OSError as exc:
        raise WorkerError("loopback model unavailable") from exc
    if len(raw) > 1_048_576:
        raise WorkerError("model result exceeds bound")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise WorkerError("model result schema is invalid")
    return result


def execute(job: dict[str, Any]) -> dict[str, Any]:
    command_type = job.get("command_type")
    payload = job.get("command_payload")
    profile = job.get("model_profile")
    if (
        command_type not in ALLOWED_TYPES
        or not isinstance(payload, dict)
        or profile not in MODEL_REGISTRY
    ):
        raise WorkerError("unsupported job contract")
    capability = MODEL_REGISTRY[profile]
    if capability is None:
        raise WorkerError("capability unavailable")
    provider, model = capability
    limits = job.get("resource_limits") or {}
    timeout = min(int(limits.get("runtime_seconds", 300)), 600)
    started = time.time()
    if provider == "ollama-embeddings":
        source = payload.get("input", {}).get("texts") or [
            payload.get("input", {}).get("text", "")
        ]
        raw = loopback_json(
            "http://127.0.0.1:11434/api/embed",
            {"model": model, "input": source},
            timeout,
        )
        output = {
            "embeddings": raw.get("embeddings", []),
            "dimension": len((raw.get("embeddings") or [[]])[0]),
        }
    elif provider == "ollama":
        prompt = json.dumps(payload.get("input", {}), sort_keys=True)
        raw = loopback_json(
            "http://127.0.0.1:11434/api/generate",
            {"model": model, "prompt": prompt, "stream": False},
            timeout,
        )
        output = {"proposal": raw.get("response", "")}
    else:
        prompt = json.dumps(payload.get("input", {}), sort_keys=True)
        raw = loopback_json(
            "http://127.0.0.1:4000/v1/chat/completions",
            {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": payload.get("model_policy", {}).get("max_tokens", 1024),
            },
            timeout,
            BASE / "litellm.key",
        )
        choices = raw.get("choices") or []
        output = {
            "proposal": choices[0].get("message", {}).get("content", "")
            if choices
            else ""
        }
    completed = time.time()
    return {
        "command_id": job["id"],
        "job_id": job["id"],
        "status": "SUCCEEDED",
        "result_schema_version": "1.0",
        "model_used": model,
        "provider_used": provider.split("-")[0],
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(completed)),
        "latency_ms": int((completed - started) * 1000),
        "token_usage": {},
        "resource_usage": {},
        "output": output,
        "structured_artifacts": [],
        "warnings": [],
        "policy_decisions": ["outbound-only", "proposal-only"],
        "error": None,
        "retryability": "none",
        "audit_reference": f"audit-{job['id']}",
    }


def _execute_child(job: dict[str, Any], sender: Any) -> None:
    """Run inference out of process so lease loss can stop the active request."""
    try:
        sender.send((True, execute(job)))
    except Exception:  # The parent deliberately receives no provider detail.
        sender.send((False, None))
    finally:
        sender.close()


def maintain_lease(
    api: Middleware,
    job_id: str,
    mutation: dict[str, object],
    stop_heartbeat: threading.Event,
    cancellation_requested: threading.Event,
    lease_lost: threading.Event,
    interval_seconds: float = 20,
    metrics: WorkerMetrics | None = None,
) -> None:
    """Renew the lease and fail closed on any unverified heartbeat state."""
    while not stop_heartbeat.wait(interval_seconds):
        try:
            status, _ = api.request(
                "POST", f"/internal/api/v1/ai/worker/jobs/{job_id}/heartbeat", mutation
            )
        except WorkerError:
            if metrics is not None:
                metrics.heartbeat_failed()
            lease_lost.set()
            return
        if status != 200:
            if metrics is not None:
                metrics.heartbeat_failed()
            lease_lost.set()
            return
        try:
            status, document = api.request(
                "POST",
                f"/internal/api/v1/ai/worker/jobs/{job_id}/cancellation-check",
                mutation,
            )
        except WorkerError:
            if metrics is not None:
                metrics.heartbeat_failed()
            lease_lost.set()
            return
        if status != 200:
            if metrics is not None:
                metrics.heartbeat_failed()
            lease_lost.set()
            return
        if document.get("cancel_requested") is True:
            if metrics is not None:
                metrics.cancelled()
            cancellation_requested.set()
            return


def claim_one(
    api: Middleware, allowed_model_profiles: frozenset[str] | None = None
) -> dict[str, Any] | None:
    body: dict[str, object] = {"worker_id": WORKER_ID}
    if allowed_model_profiles is not None:
        body["allowed_model_profiles"] = sorted(allowed_model_profiles)
    status, response = api.request(
        "POST", "/internal/api/v1/ai/worker/jobs/claim", body
    )
    if status == 503:
        raise WorkerError("claims disabled")
    if status != 200:
        raise WorkerError("claim rejected")
    job = response.get("job")
    if job is None:
        return None
    if not isinstance(job, dict):
        raise WorkerError("claim schema invalid")
    return job


def run_claimed_job(
    api: Middleware,
    job: dict[str, Any],
    *,
    shutdown_requested: threading.Event | None = None,
    metrics: WorkerMetrics | None = None,
) -> str:
    job_id, token = str(job["id"]), int(job["fencing_token"])
    mutation = {"worker_id": WORKER_ID, "fencing_token": token}
    stop_heartbeat = threading.Event()
    cancellation_requested = threading.Event()
    lease_lost = threading.Event()

    heartbeat = threading.Thread(
        target=maintain_lease,
        args=(
            api,
            job_id,
            mutation,
            stop_heartbeat,
            cancellation_requested,
            lease_lost,
            20,
            metrics,
        ),
        daemon=True,
    )
    # The deployment target is Linux; fork lets the child inherit the already
    # validated, read-only job and avoids re-running module startup code.
    # Slot threads must never fork a multithreaded parent. Spawn gives each
    # inference an isolated interpreter and deterministic cancellation boundary.
    # The direct one-shot compatibility path retains fork on the main thread.
    context: Any
    if threading.current_thread() is threading.main_thread():
        context = multiprocessing.get_context("fork")
    else:
        context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    inference = context.Process(target=_execute_child, args=(job, sender), daemon=True)
    inference.start()
    sender.close()
    heartbeat.start()
    try:
        while inference.is_alive() and not (
            cancellation_requested.is_set()
            or lease_lost.is_set()
            or (shutdown_requested is not None and shutdown_requested.is_set())
        ):
            inference.join(timeout=0.1)
        if (
            cancellation_requested.is_set()
            or lease_lost.is_set()
            or (shutdown_requested is not None and shutdown_requested.is_set())
        ):
            if inference.is_alive():
                inference.terminate()
            inference.join(timeout=2)
        if lease_lost.is_set():
            return "lease-lost"
        if shutdown_requested is not None and shutdown_requested.is_set():
            status, _ = api.request(
                "POST", f"/internal/api/v1/ai/worker/jobs/{job_id}/release", mutation
            )
            return "shutdown" if status == 200 else "lease-lost"
        if cancellation_requested.is_set():
            status, document = api.request(
                "POST", f"/internal/api/v1/ai/worker/jobs/{job_id}/cancel", mutation
            )
            if status != 200 or document.get("state") != "cancelled":
                return "lease-lost"
            return "cancelled"
        if inference.exitcode != 0 or not receiver.poll():
            raise WorkerError("model execution failed")
        succeeded, result = receiver.recv()
        if not succeeded or not isinstance(result, dict):
            raise WorkerError("model execution failed")
        status, _ = api.request(
            "POST",
            f"/internal/api/v1/ai/worker/jobs/{job_id}/complete",
            {**mutation, "result": result},
        )
        if status == 409:
            return "lease-lost"
        if status != 200:
            raise WorkerError("completion rejected")
        return "completed"
    except WorkerError:
        api.request(
            "POST",
            f"/internal/api/v1/ai/worker/jobs/{job_id}/fail",
            {
                **mutation,
                "error_code": "model_unavailable",
                "retryable": True,
                "safe_error_details": {"component": "loopback-model"},
            },
        )
        return "failed-retryable"
    finally:
        stop_heartbeat.set()
        heartbeat.join(timeout=2)
        if inference.is_alive():
            inference.terminate()
            inference.join(timeout=2)
        receiver.close()


def run_once(api: Middleware) -> str:
    """Backward-compatible concurrency-one claim and execution operation."""
    try:
        job = claim_one(api)
    except WorkerError as exc:
        if str(exc) == "claims disabled":
            return "claims-disabled"
        raise
    if job is None:
        return "empty"
    return run_claimed_job(api, job)


def configured_concurrency() -> int:
    raw = os.environ.get("QWEN_MAX_IN_PROCESS_JOBS", "1")
    try:
        value = int(raw)
    except ValueError as exc:
        raise WorkerError("configured concurrency is invalid") from exc
    if value < 1:
        raise WorkerError("configured concurrency is invalid")
    return min(value, HARD_SAFETY_CAP)


def worker_configuration(
    api: Middleware,
) -> tuple[int, dict[str, str], dict[str, frozenset[str]]]:
    status, document = api.request("GET", "/internal/api/v1/ai/worker/config", {})
    if status != 200:
        raise WorkerError("worker configuration unavailable")
    value = document.get("registration_max_concurrency")
    if not isinstance(value, int) or value < 1:
        raise WorkerError("registration concurrency unavailable")
    raw_classes = document.get("model_runtime_classes")
    raw_compatibility = document.get("runtime_class_compatibility")
    if not isinstance(raw_classes, dict) or not isinstance(raw_compatibility, dict):
        raise WorkerError("runtime compatibility policy unavailable")
    classes: dict[str, str] = {}
    compatibility: dict[str, frozenset[str]] = {}
    if not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in raw_classes.items()
    ):
        raise WorkerError("runtime compatibility policy invalid")
    classes.update(raw_classes)
    for runtime_class, compatible_classes in raw_compatibility.items():
        if not isinstance(runtime_class, str) or not isinstance(
            compatible_classes, list
        ):
            raise WorkerError("runtime compatibility policy invalid")
        if not all(isinstance(item, str) for item in compatible_classes):
            raise WorkerError("runtime compatibility policy invalid")
        compatibility[runtime_class] = frozenset(compatible_classes)
    if not classes or not compatibility:
        raise WorkerError("runtime compatibility policy invalid")
    return value, classes, compatibility


def registration_concurrency(api: Middleware) -> int:
    return worker_configuration(api)[0]


class BoundedWorkerRuntime:
    """Claims only into free slots and isolates every job lifecycle."""

    def __init__(self, api: Middleware, local_limit: int) -> None:
        self.api = api
        self.local_limit = min(local_limit, HARD_SAFETY_CAP)
        self.metrics = WorkerMetrics(self.local_limit)
        self.shutdown_requested = threading.Event()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=HARD_SAFETY_CAP,
            thread_name_prefix="qwen-job",
        )
        self._active: set[concurrent.futures.Future[str]] = set()
        self._active_profiles: dict[concurrent.futures.Future[str], str] = {}
        self._profile_runtime_classes: dict[str, str] = {}
        self._runtime_class_compatibility: dict[str, frozenset[str]] = {}

    def effective_limit(self) -> int:
        registration_limit, classes, compatibility = worker_configuration(self.api)
        self._profile_runtime_classes = classes
        self._runtime_class_compatibility = compatibility
        effective = min(self.local_limit, registration_limit, HARD_SAFETY_CAP)
        self.metrics.update_limit(effective)
        return effective

    def reap(self) -> list[str]:
        completed: list[str] = []
        for future in tuple(self._active):
            if future.done():
                self._active.remove(future)
                self._active_profiles.pop(future, None)
                completed.append(future.result())
        return completed

    def poll(self) -> str:
        self.reap()
        if self.shutdown_requested.is_set():
            return "stopping"
        if len(self._active) >= self.effective_limit():
            return "capacity"
        allowed_profiles: frozenset[str] | None = None
        if self._active_profiles:
            active_profiles = set(self._active_profiles.values())
            if len(active_profiles) != 1:
                return "capacity"
            active_profile = active_profiles.pop()
            active_class = self._profile_runtime_classes.get(active_profile)
            compatible_classes = self._runtime_class_compatibility.get(
                active_class or "", frozenset()
            )
            allowed_profiles = frozenset(
                profile
                for profile, runtime_class in self._profile_runtime_classes.items()
                if runtime_class in compatible_classes
            )
            if not allowed_profiles:
                self.metrics.compatibility_rejected()
                return "capacity"
        job = claim_one(self.api, allowed_profiles)
        if job is None:
            return "empty"
        claimed_profile = job.get("model_profile")
        if allowed_profiles is not None and claimed_profile not in allowed_profiles:
            mutation = {
                "worker_id": WORKER_ID,
                "fencing_token": int(job["fencing_token"]),
            }
            status, _ = self.api.request(
                "POST",
                f"/internal/api/v1/ai/worker/jobs/{job['id']}/release",
                mutation,
            )
            self.metrics.admission_rejected(mismatch=True)
            print(
                json.dumps(
                    {
                        "event": "worker_profile_admission_mismatch",
                        "lease_release_status": "released"
                        if status == 200
                        else "failed",
                    },
                    sort_keys=True,
                )
            )
            return "profile-mismatch" if status == 200 else "lease-lost"
        if self.shutdown_requested.is_set():
            mutation = {
                "worker_id": WORKER_ID,
                "fencing_token": int(job["fencing_token"]),
            }
            status, _ = self.api.request(
                "POST",
                f"/internal/api/v1/ai/worker/jobs/{job['id']}/release",
                mutation,
            )
            return "stopping" if status == 200 else "lease-lost"
        started = time.monotonic()
        profile = str(claimed_profile or "")
        profile_class = self._profile_runtime_classes.get(profile, "unknown")
        self.metrics.claimed(profile_class)

        def execute_slot() -> str:
            try:
                return run_claimed_job(
                    self.api,
                    job,
                    shutdown_requested=self.shutdown_requested,
                    metrics=self.metrics,
                )
            finally:
                self.metrics.finished(time.monotonic() - started, profile_class)

        future = self._executor.submit(execute_slot)
        self._active.add(future)
        self._active_profiles[future] = profile
        return "claimed"

    def shutdown(self, timeout_seconds: float = 40) -> None:
        self.shutdown_requested.set()
        deadline = time.monotonic() + timeout_seconds
        while self._active and time.monotonic() < deadline:
            self.reap()
            if self._active:
                time.sleep(0.05)
        self._executor.shutdown(wait=False, cancel_futures=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.validate_only:
        Middleware.create()
        protected(BASE / "litellm.key")
        print("WORKER_CONFIGURATION=PASS")
        return 0
    api = Middleware.create()
    if args.once:
        print(f"WORKER_OUTCOME={run_once(api)}")
        return 0
    runtime = BoundedWorkerRuntime(api, configured_concurrency())

    def stop(*_: object) -> None:
        runtime.shutdown_requested.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    delay = 2.0
    next_metrics = time.monotonic() + 30
    while not runtime.shutdown_requested.is_set():
        try:
            outcome = runtime.poll()
            delay = 2.0
            if outcome in {"empty", "capacity"}:
                time.sleep(2)
        except WorkerError as exc:
            if str(exc) == "claims disabled":
                time.sleep(2)
            else:
                time.sleep(delay)
            delay = min(delay * 2, 60)
        if time.monotonic() >= next_metrics:
            print(json.dumps(runtime.metrics.snapshot(), sort_keys=True))
            next_metrics = time.monotonic() + 30
    runtime.shutdown()
    print(json.dumps(runtime.metrics.snapshot(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
