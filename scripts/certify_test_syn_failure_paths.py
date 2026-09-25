#!/usr/bin/env python3
"""TEST_SYN failure-path certification of the governed n8n command/result plane.

    python -m scripts.certify_test_syn_failure_paths --output /abs/0700/dir
    # operator restarts the Middleware runtime container, then:
    python -m scripts.certify_test_syn_failure_paths --output /abs/0700/dir --phase after-restart

Phase ``certify`` (default) drives one synthetic TEST_SYN command through the
canonical runtime (never the retired 8080 listener) and proves, fail closed:

 1. runtime-safety-readback     staging profile, exact SHA/digest, every effect control off;
                                runtime process identity readable, dispatch target not 8080
 2. auth-negative               guarded dispatch/evidence reject missing and wrong bearers (401)
 3. command-dispatch            202 created, retry -> 200 duplicate (same execution), payload
                                conflict on the same idempotency key -> 409
 4. result-auth-negative        bad signature, body-hash mismatch, stale timestamp, contract
                                violation -> 401; unknown execution, tenant or correlation
                                mismatch -> 409; none of them changes durable state
 5. result-auth-positive        signed running + completed -> 202, same-nonce replay -> 409,
                                same result under a fresh nonce -> 200 duplicate
 6. reconciliation-evidence     /executions/{id}/evidence: COMPLETED and reconciled, correlation
                                continuous across execution, results and audit, no Odoo delivery
 7. no-provider-effect          runtime safety and dispatch posture unchanged after the run

Phase ``after-restart`` reloads the state written by ``certify`` and proves the
runtime process was replaced while the durable evidence is unchanged and the
idempotency and replay guards still hold (restart continuity).

Every credential is a *_FILE path to a 0600 file; nothing secret is written.
Exit 0 = GO, exit 2 = a step failed (evidence written), exit 3 = unsafe to run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

import httpx

from app.core.n8n_runtime import LEGACY_RUNTIME_PORT, sign_runtime
from app.monitoring.collector import IDENTIFIER, SECRET_SHAPED, scrub
from scripts.certify_test_syn import (
    CertificationError,
    base_url,
    read_secret_file,
    required,
)
from scripts.staging_synthetic_acceptance import (
    AcceptanceError,
    validate_runtime_safety,
)

RUNTIME = "/api/v1/n8n-runtime"
EVIDENCE_FILE = "test-syn-failure-path-certification.json"
RESTART_EVIDENCE_FILE = "test-syn-failure-path-restart.json"
STATE_FILE = "test-syn-failure-path-state.json"
STALE_SECONDS = 3600


def canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def reject_legacy_port(name: str, url: str) -> str:
    if httpx.URL(url).port == LEGACY_RUNTIME_PORT:
        raise CertificationError(f"{name} targets the retired 8080 listener")
    return url


class Plan:
    def __init__(self, env: Mapping[str, str]):
        self.middleware = reject_legacy_port(
            "TEST_SYN_MIDDLEWARE_BASE_URL",
            base_url(env, "TEST_SYN_MIDDLEWARE_BASE_URL"),
        )
        self.tenant_id = required(env, "TEST_SYN_TENANT_ID")
        self.event_type = required(env, "TEST_SYN_EVENT_TYPE")
        self.identity = env.get("TEST_SYN_RUNTIME_IDENTITY", "n8n-staging")
        self.expected_sha = required(env, "EXPECTED_SOURCE_SHA").lower()
        self.expected_digest = required(env, "EXPECTED_IMAGE_DIGEST").lower()
        for value in (self.tenant_id, self.event_type, self.identity):
            if not IDENTIFIER.fullmatch(value):
                raise CertificationError(
                    "tenant, event type and identity must be bounded"
                )
        if not self.tenant_id.startswith("TEST_SYN"):
            raise CertificationError(
                "failure-path certification is TEST_SYN tenant only"
            )
        self.monitoring_token = read_secret_file(
            required(env, "TEST_SYN_MONITORING_TOKEN_FILE")
        )
        self.middleware_bearer = read_secret_file(
            required(env, "TEST_SYN_MIDDLEWARE_BEARER_FILE")
        )
        self.hmac_secret = read_secret_file(
            required(env, "TEST_SYN_N8N_RUNTIME_HMAC_SECRET_FILE")
        ).encode("utf-8")
        if len(self.hmac_secret) < 32:
            raise CertificationError(
                "n8n runtime HMAC secret must be at least 32 bytes"
            )
        self.secrets = [
            self.monitoring_token,
            self.middleware_bearer,
            self.hmac_secret.decode("utf-8"),
        ]

    def public(self) -> dict[str, Any]:
        return {
            "middleware": self.middleware,
            "tenant_id": self.tenant_id,
            "event_type": self.event_type,
            "identity": self.identity,
            "expected_source_sha": self.expected_sha,
            "expected_image_digest": self.expected_digest,
            "credentials": "loaded from *_FILE paths; never recorded",
        }


class Runner:
    def __init__(
        self, plan: Plan, client: httpx.Client, state: dict[str, Any] | None = None
    ):
        self.plan = plan
        self.client = client
        self.steps: list[dict[str, Any]] = []
        self.state: dict[str, Any] = state or {}
        self.safety_before: dict[str, Any] = {}
        self.process: dict[str, Any] = {}

    # -- helpers -----------------------------------------------------------------------------

    def bearer(self, token: str | None = None) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + (token or self.plan.middleware_bearer),
            "Accept": "application/json",
        }

    def expect(self, response: httpx.Response, status: int, label: str) -> Any:
        if response.status_code != status:
            raise AcceptanceError(
                f"{label} returned {response.status_code}, expected {status}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise AcceptanceError(f"{label} did not return JSON") from exc

    def step(self, name: str, action: Callable[[], dict[str, Any]]) -> bool:
        started = datetime.now(timezone.utc).isoformat()
        try:
            details = action()
        except (AcceptanceError, httpx.HTTPError, CertificationError) as exc:
            self.steps.append(
                {
                    "step": name,
                    "status": "fail",
                    "started_at": started,
                    "error": scrub(str(exc))[:400],
                }
            )
            return False
        self.steps.append(
            {"step": name, "status": "pass", "started_at": started, "details": details}
        )
        return True

    def skip(self, names: tuple[str, ...], reason: str) -> None:
        for name in names:
            self.steps.append({"step": name, "status": "skipped", "reason": reason})

    def read_process(self) -> dict[str, Any]:
        process = self.expect(
            self.client.get(
                self.plan.middleware + RUNTIME + "/process", headers=self.bearer()
            ),
            200,
            "runtime process readback",
        )
        target = process.get("dispatch_target") or {}
        if process.get("environment") != "staging":
            raise AcceptanceError("runtime process is not staging")
        if process.get("runtime_enabled") is not True:
            raise AcceptanceError("governed n8n runtime is not enabled")
        if (
            target.get("legacy_8080") is not False
            or target.get("port") == LEGACY_RUNTIME_PORT
        ):
            raise AcceptanceError(
                "n8n dispatch target resolves to the retired 8080 listener"
            )
        if target.get("allowed") is not True:
            raise AcceptanceError(
                f"n8n dispatch target is not allowed: {target.get('reason')}"
            )
        return process

    def read_safety(self) -> dict[str, Any]:
        payload = self.expect(
            self.client.get(
                self.plan.middleware + "/v1/runtime/safety",
                headers=self.bearer(self.plan.monitoring_token),
            ),
            200,
            "runtime safety readback",
        )
        return validate_runtime_safety(
            payload,
            expected_source_sha=self.plan.expected_sha,
            expected_image_digest=self.plan.expected_digest,
        )

    def dispatch_body(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            **self.state["dispatch"],
            "payload": payload or self.state["dispatch"]["payload"],
        }

    def dispatch(
        self, body: dict[str, Any], headers: dict[str, str] | None = None
    ) -> httpx.Response:
        return self.client.post(
            self.plan.middleware + RUNTIME + "/dispatch",
            content=canonical(body),
            headers={
                **(self.bearer() if headers is None else headers),
                "Content-Type": "application/json",
                "X-Correlation-ID": self.state["correlation_id"],
            },
        )

    def evidence(self, headers: dict[str, str] | None = None) -> httpx.Response:
        return self.client.get(
            self.plan.middleware
            + RUNTIME
            + f"/executions/{self.state['execution_id']}/evidence",
            params={"tenant_id": self.plan.tenant_id},
            headers=self.bearer() if headers is None else headers,
        )

    def result_document(self, status: str, **overrides: Any) -> dict[str, Any]:
        document = {
            "schema_version": "codestra.n8n.result.v1",
            "workflow_code": self.state["workflow_code"],
            "workflow_version": self.state["workflow_version"],
            "execution_id": self.state["execution_id"],
            "correlation_id": self.state["correlation_id"],
            "tenant_id": self.plan.tenant_id,
            "status": status,
            "occurred_at": utc_now(),
            "result": {"synthetic": True, "certification": "TEST_SYN_FAILURE_PATH"},
        }
        document.update(overrides)
        return document

    def post_result(
        self,
        document: dict[str, Any],
        *,
        nonce: str | None = None,
        timestamp: int | None = None,
        tenant: str | None = None,
        execution: str | None = None,
        correlation: str | None = None,
        secret: bytes | None = None,
        declared_hash: str | None = None,
    ) -> tuple[httpx.Response, str]:
        raw = canonical(document)
        body_hash = hashlib.sha256(raw).hexdigest()
        nonce = nonce or f"testsyn-fp-{uuid4().hex}"
        values = {
            "identity": self.plan.identity,
            "tenant_id": tenant or self.plan.tenant_id,
            "workflow_code": self.state["workflow_code"],
            "execution_id": execution or self.state["execution_id"],
            "correlation_id": correlation or self.state["correlation_id"],
            "timestamp": str(timestamp if timestamp is not None else int(time.time())),
            "nonce": nonce,
            "body_hash": body_hash,
        }
        signature = sign_runtime(secret=secret or self.plan.hmac_secret, **values)
        headers = {
            "Content-Type": "application/json",
            "X-Codestra-Identity": values["identity"],
            "X-Codestra-Tenant": values["tenant_id"],
            "X-Codestra-Workflow": values["workflow_code"],
            "X-Codestra-Execution": values["execution_id"],
            "X-Codestra-Correlation-ID": values["correlation_id"],
            "X-Codestra-Timestamp": values["timestamp"],
            "X-Codestra-Nonce": nonce,
            "X-Codestra-Body-SHA256": "sha256:" + (declared_hash or body_hash),
            "X-Codestra-Signature": "sha256=" + signature,
        }
        response = self.client.post(
            self.plan.middleware + RUNTIME + "/results", content=raw, headers=headers
        )
        return response, nonce

    # -- certify phase -----------------------------------------------------------------------

    def runtime_safety(self) -> dict[str, Any]:
        self.safety_before = self.read_safety()
        self.process = self.read_process()
        return {
            "environment": self.safety_before["environment"],
            "runtime_profile_id": self.safety_before["runtime_profile_id"],
            "source_sha": self.safety_before["release"]["source_sha"],
            "process_instance_id": self.process["process_instance_id"],
            "dispatch_target_port": self.process["dispatch_target"].get("port"),
            "legacy_8080": False,
        }

    def auth_negative(self) -> dict[str, Any]:
        observed = {}
        for label, headers in (
            ("dispatch_without_bearer", {"Accept": "application/json"}),
            (
                "dispatch_wrong_bearer",
                self.bearer("testsyn-wrong-bearer-" + secrets.token_hex(12)),
            ),
        ):
            response = self.dispatch(self.dispatch_body(), headers)
            if response.status_code != 401:
                raise AcceptanceError(
                    f"{label} returned {response.status_code}, expected 401"
                )
            observed[label] = 401
        response = self.client.get(
            self.plan.middleware + RUNTIME + "/process",
            headers={"Accept": "application/json"},
        )
        if response.status_code != 401:
            raise AcceptanceError(
                f"process readback without bearer returned {response.status_code}, expected 401"
            )
        observed["process_without_bearer"] = 401
        return observed

    def command_dispatch(self) -> dict[str, Any]:
        created = self.expect(self.dispatch(self.dispatch_body()), 202, "dispatch")
        if created.get("duplicate") is not False or created.get("status") != "PENDING":
            raise AcceptanceError("dispatch did not create a fresh PENDING execution")
        if created.get("correlation_id") != self.state["correlation_id"]:
            raise AcceptanceError("dispatch did not preserve the correlation_id")
        self.state.update(
            execution_id=created["execution_id"],
            workflow_code=created["workflow_code"],
            workflow_version=created["workflow_version"],
        )
        duplicate = self.expect(
            self.dispatch(self.dispatch_body()), 200, "dispatch retry"
        )
        if (
            duplicate.get("duplicate") is not True
            or duplicate.get("execution_id") != created["execution_id"]
        ):
            raise AcceptanceError(
                "dispatch retry was not reconciled onto the same execution"
            )
        conflict = self.dispatch(
            self.dispatch_body(
                {**self.state["dispatch"]["payload"], "variant": "conflict"}
            )
        )
        if conflict.status_code != 409:
            raise AcceptanceError(
                f"payload conflict on the same idempotency key returned {conflict.status_code}, expected 409"
            )
        return {
            "execution_id": created["execution_id"],
            "workflow_code": created["workflow_code"],
            "workflow_version": created["workflow_version"],
            "created_status": 202,
            "duplicate_status": 200,
            "conflict_status": 409,
        }

    def result_auth_negative(self) -> dict[str, Any]:
        stale = int(time.time()) - STALE_SECONDS
        other = f"TEST_SYN_OTHER_{secrets.token_hex(4)}"
        wrong_secret = secrets.token_bytes(48)
        cases: list[tuple[str, int, Callable[[], httpx.Response]]] = [
            (
                "bad_signature",
                401,
                lambda: self.post_result(
                    self.result_document("failed"), secret=wrong_secret
                )[0],
            ),
            (
                "body_hash_mismatch",
                401,
                lambda: self.post_result(
                    self.result_document("failed"), declared_hash="0" * 64
                )[0],
            ),
            (
                "stale_timestamp",
                401,
                lambda: self.post_result(
                    self.result_document("failed"), timestamp=stale
                )[0],
            ),
            (
                "contract_violation",
                401,
                lambda: self.post_result(
                    self.result_document("failed", unexpected=True)
                )[0],
            ),
            ("unknown_execution", 409, self._unknown_execution),
            (
                "tenant_mismatch",
                409,
                lambda: self.post_result(
                    self.result_document("failed", tenant_id=other), tenant=other
                )[0],
            ),
            (
                "correlation_mismatch",
                409,
                lambda: self.post_result(
                    self.result_document("failed", correlation_id=other),
                    correlation=other,
                )[0],
            ),
        ]
        observed = {}
        for label, status, send in cases:
            response = send()
            if response.status_code != status:
                raise AcceptanceError(
                    f"{label} returned {response.status_code}, expected {status}"
                )
            observed[label] = status
        evidence = self.expect(self.evidence(), 200, "execution evidence")
        if evidence["execution"]["status"] == "FAILED" or any(
            r["status"] == "FAILED" for r in evidence["results"]
        ):
            raise AcceptanceError(
                "a rejected result callback changed durable execution state"
            )
        return {"rejected": observed, "state_unchanged": True}

    def _unknown_execution(self) -> httpx.Response:
        unknown = str(uuid4())
        return self.post_result(
            self.result_document("failed", execution_id=unknown), execution=unknown
        )[0]

    def result_auth_positive(self) -> dict[str, Any]:
        running, _ = self.post_result(self.result_document("running"))
        self.expect(running, 202, "running result")
        completed_document = self.result_document("completed")
        completed, nonce = self.post_result(completed_document)
        accepted = self.expect(completed, 202, "completed result")
        if (
            accepted.get("status") != "COMPLETED"
            or accepted.get("duplicate") is not False
        ):
            raise AcceptanceError(
                "completed result was not accepted as a new COMPLETED result"
            )
        replay, _ = self.post_result(completed_document, nonce=nonce)
        if replay.status_code != 409:
            raise AcceptanceError(
                f"same-nonce replay returned {replay.status_code}, expected 409"
            )
        duplicate, _ = self.post_result(completed_document)
        if (
            self.expect(duplicate, 200, "fresh-nonce duplicate result").get("duplicate")
            is not True
        ):
            raise AcceptanceError(
                "identical result under a fresh nonce was not deduplicated"
            )
        self.state.update(completed_document=completed_document, completed_nonce=nonce)
        return {
            "running_status": 202,
            "completed_status": 202,
            "replay_status": 409,
            "duplicate_status": 200,
        }

    def reconciliation_evidence(self) -> dict[str, Any]:
        evidence = self.expect(self.evidence(), 200, "execution evidence")
        verify_evidence(evidence, self.state, self.plan.tenant_id)
        if (
            evidence["process"]["process_instance_id"]
            != self.process["process_instance_id"]
        ):
            raise AcceptanceError(
                "runtime process changed during the certification run"
            )
        self.state["evidence"] = evidence_fingerprint(evidence)
        return {
            **self.state["evidence"],
            "audit_actions": sorted({a["action"] for a in evidence["audit"]}),
            "accepted_callback_nonces": evidence["accepted_callback_nonces"],
        }

    def no_provider_effect(self) -> dict[str, Any]:
        after = self.read_safety()
        for key in (
            "external_effects",
            "umbrella_controls",
            "dispatch",
            "production_dialing",
        ):
            if after.get(key) != self.safety_before.get(key):
                raise AcceptanceError(f"runtime safety changed during the run: {key}")
        process = self.read_process()
        return {
            "runtime_safety_unchanged": True,
            "legacy_8080": process["dispatch_target"]["legacy_8080"],
            "odoo_result_deliveries": self.state.get("evidence", {}).get(
                "odoo_result_deliveries"
            ),
        }

    def run_certify(self) -> list[dict[str, Any]]:
        suffix = secrets.token_hex(8)
        correlation = f"TEST_SYN_FP_CORR_{suffix}"
        self.state.update(
            correlation_id=correlation,
            dispatch={
                "schema_version": "codestra.n8n.dispatch.v1",
                "tenant_id": self.plan.tenant_id,
                "event_id": f"TEST_SYN_FP_EVENT_{suffix}",
                "event_type": self.plan.event_type,
                "source_event_id": f"TEST_SYN_FP_SOURCE_{suffix}",
                "correlation_id": correlation,
                "causation_id": f"TEST_SYN_FP_CAUSE_{suffix}",
                "trace_id": secrets.token_hex(16),
                "idempotency_key": f"test-syn-failure-path:{suffix}",
                "payload": {
                    "synthetic": True,
                    "certification": "TEST_SYN_FAILURE_PATH",
                },
            },
        )
        remaining = (
            "auth-negative",
            "command-dispatch",
            "result-auth-negative",
            "result-auth-positive",
            "reconciliation-evidence",
            "no-provider-effect",
        )
        if not self.step("runtime-safety-readback", self.runtime_safety):
            self.skip(
                remaining,
                "runtime safety read-back failed; no synthetic traffic is sent",
            )
            return self.steps
        self.step("auth-negative", self.auth_negative)
        if self.step("command-dispatch", self.command_dispatch):
            self.step("result-auth-negative", self.result_auth_negative)
            if self.step("result-auth-positive", self.result_auth_positive):
                self.step("reconciliation-evidence", self.reconciliation_evidence)
            else:
                self.skip(
                    ("reconciliation-evidence",), "no completed result was accepted"
                )
        else:
            self.skip(remaining[2:5], "no synthetic execution was created")
        self.step("no-provider-effect", self.no_provider_effect)
        return self.steps

    # -- after-restart phase -----------------------------------------------------------------

    def restart_observed(self) -> dict[str, Any]:
        self.safety_before = self.read_safety()
        self.process = self.read_process()
        before = self.state["process"]
        if self.process["process_instance_id"] == before["process_instance_id"]:
            raise AcceptanceError(
                "runtime process instance is unchanged; no restart happened"
            )
        if str(self.process["started_at"]) <= str(before["started_at"]):
            raise AcceptanceError("runtime process start time did not advance")
        return {
            "process_instance_before": before["process_instance_id"],
            "process_instance_after": self.process["process_instance_id"],
            "started_at_after": self.process["started_at"],
        }

    def durable_evidence(self) -> dict[str, Any]:
        evidence = self.expect(self.evidence(), 200, "execution evidence after restart")
        verify_evidence(evidence, self.state, self.plan.tenant_id)
        after = evidence_fingerprint(evidence)
        if after != self.state["evidence"]:
            raise AcceptanceError(
                "durable execution evidence changed across the restart"
            )
        return {**after, "unchanged_across_restart": True}

    def idempotency_after_restart(self) -> dict[str, Any]:
        duplicate = self.expect(
            self.dispatch(self.dispatch_body()), 200, "dispatch retry after restart"
        )
        if (
            duplicate.get("execution_id") != self.state["execution_id"]
            or duplicate.get("duplicate") is not True
        ):
            raise AcceptanceError("dispatch idempotency did not survive the restart")
        replay, _ = self.post_result(
            self.state["completed_document"], nonce=self.state["completed_nonce"]
        )
        if replay.status_code != 409:
            raise AcceptanceError(
                f"freshly signed replay of a pre-restart nonce returned {replay.status_code}, expected 409"
            )
        result, _ = self.post_result(self.state["completed_document"])
        if (
            self.expect(result, 200, "duplicate result after restart").get("duplicate")
            is not True
        ):
            raise AcceptanceError("result deduplication did not survive the restart")
        return {"dispatch_duplicate": 200, "nonce_replay": 409, "result_duplicate": 200}

    def run_after_restart(self) -> list[dict[str, Any]]:
        remaining = (
            "durable-evidence",
            "idempotency-after-restart",
            "no-provider-effect",
        )
        if not self.step("restart-observed", self.restart_observed):
            self.skip(remaining, "no verified restart of a safe staging runtime")
            return self.steps
        self.step("durable-evidence", self.durable_evidence)
        self.step("idempotency-after-restart", self.idempotency_after_restart)
        self.step("no-provider-effect", self.no_provider_effect)
        return self.steps


def verify_evidence(
    evidence: dict[str, Any], state: dict[str, Any], tenant_id: str
) -> None:
    execution = evidence.get("execution", {})
    checks = evidence.get("checks", {})
    if (
        execution.get("execution_id") != state["execution_id"]
        or execution.get("tenant_id") != tenant_id
    ):
        raise AcceptanceError("evidence is not bound to the certified execution")
    if execution.get("status") != "COMPLETED":
        raise AcceptanceError(
            f"execution status is {execution.get('status')}, expected COMPLETED"
        )
    if execution.get("trace_id") != state["dispatch"]["trace_id"]:
        raise AcceptanceError("execution trace_id does not match the dispatched trace")
    if checks.get("reconciliation") != "reconciled":
        raise AcceptanceError(
            f"execution reconciliation is {checks.get('reconciliation')}"
        )
    if checks.get("correlation_continuous") is not True or any(
        a.get("correlation_id") != state["correlation_id"]
        for a in evidence.get("audit", [])
    ):
        raise AcceptanceError(
            "correlation_id is not continuous across execution, results and audit"
        )
    if (
        checks.get("result_binding_intact") is not True
        or checks.get("result_hashes_unique") is not True
    ):
        raise AcceptanceError("result binding or result idempotency is broken")
    actions = {a.get("action") for a in evidence.get("audit", [])}
    if not {"n8n.runtime.created", "n8n.runtime.result"} <= actions:
        raise AcceptanceError("audit trail is missing dispatch or result records")
    if (
        checks.get("synthetic_odoo_binding") is not False
        or checks.get("odoo_result_deliveries") != 0
    ):
        raise AcceptanceError("failure-path run queued an Odoo result delivery")
    if any(r.get("status") == "FAILED" for r in evidence.get("results", [])):
        raise AcceptanceError("a rejected negative result was persisted")


def evidence_fingerprint(evidence: dict[str, Any]) -> dict[str, Any]:
    """The restart-stable part of the evidence (process identity excluded)."""
    return {
        "execution_id": evidence["execution"]["execution_id"],
        "status": evidence["execution"]["status"],
        "correlation_id": evidence["execution"]["correlation_id"],
        "payload_hash": evidence["execution"]["payload_hash"],
        "results": sorted(
            (r["result_id"], r["status"], r["result_hash"]) for r in evidence["results"]
        ),
        "reconciliation": evidence["checks"]["reconciliation"],
        "correlation_continuous": evidence["checks"]["correlation_continuous"],
        "odoo_result_deliveries": evidence["checks"]["odoo_result_deliveries"],
    }


def report(
    plan: Plan, phase: str, steps: list[dict[str, Any]], state: dict[str, Any]
) -> dict[str, Any]:
    passed = bool(steps) and all(step["status"] == "pass" for step in steps)
    return {
        "schema_version": 1,
        "certification": "TEST_SYN_FAILURE_PATH",
        "phase": phase,
        "environment": "staging",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "plan": plan.public(),
        "execution_id": state.get("execution_id"),
        "correlation_id": state.get("correlation_id"),
        "steps": steps,
        "verdict": {
            "GO": "YES" if passed else "NO",
            "steps_passed": sum(1 for s in steps if s["status"] == "pass"),
            "steps_total": len(steps),
        },
        "legacy_8080_fallback": False,
        "business_effect": "none (TEST_SYN tenant, effect controls attested off before and after)",
        "secrets_recorded": False,
    }


def write_json(document: dict[str, Any], plan: Plan, output: Path, name: str) -> Path:
    serialized = json.dumps(document, indent=2, sort_keys=True, default=list)
    for secret in plan.secrets:
        if secret and secret in serialized:
            raise CertificationError(
                "evidence would contain a live credential; refusing to write it"
            )
    if SECRET_SHAPED.search(serialized):
        raise CertificationError(
            "evidence would contain secret-shaped material; refusing to write it"
        )
    output.mkdir(parents=True, exist_ok=True)
    try:
        output.chmod(0o700)
    except OSError:
        pass
    path = output / name
    path.write_text(serialized + "\n", encoding="utf-8")
    return path


def load_state(output: Path) -> dict[str, Any]:
    path = output / STATE_FILE
    if not path.is_file() or path.is_symlink():
        raise CertificationError("no certify-phase state; run the certify phase first")
    state = json.loads(path.read_text(encoding="utf-8"))
    needed = {
        "execution_id",
        "correlation_id",
        "dispatch",
        "process",
        "evidence",
        "completed_document",
        "completed_nonce",
    }
    if not needed <= set(state):
        raise CertificationError(
            "certify-phase state is incomplete; the certify phase did not pass"
        )
    state["evidence"]["results"] = [tuple(r) for r in state["evidence"]["results"]]
    generated = datetime.fromisoformat(state["generated_at"])
    if datetime.now(timezone.utc) - generated > timedelta(hours=24):
        raise CertificationError(
            "certify-phase state is older than 24 h; certify again"
        )
    return state


def main(
    argv: list[str] | None = None,
    env: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--output",
        required=True,
        help="absolute 0700 directory for the redacted evidence",
    )
    parser.add_argument(
        "--phase", choices=("certify", "after-restart"), default="certify"
    )
    args = parser.parse_args(argv)
    output = Path(args.output)
    if not output.is_absolute():
        print(
            "TEST_SYN_FAILURE_PATH=FAIL reason=output-must-be-absolute", file=sys.stderr
        )
        return 3
    try:
        plan = Plan(os.environ if env is None else env)
        state = load_state(output) if args.phase == "after-restart" else None
    except (CertificationError, ValueError) as exc:
        print(f"TEST_SYN_FAILURE_PATH=FAIL reason={exc}", file=sys.stderr)
        return 3
    with httpx.Client(
        timeout=httpx.Timeout(15.0), follow_redirects=False, transport=transport
    ) as client:
        runner = Runner(plan, client, state)
        steps = (
            runner.run_certify()
            if args.phase == "certify"
            else runner.run_after_restart()
        )
    document = report(plan, args.phase, steps, runner.state)
    try:
        path = write_json(
            document,
            plan,
            output,
            EVIDENCE_FILE if args.phase == "certify" else RESTART_EVIDENCE_FILE,
        )
        if args.phase == "certify" and document["verdict"]["GO"] == "YES":
            write_json(
                {
                    **runner.state,
                    "process": {
                        "process_instance_id": runner.process["process_instance_id"],
                        "started_at": runner.process["started_at"],
                    },
                    "generated_at": document["generated_at"],
                },
                plan,
                output,
                STATE_FILE,
            )
    except CertificationError as exc:
        print(f"TEST_SYN_FAILURE_PATH=FAIL reason={exc}", file=sys.stderr)
        return 3
    verdict = document["verdict"]
    print(
        f"TEST_SYN_FAILURE_PATH_GO={verdict['GO']} phase={args.phase} "
        f"steps={verdict['steps_passed']}/{verdict['steps_total']} "
        f"execution_id={document['execution_id']} evidence={path.name}"
    )
    return 0 if verdict["GO"] == "YES" else 2


if __name__ == "__main__":
    sys.exit(main())
