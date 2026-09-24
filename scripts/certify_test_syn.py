#!/usr/bin/env python3
"""TEST_SYN end-to-end certification: one synthetic request, proven across every plane.

    python -m scripts.certify_test_syn --output /abs/0700/dir

Eight fail-closed steps, all read-only except the two synthetic writes the
staging TEST_SYN boundary exists for (one signed synthetic event through the
public edge, one informational synthetic alert into Alertmanager):

 1. runtime-safety-readback   staging profile, exact SHA/digest, every effect control off
 2. edge-synthetic-request    signed TEST_SYN event via Caddy -> Kong -> Middleware, 202 then 200 duplicate,
                              carrying traceparent + X-Correlation-ID
 3. trace-propagation         Tempo holds the trace with caddy, kong and middleware spans that share
                              correlation_id; odoo/n8n hops are reported as observed or planned, with
                              span links for asynchronous continuation
 4. log-correlation           Loki returns the Middleware log line for the correlation_id with the trace_id
 5. metrics-freshness         Prometheus shows the middleware target up, scraped within 90 s, request counted
 6. alert-ingestion           synthetic alert -> Alertmanager -> Middleware incident, once (idempotent)
 7. dashboard-readback        Grafana Middleware datasource healthy, dashboards present, Middleware
                              observability API answering the monitoring-readonly token
 8. no-business-effect        runtime safety unchanged after the run; provider effect counters unchanged

Configuration is read from the environment; every credential is a *_FILE path
to a 0600 file. Nothing secret is written: the JSON evidence carries ids,
hashes, counts and verdicts only, and is refused if it looks secret-shaped.
Exit 0 = TEST_SYN_GO, exit 2 = a step failed (evidence written), exit 3 = the
run could not be executed safely.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import httpx

from app.monitoring.collector import IDENTIFIER, SECRET_SHAPED, scrub
from scripts.staging_synthetic_acceptance import (
    WEBHOOK_PATH,
    AcceptanceError,
    build_signed_event,
    validate_runtime_safety,
)

REQUIRED_HOPS = ("caddy", "kong", "middleware")
PLANNED_HOPS = ("odoo", "n8n")
HOP_SERVICE_NAMES = {
    "caddy": {"caddy", "codestra-caddy", "edge-caddy"},
    "kong": {"kong", "codestra-kong", "kong-gateway"},
    "middleware": {"middleware", "middleware-integration-api", "codestra-middleware"},
    "odoo": {"odoo", "odoo-web", "codestra-odoo"},
    "n8n": {"n8n", "n8n-automation", "codestra-n8n"},
}
SYNTHETIC_ALERTNAME = "TestSynSyntheticAlert"
FRESH_SECONDS = 90.0
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")


class CertificationError(RuntimeError):
    """The run cannot proceed safely; nothing partial is certified."""


def read_secret_file(path: str) -> str:
    file = Path(path)
    if not file.is_absolute() or file.is_symlink() or not file.is_file():
        raise CertificationError(f"secret file {file.name} is unavailable or unsafe")
    value = file.read_text(encoding="utf-8").strip()
    if not value:
        raise CertificationError(f"secret file {file.name} is empty")
    return value


def required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise CertificationError(f"{name} is required")
    return value


def base_url(env: Mapping[str, str], name: str) -> str:
    value = required(env, name).rstrip("/")
    if not value.startswith(("http://", "https://")):
        raise CertificationError(f"{name} must be an http(s) URL")
    return value


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def new_traceparent() -> tuple[str, str]:
    trace_id = secrets.token_hex(16)
    return trace_id, f"00-{trace_id}-{secrets.token_hex(8)}-01"


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class Plan:
    """Resolved, secret-free view of the run parameters plus the loaded credentials."""

    def __init__(self, env: Mapping[str, str]):
        self.edge = base_url(env, "TEST_SYN_EDGE_BASE_URL")
        self.middleware = base_url(env, "TEST_SYN_MIDDLEWARE_BASE_URL")
        self.tempo = base_url(env, "TEST_SYN_TEMPO_BASE_URL")
        self.loki = base_url(env, "TEST_SYN_LOKI_BASE_URL")
        self.prometheus = base_url(env, "TEST_SYN_PROMETHEUS_BASE_URL")
        self.alertmanager = base_url(env, "TEST_SYN_ALERTMANAGER_BASE_URL")
        self.grafana = base_url(env, "TEST_SYN_GRAFANA_BASE_URL")
        self.loki_tenant = required(env, "TEST_SYN_LOKI_TENANT")
        self.tenant_id = required(env, "TEST_SYN_TENANT_ID")
        self.expected_sha = required(env, "EXPECTED_SOURCE_SHA").lower()
        self.expected_digest = required(env, "EXPECTED_IMAGE_DIGEST").lower()
        self.middleware_service = env.get(
            "TEST_SYN_MIDDLEWARE_SERVICE", "middleware-integration-api"
        )
        self.request_metric_query = env.get(
            "TEST_SYN_REQUEST_METRIC_QUERY",
            'sum(increase(http_requests_total{service="middleware-integration-api"}[5m]))',
        )
        self.effect_metric_query = env.get(
            "TEST_SYN_EFFECT_METRIC_QUERY",
            'sum(codestra_provider_effects_total{environment="staging"}) or vector(0)',
        )
        self.wait_seconds = float(env.get("TEST_SYN_WAIT_SECONDS", "20"))
        self.poll_seconds = float(env.get("TEST_SYN_POLL_SECONDS", "2"))
        if not IDENTIFIER.fullmatch(self.tenant_id) or not IDENTIFIER.fullmatch(
            self.loki_tenant
        ):
            raise CertificationError("tenant identifiers must be bounded")
        if not re.fullmatch(r"[0-9a-f]{40}", self.expected_sha) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.expected_digest
        ):
            raise CertificationError(
                "EXPECTED_SOURCE_SHA / EXPECTED_IMAGE_DIGEST must be exact"
            )
        self.monitoring_token = read_secret_file(
            required(env, "TEST_SYN_MONITORING_TOKEN_FILE")
        )
        self.producer_token = read_secret_file(
            required(env, "TEST_SYN_PRODUCER_TOKEN_FILE")
        )
        self.operator_token = read_secret_file(
            required(env, "TEST_SYN_OPERATOR_TOKEN_FILE")
        )
        self.grafana_token = read_secret_file(
            required(env, "TEST_SYN_GRAFANA_TOKEN_FILE")
        )
        self.webhook_secret = read_secret_file(
            required(env, "TEST_SYN_WEBHOOK_SECRET_FILE")
        ).encode("utf-8")
        if len(self.webhook_secret) < 32:
            raise CertificationError("webhook secret must be at least 32 bytes")
        self.secrets = [
            self.monitoring_token,
            self.producer_token,
            self.operator_token,
            self.grafana_token,
            self.webhook_secret.decode("utf-8"),
        ]

    def public(self) -> dict[str, Any]:
        return {
            "edge": self.edge,
            "middleware": self.middleware,
            "tempo": self.tempo,
            "loki": self.loki,
            "prometheus": self.prometheus,
            "alertmanager": self.alertmanager,
            "grafana": self.grafana,
            "tenant_id": self.tenant_id,
            "loki_tenant": self.loki_tenant,
            "expected_source_sha": self.expected_sha,
            "expected_image_digest": self.expected_digest,
            "credentials": "loaded from *_FILE paths; never recorded",
        }


class Runner:
    def __init__(
        self,
        plan: Plan,
        client: httpx.Client,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.plan = plan
        self.client = client
        self.sleep = sleep
        self.steps: list[dict[str, Any]] = []
        self.event: dict[str, Any] = {}
        self.trace_id, self.traceparent = new_traceparent()
        self.correlation_id = ""
        self.safety_before: dict[str, Any] = {}
        self.effects_before: float | None = None

    # -- helpers -----------------------------------------------------------------------------

    def bearer(self, token: str) -> dict[str, str]:
        return {"Authorization": "Bearer " + token, "Accept": "application/json"}

    def get_json(
        self, url: str, headers: dict[str, str] | None = None, expect: int = 200
    ) -> Any:
        response = self.client.get(
            url, headers=headers or {"Accept": "application/json"}
        )
        if response.status_code != expect:
            raise AcceptanceError(
                f"GET {httpx.URL(url).path} returned {response.status_code}, expected {expect}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise AcceptanceError(
                f"GET {httpx.URL(url).path} did not return JSON"
            ) from exc

    def poll(self, probe: Callable[[], Any | None]) -> Any | None:
        deadline = time.monotonic() + self.plan.wait_seconds
        while True:
            result = probe()
            if result is not None or time.monotonic() >= deadline:
                return result
            self.sleep(self.plan.poll_seconds)

    def step(self, name: str, action: Callable[[], dict[str, Any]]) -> bool:
        started = datetime.now(timezone.utc).isoformat()
        try:
            details = action()
            self.steps.append(
                {
                    "step": name,
                    "status": "pass",
                    "started_at": started,
                    "details": details,
                }
            )
            return True
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

    def skip(self, name: str, reason: str) -> None:
        self.steps.append({"step": name, "status": "skipped", "reason": reason})

    # -- steps -------------------------------------------------------------------------------

    def runtime_safety(self) -> dict[str, Any]:
        payload = self.get_json(
            self.plan.middleware + "/v1/runtime/safety",
            self.bearer(self.plan.monitoring_token),
        )
        safety = validate_runtime_safety(
            payload,
            expected_source_sha=self.plan.expected_sha,
            expected_image_digest=self.plan.expected_digest,
        )
        self.safety_before = safety
        return {
            "environment": safety["environment"],
            "runtime_profile_id": safety["runtime_profile_id"],
            "source_sha": safety["release"]["source_sha"],
            "schema_head": safety["release"]["schema_head"],
            "external_effects_enabled": [],
        }

    def edge_request(self) -> dict[str, Any]:
        event, body, headers = build_signed_event(
            tenant_id=self.plan.tenant_id, secret=self.plan.webhook_secret
        )
        self.event = event
        self.correlation_id = event["correlation_id"]
        headers.update(
            {
                "Authorization": "Bearer " + self.plan.producer_token,
                "traceparent": self.traceparent,
                "X-Correlation-ID": self.correlation_id,
            }
        )
        first = self.client.post(
            self.plan.edge + WEBHOOK_PATH, content=body, headers=headers
        )
        if first.status_code != 202:
            raise AcceptanceError(
                f"edge synthetic request returned {first.status_code}, expected 202"
            )
        accepted = first.json()
        if (
            accepted.get("event_id") != event["event_id"]
            or accepted.get("status") != "accepted"
            or accepted.get("duplicate") is not False
        ):
            raise AcceptanceError("edge synthetic response is not canonical acceptance")
        second = self.client.post(
            self.plan.edge + WEBHOOK_PATH, content=body, headers=headers
        )
        if second.status_code != 200 or second.json().get("status") != "duplicate":
            raise AcceptanceError(
                "edge synthetic retry was not reconciled as a duplicate"
            )
        echoed = first.headers.get("X-Correlation-ID", "")
        return {
            "event_id": event["event_id"],
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "first_status": 202,
            "duplicate_status": 200,
            "correlation_echoed": echoed == self.correlation_id,
            "edge_server": first.headers.get("Server", "")[:40],
            "via_kong": bool(
                first.headers.get("X-Kong-Proxy-Latency")
                or first.headers.get("Via", "").lower().find("kong") >= 0
            ),
        }

    def trace_propagation(self) -> dict[str, Any]:
        def probe():
            response = self.client.get(
                self.plan.tempo + f"/api/traces/{self.trace_id}",
                headers={"Accept": "application/json"},
            )
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise AcceptanceError(f"tempo returned {response.status_code}")
            spans = extract_spans(response.json())
            return spans or None

        spans = self.poll(probe)
        if not spans:
            raise AcceptanceError(
                "tempo holds no spans for the synthetic trace within the wait window"
            )
        observed_services = {span["service"] for span in spans}
        hops: dict[str, str] = {}
        for hop in REQUIRED_HOPS + PLANNED_HOPS:
            hops[hop] = (
                "observed"
                if observed_services & HOP_SERVICE_NAMES[hop]
                else ("missing" if hop in REQUIRED_HOPS else "planned")
            )
        missing = [hop for hop in REQUIRED_HOPS if hops[hop] == "missing"]
        if missing:
            raise AcceptanceError(
                "required trace hops missing: "
                + ", ".join(missing)
                + f" (observed services: {sorted(observed_services)})"
            )
        correlated = [
            s
            for s in spans
            if self.correlation_id
            in (
                s["attributes"].get("correlation.id"),
                s["attributes"].get("correlation_id"),
            )
        ]
        if not any(s["service"] in HOP_SERVICE_NAMES["middleware"] for s in correlated):
            raise AcceptanceError(
                "middleware span does not carry the request correlation_id"
            )
        return {
            "trace_id": self.trace_id,
            "spans": len(spans),
            "services": sorted(observed_services),
            "hops": hops,
            "spans_with_correlation_id": len(correlated),
            "span_links": sum(len(s["links"]) for s in spans),
            "single_trace": len({s["trace_id"] for s in spans if s["trace_id"]}) <= 1,
        }

    def log_correlation(self) -> dict[str, Any]:
        query = f'{{service="{self.plan.middleware_service}"}} | json | correlation_id="{self.correlation_id}"'

        def probe():
            payload = self.get_json(
                self.plan.loki
                + "/loki/api/v1/query_range?"
                + httpx.QueryParams(
                    {"query": query, "limit": "50", "since": "15m"}
                ).__str__(),
                {"Accept": "application/json", "X-Scope-OrgID": self.plan.loki_tenant},
            )
            streams = (
                payload.get("data", {}).get("result", [])
                if isinstance(payload, dict)
                else []
            )
            lines = [
                value[1] for stream in streams for value in stream.get("values", [])
            ]
            return lines or None

        lines = self.poll(probe)
        if not lines:
            raise AcceptanceError(
                "loki returned no middleware log line for the correlation_id within the wait window"
            )
        with_trace = 0
        leaking = 0
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                record = {}
            if record.get("trace_id") == self.trace_id:
                with_trace += 1
            if SECRET_SHAPED.search(line):
                leaking += 1
        if leaking:
            raise AcceptanceError(
                f"{leaking} correlated log line(s) contain secret-shaped material; redaction is broken"
            )
        if not with_trace:
            raise AcceptanceError("correlated log lines do not carry the trace_id")
        return {
            "lines": len(lines),
            "lines_with_trace_id": with_trace,
            "secret_shaped_lines": 0,
            "query_digest": digest(query),
        }

    def metrics_freshness(self) -> dict[str, Any]:
        targets = self.get_json(self.plan.prometheus + "/api/v1/targets?state=active")
        active = targets.get("data", {}).get("activeTargets", [])
        now = datetime.now(timezone.utc)
        middleware = [
            t
            for t in active
            if t.get("labels", {}).get("service") == self.plan.middleware_service
            or t.get("labels", {}).get("job") == "codestra-middleware-metrics"
        ]
        if not middleware:
            raise AcceptanceError("prometheus has no active middleware target")
        target = middleware[0]
        last = parse_time(target.get("lastScrape"))
        age = (now - last).total_seconds() if last else None
        if target.get("health") != "up":
            raise AcceptanceError(
                f"middleware target health is {target.get('health')}: {scrub(str(target.get('lastError', '')))[:120]}"
            )
        if age is None or age > FRESH_SECONDS:
            raise AcceptanceError(f"middleware metrics are stale ({age} s)")
        host = httpx.URL(target.get("scrapeUrl", "")).host
        port = httpx.URL(target.get("scrapeUrl", "")).port
        if port == 8080:
            raise AcceptanceError("middleware scrape target uses legacy port 8080")
        query = self.get_json(
            self.plan.prometheus
            + "/api/v1/query?"
            + str(httpx.QueryParams({"query": self.plan.request_metric_query}))
        )
        results = query.get("data", {}).get("result", [])
        value = float(results[0]["value"][1]) if results else 0.0
        if value <= 0:
            raise AcceptanceError(
                "request metric did not increase for the synthetic window"
            )
        effect = self.get_json(
            self.plan.prometheus
            + "/api/v1/query?"
            + str(httpx.QueryParams({"query": self.plan.effect_metric_query}))
        )
        effect_results = effect.get("data", {}).get("result", [])
        self.effects_before = (
            float(effect_results[0]["value"][1]) if effect_results else 0.0
        )
        return {
            "target_host": host,
            "target_port": port,
            "health": "up",
            "last_scrape_age_seconds": round(age, 1),
            "request_metric_5m": value,
            "provider_effect_counter": self.effects_before,
        }

    def alert_ingestion(self) -> dict[str, Any]:
        starts = datetime.now(timezone.utc).isoformat()
        labels = {
            "alertname": SYNTHETIC_ALERTNAME,
            "severity": "informational",
            "service": "test-syn",
            "environment": "staging",
            "business": "platform",
            "correlation_id": self.correlation_id,
        }
        alert = [
            {
                "labels": labels,
                "annotations": {
                    "summary": "TEST_SYN synthetic alert; no business effect",
                    "correlation_id": self.correlation_id,
                },
                "startsAt": starts,
                "generatorURL": "https://certification/test-syn",
            }
        ]
        for attempt in range(2):
            response = self.client.post(
                self.plan.alertmanager + "/api/v2/alerts",
                json=alert,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code != 200:
                raise AcceptanceError(
                    f"alertmanager rejected the synthetic alert with {response.status_code}"
                )

        def probe():
            page = self.get_json(
                self.plan.middleware
                + "/v1/observability/incidents?"
                + str(httpx.QueryParams({"service": "test-syn", "limit": "100"})),
                {
                    **self.bearer(self.plan.operator_token),
                    "X-Correlation-ID": self.correlation_id,
                },
            )
            items = [
                i
                for i in page.get("items", [])
                if i.get("labels", {}).get("correlation_id") == self.correlation_id
            ]
            return items or None

        items = self.poll(probe)
        if not items:
            raise AcceptanceError(
                "middleware recorded no incident for the synthetic alert within the wait window"
            )
        if len(items) != 1:
            raise AcceptanceError(
                f"synthetic alert produced {len(items)} incidents; ingestion is not idempotent"
            )
        incident = items[0]
        return {
            "incident_id": str(incident.get("incident_id")),
            "fingerprint": incident.get("alert_fingerprint"),
            "state": incident.get("state"),
            "severity": incident.get("severity"),
            "incidents_for_alert": 1,
            "posted_twice": True,
            "source_deployment": incident.get("source_deployment"),
        }

    def dashboard_readback(self) -> dict[str, Any]:
        headers = self.bearer(self.plan.grafana_token)
        health = self.get_json(
            self.plan.grafana
            + "/api/datasources/uid/codestra-middleware-observability/health",
            headers,
        )
        if str(health.get("status", "")).upper() != "OK":
            raise AcceptanceError(
                f"grafana middleware datasource health is {health.get('status')}"
            )
        dashboards = self.get_json(
            self.plan.grafana + "/api/search?type=dash-db&limit=5000", headers
        )
        uids = {d.get("uid") for d in dashboards if isinstance(d, dict)}
        expected = {"codestra-openbao", "codestra-middleware-operations"}
        if not expected <= uids:
            raise AcceptanceError(
                "grafana is missing dashboards: " + ", ".join(sorted(expected - uids))
            )
        overview = self.client.get(
            self.plan.middleware + "/v1/observability/overview",
            headers={
                **self.bearer(self.plan.monitoring_token),
                "X-Correlation-ID": self.correlation_id,
            },
        )
        if overview.status_code != 200:
            raise AcceptanceError(
                f"middleware observability overview returned {overview.status_code} for monitoring-readonly"
            )
        return {
            "middleware_datasource": "OK",
            "dashboards": len(uids),
            "required_dashboards_present": True,
            "observability_overview": 200,
        }

    def no_business_effect(self) -> dict[str, Any]:
        payload = self.get_json(
            self.plan.middleware + "/v1/runtime/safety",
            self.bearer(self.plan.monitoring_token),
        )
        after = validate_runtime_safety(
            payload,
            expected_source_sha=self.plan.expected_sha,
            expected_image_digest=self.plan.expected_digest,
        )
        for key in (
            "external_effects",
            "umbrella_controls",
            "dispatch",
            "production_dialing",
        ):
            if after.get(key) != self.safety_before.get(key):
                raise AcceptanceError(f"runtime safety changed during the run: {key}")
        effect = self.get_json(
            self.plan.prometheus
            + "/api/v1/query?"
            + str(httpx.QueryParams({"query": self.plan.effect_metric_query}))
        )
        effect_results = effect.get("data", {}).get("result", [])
        effects_after = float(effect_results[0]["value"][1]) if effect_results else 0.0
        if self.effects_before is not None and effects_after != self.effects_before:
            raise AcceptanceError(
                f"provider effect counter moved from {self.effects_before} to {effects_after}"
            )
        return {
            "runtime_safety_unchanged": True,
            "provider_effect_counter_before": self.effects_before,
            "provider_effect_counter_after": effects_after,
            "campaign": "TEST_SYN",
            "tenant_id": self.plan.tenant_id,
        }

    # -- orchestration -----------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        ok = self.step("runtime-safety-readback", self.runtime_safety)
        if not ok:
            for name in (
                "edge-synthetic-request",
                "trace-propagation",
                "log-correlation",
                "metrics-freshness",
                "alert-ingestion",
                "dashboard-readback",
                "no-business-effect",
            ):
                self.skip(
                    name,
                    "runtime safety read-back failed; no synthetic traffic is sent",
                )
        else:
            sent = self.step("edge-synthetic-request", self.edge_request)
            if sent:
                self.step("trace-propagation", self.trace_propagation)
                self.step("log-correlation", self.log_correlation)
            else:
                self.skip("trace-propagation", "no synthetic request was accepted")
                self.skip("log-correlation", "no synthetic request was accepted")
            self.step("metrics-freshness", self.metrics_freshness)
            self.step("alert-ingestion", self.alert_ingestion)
            self.step("dashboard-readback", self.dashboard_readback)
            self.step("no-business-effect", self.no_business_effect)
        passed = all(step["status"] == "pass" for step in self.steps)
        trace_step = next(
            (s for s in self.steps if s["step"] == "trace-propagation"), {}
        )
        hops = trace_step.get("details", {}).get("hops", {})
        return {
            "schema_version": 1,
            "certification": "TEST_SYN",
            "environment": "staging",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "plan": self.plan.public(),
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id or None,
            "synthetic_event_id": self.event.get("event_id"),
            "steps": self.steps,
            "hops": hops,
            "planned_hops_observed": [
                hop for hop in PLANNED_HOPS if hops.get(hop) == "observed"
            ],
            "verdict": {
                "TEST_SYN_GO": "YES" if passed else "NO",
                "steps_passed": sum(1 for s in self.steps if s["status"] == "pass"),
                "steps_total": len(self.steps),
            },
            "business_effect": "none (TEST_SYN tenant, effect controls attested off before and after)",
            "secrets_recorded": False,
        }


def extract_spans(payload: Any) -> list[dict[str, Any]]:
    """Flatten a Tempo OTLP-JSON trace into (service, name, trace_id, attributes, links)."""
    spans: list[dict[str, Any]] = []
    batches = (
        payload.get("batches") or payload.get("resourceSpans") or []
        if isinstance(payload, dict)
        else []
    )
    for batch in batches:
        resource_attributes = attributes_of(
            batch.get("resource", {}).get("attributes", [])
        )
        service = str(resource_attributes.get("service.name", "unknown"))
        for scope in (
            batch.get("scopeSpans") or batch.get("instrumentationLibrarySpans") or []
        ):
            for span in scope.get("spans", []):
                attrs = attributes_of(span.get("attributes", []))
                spans.append(
                    {
                        "service": service,
                        "name": span.get("name"),
                        "trace_id": normalize_trace_id(span.get("traceId")),
                        "attributes": {
                            k: v
                            for k, v in attrs.items()
                            if k
                            in {
                                "correlation.id",
                                "correlation_id",
                                "service_id",
                                "environment",
                                "deployment_id",
                                "http.route",
                                "http.status_code",
                            }
                        },
                        "links": span.get("links", []) or [],
                    }
                )
    return spans


def attributes_of(items: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in items or []:
        if not isinstance(item, dict) or "key" not in item:
            continue
        value = item.get("value", {})
        if isinstance(value, dict):
            value = value.get(
                "stringValue",
                value.get("intValue", value.get("boolValue", value.get("doubleValue"))),
            )
        result[item["key"]] = value
    return result


def normalize_trace_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if TRACE_ID.fullmatch(value.lower()):
        return value.lower()
    try:
        import base64

        raw = base64.b64decode(value)
        return raw.hex() if len(raw) == 16 else None
    except Exception:  # noqa: BLE001 - any undecodable id is simply unknown
        return None


def write_evidence(report: dict[str, Any], plan: Plan, output: Path) -> Path:
    serialized = json.dumps(report, indent=2, sort_keys=True)
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
    path = output / "test-syn-certification.json"
    path.write_text(serialized + "\n", encoding="utf-8")
    return path


def main(
    argv: list[str] | None = None,
    env: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--output",
        required=True,
        help="absolute 0700 directory for the redacted evidence",
    )
    args = parser.parse_args(argv)
    output = Path(args.output)
    if not output.is_absolute():
        print("TEST_SYN=FAIL reason=output-must-be-absolute", file=sys.stderr)
        return 3
    try:
        plan = Plan(os.environ if env is None else env)
    except CertificationError as exc:
        print(f"TEST_SYN=FAIL reason={exc}", file=sys.stderr)
        return 3
    with httpx.Client(
        timeout=httpx.Timeout(15.0), follow_redirects=False, transport=transport
    ) as client:
        report = Runner(plan, client, sleep).run()
    try:
        path = write_evidence(report, plan, output)
    except CertificationError as exc:
        print(f"TEST_SYN=FAIL reason={exc}", file=sys.stderr)
        return 3
    verdict = report["verdict"]
    print(
        f"TEST_SYN_GO={verdict['TEST_SYN_GO']} steps={verdict['steps_passed']}/{verdict['steps_total']} trace_id={report['trace_id']} evidence={path.name}"
    )
    return 0 if verdict["TEST_SYN_GO"] == "YES" else 2


if __name__ == "__main__":
    sys.exit(main())
