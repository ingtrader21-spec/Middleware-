"""TEST_SYN certification runner: eight fail-closed steps across edge, traces, logs, metrics, alerts."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.runtime_safety import runtime_safety_readback
from scripts import certify_test_syn as cert

SOURCE_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + ("b" * 64)


def _synthetic_jwt(claims: dict[str, str], signature: str) -> str:
    """JWT-shaped fixture assembled at import time: unsigned, unverifiable, never a credential."""

    def segment(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return ".".join(
        (
            segment(b'{"alg":"RS256"}'),
            segment(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
            segment(signature.encode("utf-8")),
        )
    )


TOKENS = {
    "monitoring": _synthetic_jwt(
        {"azp": "monitoring-readonly"}, "monitoring-signature-value"
    ),
    "producer": _synthetic_jwt({"azp": "odoo-integration"}, "producer-signature-value"),
    "operator": _synthetic_jwt(
        {"azp": "platform-operator"}, "operator-signature-value"
    ),
    "grafana": "glsa_testsyn_readonly_0123456789abcdef_0123456789",
    "webhook": "staging-webhook-secret-at-least-thirty-two-bytes-long",
}


@pytest.fixture
def safety(test_settings) -> dict:
    staging = test_settings.replace(
        app_env="staging",
        runtime_profile_id="codestra-middleware-staging-v1",
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        build_time="2026-08-28T12:00:00Z",
        allow_in_memory_storage=False,
    )
    return runtime_safety_readback(staging)


def environment(tmp_path) -> dict[str, str]:
    files = {}
    for name, value in TOKENS.items():
        path = tmp_path / f"{name}.secret"
        path.write_text(value, encoding="utf-8")
        files[name] = str(path)
    return {
        "TEST_SYN_EDGE_BASE_URL": "https://api-staging.example.test",
        "TEST_SYN_MIDDLEWARE_BASE_URL": "http://middleware-integration-api:8095",
        "TEST_SYN_TEMPO_BASE_URL": "http://tempo:3200",
        "TEST_SYN_LOKI_BASE_URL": "http://loki:3100",
        "TEST_SYN_PROMETHEUS_BASE_URL": "http://prometheus:9090",
        "TEST_SYN_ALERTMANAGER_BASE_URL": "http://alertmanager:9093",
        "TEST_SYN_GRAFANA_BASE_URL": "http://grafana:3000",
        "TEST_SYN_LOKI_TENANT": "codestra-staging",
        "TEST_SYN_TENANT_ID": "TEST_SYN_TENANT",
        "EXPECTED_SOURCE_SHA": SOURCE_SHA,
        "EXPECTED_IMAGE_DIGEST": IMAGE_DIGEST,
        "TEST_SYN_WAIT_SECONDS": "1",
        "TEST_SYN_POLL_SECONDS": "0",
        "TEST_SYN_MONITORING_TOKEN_FILE": files["monitoring"],
        "TEST_SYN_PRODUCER_TOKEN_FILE": files["producer"],
        "TEST_SYN_OPERATOR_TOKEN_FILE": files["operator"],
        "TEST_SYN_GRAFANA_TOKEN_FILE": files["grafana"],
        "TEST_SYN_WEBHOOK_SECRET_FILE": files["webhook"],
    }


class Platform:
    """A fake staging platform behind one httpx MockTransport; mutable knobs per test."""

    def __init__(self, safety: dict):
        self.safety = safety
        self.calls: list[str] = []
        self.accepted: dict | None = None
        self.trace_ready_after = 0
        self.trace_services = ["caddy", "kong", "middleware-integration-api"]
        self.log_lines_template = [
            '{{"level":"info","msg":"event accepted","correlation_id":"{corr}","trace_id":"{trace}"}}'
        ]
        self.request_metric = "3"
        self.effect_counter = ["0", "0"]
        self.alert_posts = 0
        self.incidents: list[dict] = []
        self.incident_per_post = 1
        self.datasource_health = "OK"
        self.dashboards = ["codestra-openbao", "codestra-middleware-operations"]
        self.scrape_port = 8095
        self.trace_polls = 0
        self.correlation: str | None = None
        self.trace_id: str | None = None
        self.safety_after: dict | None = None

    def spans(self) -> dict:
        assert self.trace_id is not None
        raw = bytes.fromhex(self.trace_id)
        batches = []
        for service in self.trace_services:
            attrs = [
                {"key": "correlation.id", "value": {"stringValue": self.correlation}},
                {"key": "environment", "value": {"stringValue": "staging"}},
            ]
            batches.append(
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": service}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": "POST /api/v1/odoo/events",
                                    "traceId": base64.b64encode(raw).decode(),
                                    "attributes": attrs,
                                    "links": []
                                    if service != "n8n"
                                    else [{"traceId": base64.b64encode(raw).decode()}],
                                }
                            ]
                        }
                    ],
                }
            )
        return {"batches": batches}

    def handler(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        self.calls.append(f"{request.method} {host}{path}")
        if host == "middleware-integration-api" and path == "/v1/runtime/safety":
            assert request.headers["Authorization"] == "Bearer " + TOKENS["monitoring"]
            return httpx.Response(
                200,
                json=self.safety_after
                if self.safety_after and self.accepted
                else self.safety,
            )
        if host == "api-staging.example.test" and path == "/api/v1/odoo/events":
            assert request.headers["Authorization"] == "Bearer " + TOKENS["producer"]
            assert (
                request.headers["traceparent"].startswith("00-")
                and request.headers["X-Correlation-ID"]
            )
            current = json.loads(request.content)
            self.correlation = current["correlation_id"]
            self.trace_id = request.headers["traceparent"].split("-")[1]
            if self.accepted is None:
                self.accepted = current
                return httpx.Response(
                    202,
                    json={
                        "event_id": current["event_id"],
                        "tenant_id": current["tenant_id"],
                        "status": "accepted",
                        "duplicate": False,
                    },
                    headers={
                        "X-Correlation-ID": self.correlation or "",
                        "Via": "1.1 kong/3.9",
                        "Server": "Caddy",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "event_id": current["event_id"],
                    "tenant_id": current["tenant_id"],
                    "status": "duplicate",
                    "duplicate": True,
                },
                headers={"X-Correlation-ID": self.correlation or ""},
            )
        if host == "tempo" and path.startswith("/api/traces/"):
            assert self.trace_id is not None
            assert path.endswith(self.trace_id)
            self.trace_polls += 1
            if self.trace_polls <= self.trace_ready_after:
                return httpx.Response(404, text="trace not found")
            return httpx.Response(200, json=self.spans())
        if host == "loki" and path == "/loki/api/v1/query_range":
            assert request.headers["X-Scope-OrgID"] == "codestra-staging"
            assert f'correlation_id="{self.correlation}"' in request.url.params["query"]
            values = [
                ["1", line.format(corr=self.correlation, trace=self.trace_id)]
                for line in self.log_lines_template
            ]
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "streams",
                        "result": [
                            {
                                "stream": {"service": "middleware-integration-api"},
                                "values": values,
                            }
                        ]
                        if values
                        else [],
                    },
                },
            )
        if host == "prometheus" and path == "/api/v1/targets":
            now = datetime.now(timezone.utc)
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "activeTargets": [
                            {
                                "labels": {
                                    "job": "codestra-middleware-metrics",
                                    "service": "middleware-integration-api",
                                    "environment": "staging",
                                },
                                "scrapeUrl": f"http://middleware-integration-api:{self.scrape_port}/metrics",
                                "health": "up",
                                "lastScrape": (now - timedelta(seconds=15)).isoformat(),
                                "lastError": "",
                            }
                        ]
                    },
                },
            )
        if host == "prometheus" and path == "/api/v1/query":
            query = request.url.params["query"]
            if "http_requests_total" in query:
                return httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "data": {
                            "resultType": "vector",
                            "result": [
                                {"metric": {}, "value": [1, self.request_metric]}
                            ],
                        },
                    },
                )
            value = self.effect_counter.pop(0) if self.effect_counter else "0"
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [{"metric": {}, "value": [1, value]}],
                    },
                },
            )
        if host == "alertmanager" and path == "/api/v2/alerts":
            body = json.loads(request.content)
            assert (
                body[0]["labels"]["severity"] == "informational"
                and body[0]["labels"]["service"] == "test-syn"
            )
            self.alert_posts += 1
            created = (
                self.incident_per_post
                if (self.alert_posts == 1 or self.incident_per_post > 1)
                else 0
            )
            for _ in range(created):
                self.incidents.append(
                    {
                        "incident_id": f"00000000-0000-4000-8000-00000000000{len(self.incidents) + 1}",
                        "alert_fingerprint": "fp-" + (self.correlation or "")[-8:],
                        "state": "open",
                        "severity": "informational",
                        "service": "test-syn",
                        "environment": "staging",
                        "labels": body[0]["labels"],
                        "source_deployment": "alertmanager-staging",
                    }
                )
            return httpx.Response(200, json=None)
        if (
            host == "middleware-integration-api"
            and path == "/v1/observability/incidents"
        ):
            assert request.headers["Authorization"] == "Bearer " + TOKENS["operator"]
            return httpx.Response(
                200, json={"items": self.incidents, "next_cursor": None}
            )
        if (
            host == "grafana"
            and path == "/api/datasources/uid/codestra-middleware-observability/health"
        ):
            assert request.headers["Authorization"] == "Bearer " + TOKENS["grafana"]
            return httpx.Response(200, json={"status": self.datasource_health})
        if host == "grafana" and path == "/api/search":
            return httpx.Response(
                200, json=[{"uid": uid, "type": "dash-db"} for uid in self.dashboards]
            )
        if (
            host == "middleware-integration-api"
            and path == "/v1/observability/overview"
        ):
            assert request.headers["Authorization"] == "Bearer " + TOKENS["monitoring"]
            return httpx.Response(200, json={"result": {"services": 15}})
        return httpx.Response(404, text="unexpected " + path)


def run(
    platform: Platform, tmp_path, env_overrides: dict | None = None
) -> tuple[int, dict]:
    env = environment(tmp_path)
    env.update(env_overrides or {})
    code = cert.main(
        ["--output", str(tmp_path / "evidence")],
        env=env,
        transport=httpx.MockTransport(platform.handler),
        sleep=lambda _: None,
    )
    path = tmp_path / "evidence" / "test-syn-certification.json"
    return code, (json.loads(path.read_text(encoding="utf-8")) if path.exists() else {})


def test_full_certification_passes_all_eight_steps(safety, tmp_path):
    platform = Platform(safety)
    platform.trace_ready_after = 1
    code, report = run(platform, tmp_path)
    assert code == 0, report
    assert [s["step"] for s in report["steps"]] == [
        "runtime-safety-readback",
        "edge-synthetic-request",
        "trace-propagation",
        "log-correlation",
        "metrics-freshness",
        "alert-ingestion",
        "dashboard-readback",
        "no-business-effect",
    ]
    assert all(s["status"] == "pass" for s in report["steps"])
    assert report["verdict"] == {
        "TEST_SYN_GO": "YES",
        "steps_passed": 8,
        "steps_total": 8,
    }
    assert report["hops"] == {
        "caddy": "observed",
        "kong": "observed",
        "middleware": "observed",
        "odoo": "planned",
        "n8n": "planned",
    }
    edge = next(s for s in report["steps"] if s["step"] == "edge-synthetic-request")[
        "details"
    ]
    assert (
        edge["first_status"] == 202
        and edge["duplicate_status"] == 200
        and edge["correlation_echoed"]
        and edge["via_kong"]
    )
    alert = next(s for s in report["steps"] if s["step"] == "alert-ingestion")[
        "details"
    ]
    assert (
        alert["incidents_for_alert"] == 1
        and alert["posted_twice"]
        and platform.alert_posts == 2
    )
    metrics = next(s for s in report["steps"] if s["step"] == "metrics-freshness")[
        "details"
    ]
    assert metrics["target_port"] == 8095 and metrics["last_scrape_age_seconds"] < 90
    assert (
        report["secrets_recorded"] is False and report["trace_id"] == platform.trace_id
    )
    # only the two authorised synthetic writes happened
    posts = [c for c in platform.calls if c.startswith("POST")]
    assert (
        posts
        == ["POST api-staging.example.test/api/v1/odoo/events"] * 2
        + ["POST alertmanager/api/v2/alerts"] * 2
    )
    written = (tmp_path / "evidence" / "test-syn-certification.json").read_text(
        encoding="utf-8"
    )
    assert not any(value in written for value in TOKENS.values())


def test_async_hops_observed_with_span_links(safety, tmp_path):
    platform = Platform(safety)
    platform.trace_services = [
        "caddy",
        "kong",
        "middleware-integration-api",
        "odoo",
        "n8n",
    ]
    code, report = run(platform, tmp_path)
    assert code == 0
    assert report["planned_hops_observed"] == ["odoo", "n8n"]
    trace = next(s for s in report["steps"] if s["step"] == "trace-propagation")[
        "details"
    ]
    assert trace["span_links"] == 1 and trace["single_trace"] is True


def test_unsafe_runtime_sends_no_synthetic_traffic(safety, tmp_path):
    unsafe = json.loads(json.dumps(safety))
    unsafe["external_effects"]["SMS_DELIVERY_ENABLED"] = True
    platform = Platform(unsafe)
    code, report = run(platform, tmp_path)
    assert code == 2
    assert (
        report["steps"][0]["status"] == "fail"
        and "SMS_DELIVERY_ENABLED" in report["steps"][0]["error"]
    )
    assert (
        all(s["status"] == "skipped" for s in report["steps"][1:])
        and len(report["steps"]) == 8
    )
    assert not any(c.startswith("POST") for c in platform.calls)
    assert report["verdict"]["TEST_SYN_GO"] == "NO"


def test_missing_required_hop_fails_trace_step(safety, tmp_path):
    platform = Platform(safety)
    platform.trace_services = ["caddy", "middleware-integration-api"]
    code, report = run(platform, tmp_path)
    assert code == 2
    trace = next(s for s in report["steps"] if s["step"] == "trace-propagation")
    assert trace["status"] == "fail" and "kong" in trace["error"]
    assert (
        next(s for s in report["steps"] if s["step"] == "log-correlation")["status"]
        == "pass"
    )


def test_trace_never_arriving_fails_within_wait_window(safety, tmp_path):
    platform = Platform(safety)
    platform.trace_ready_after = 10_000
    code, report = run(platform, tmp_path, {"TEST_SYN_WAIT_SECONDS": "0"})
    assert code == 2
    trace = next(s for s in report["steps"] if s["step"] == "trace-propagation")
    assert trace["status"] == "fail" and "no spans" in trace["error"]


def test_log_line_leaking_a_token_fails_redaction(safety, tmp_path):
    platform = Platform(safety)
    platform.log_lines_template = [
        '{{"correlation_id":"{corr}","trace_id":"{trace}","authorization":"Bearer hvs.'
        + "Z" * 40
        + '"}}'
    ]
    code, report = run(platform, tmp_path)
    assert code == 2
    log = next(s for s in report["steps"] if s["step"] == "log-correlation")
    assert log["status"] == "fail" and "redaction is broken" in log["error"]
    assert "hvs." not in json.dumps(report)


def test_duplicate_incidents_fail_idempotency(safety, tmp_path):
    platform = Platform(safety)
    platform.incident_per_post = 2
    code, report = run(platform, tmp_path)
    assert code == 2
    alert = next(s for s in report["steps"] if s["step"] == "alert-ingestion")
    assert alert["status"] == "fail" and "not idempotent" in alert["error"]


def test_legacy_port_8080_scrape_target_is_rejected(safety, tmp_path):
    platform = Platform(safety)
    platform.scrape_port = 8080
    code, report = run(platform, tmp_path)
    assert code == 2
    metrics = next(s for s in report["steps"] if s["step"] == "metrics-freshness")
    assert metrics["status"] == "fail" and "8080" in metrics["error"]


def test_provider_effect_counter_movement_fails_no_effect_step(safety, tmp_path):
    platform = Platform(safety)
    platform.effect_counter = ["0", "1"]
    code, report = run(platform, tmp_path)
    assert code == 2
    step = next(s for s in report["steps"] if s["step"] == "no-business-effect")
    assert step["status"] == "fail" and "effect counter moved" in step["error"]


def test_missing_dashboard_or_unhealthy_datasource_fails(safety, tmp_path):
    platform = Platform(safety)
    platform.dashboards = ["codestra-openbao"]
    code, report = run(platform, tmp_path)
    step = next(s for s in report["steps"] if s["step"] == "dashboard-readback")
    assert (
        code == 2
        and step["status"] == "fail"
        and "codestra-middleware-operations" in step["error"]
    )


def test_missing_secret_file_refuses_to_run(safety, tmp_path, capsys):
    platform = Platform(safety)
    code, report = run(
        platform, tmp_path, {"TEST_SYN_PRODUCER_TOKEN_FILE": str(tmp_path / "absent")}
    )
    assert code == 3 and report == {} and not platform.calls
    assert "unavailable or unsafe" in capsys.readouterr().err


def test_relative_output_is_refused(safety, tmp_path):
    assert (
        cert.main(
            ["--output", "relative"],
            env=environment(tmp_path),
            transport=httpx.MockTransport(Platform(safety).handler),
        )
        == 3
    )


def test_extract_spans_accepts_hex_and_base64_trace_ids():
    hex_id = "0123456789abcdef0123456789abcdef"
    payload = {
        "batches": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "kong"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {"name": "proxy", "traceId": hex_id, "attributes": []},
                            {
                                "name": "b64",
                                "traceId": base64.b64encode(
                                    bytes.fromhex(hex_id)
                                ).decode(),
                                "attributes": [
                                    {
                                        "key": "correlation_id",
                                        "value": {"stringValue": "corr-1"},
                                    },
                                    {
                                        "key": "http.request.header.authorization",
                                        "value": {"stringValue": "Bearer x"},
                                    },
                                ],
                            },
                        ]
                    }
                ],
            }
        ]
    }
    spans = cert.extract_spans(payload)
    assert [s["trace_id"] for s in spans] == [hex_id, hex_id]
    assert spans[1]["attributes"] == {"correlation_id": "corr-1"}
