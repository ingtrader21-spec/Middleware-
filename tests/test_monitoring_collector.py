"""Monitoring collector: reads actual runtime configuration, posts observations, never leaks."""

from __future__ import annotations

import base64
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.monitoring import collector
from app.monitoring.collector import CollectorConfig, CollectorError, run
from scripts.monitoring_collector import main


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


FAKE_BEARER = _synthetic_jwt(
    {"sub": "collector", "aud": "middleware-api"}, "signature-signature-signature"
)
GRAFANA_TOKEN = "glsa_readonly_collector_0123456789abcdef_0123456789"


class Fake:
    """One HTTP server that fakes every component under a path prefix and records requests."""

    def __init__(self):
        self.routes: dict[str, tuple[int, bytes, dict[str, str]]] = {}
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.posts: list[dict] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                path = self.path.split("?")[0]
                fake.requests.append(
                    (
                        self.command,
                        self.path,
                        {k.lower(): v for k, v in self.headers.items()},
                        body,
                    )
                )
                if self.command == "POST":
                    fake.posts.append(
                        {
                            "path": path,
                            "headers": {k.lower(): v for k, v in self.headers.items()},
                            "body": json.loads(body),
                        }
                    )
                    if path == "/mw/platform/v1/runtime/observations":
                        self._respond(
                            200,
                            json.dumps(
                                {"result": {"state": "recorded", "revision": 1}}
                            ).encode(),
                            {},
                        )
                        return
                    if path.startswith("/mw/platform/v1/services/") and path.endswith(
                        "/monitoring-state/observations"
                    ):
                        self._respond(
                            200, json.dumps({"monitoring_state": "synced"}).encode(), {}
                        )
                        return
                status, payload, headers = fake.routes.get(path, (404, b"missing", {}))
                self._respond(status, payload, headers)

            def _respond(self, status, payload, headers):
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _serve
            do_POST = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def json(self, path: str, payload, status: int = 200):
        self.routes[path] = (
            status,
            json.dumps(payload).encode(),
            {"Content-Type": "application/json"},
        )

    def text(self, path: str, payload: str, status: int = 200):
        self.routes[path] = (status, payload.encode(), {"Content-Type": "text/plain"})

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake():
    server = Fake()
    now = datetime.now(timezone.utc)
    server.text("/prom/-/ready", "Prometheus Server is Ready.")
    server.json(
        "/prom/api/v1/status/config",
        {"status": "success", "data": {"yaml": "global:\n  scrape_interval: 15s\n"}},
    )
    server.json(
        "/prom/api/v1/targets",
        {
            "status": "success",
            "data": {
                "activeTargets": [
                    {
                        "labels": {
                            "job": "codestra-middleware-metrics",
                            "service": "middleware-integration-api",
                            "environment": "staging",
                        },
                        "scrapeUrl": "http://middleware-integration-api:8095/metrics",
                        "health": "up",
                        "lastScrape": (now - timedelta(seconds=12)).isoformat(),
                        "lastError": "",
                    },
                    {
                        "labels": {
                            "job": "codestra-openbao",
                            "service": "openbao",
                            "environment": "staging",
                        },
                        "scrapeUrl": "https://openbao:8200/v1/sys/metrics?format=prometheus",
                        "health": "down",
                        "lastScrape": (now - timedelta(seconds=400)).isoformat(),
                        "lastError": "server returned HTTP status 403 Forbidden for Bearer "
                        + FAKE_BEARER,
                    },
                ]
            },
        },
    )
    server.json(
        "/prom/api/v1/rules",
        {
            "status": "success",
            "data": {
                "groups": [
                    {
                        "name": "openbao",
                        "file": "/etc/prometheus/rules/openbao-alerts.yml",
                        "rules": [{"name": "OpenBaoSealed"}],
                    }
                ]
            },
        },
    )
    server.text("/am/-/ready", "OK")
    server.json(
        "/am/api/v2/status",
        {
            "config": {"original": "route:\n  receiver: middleware\n"},
            "cluster": {"status": "ready"},
            "versionInfo": {"version": "0.28.1"},
        },
    )
    server.json("/am/api/v2/alerts", [{"labels": {"alertname": "Watchdog"}}])
    server.json("/gf/api/health", {"database": "ok", "version": "11.6.0"})
    server.json(
        "/gf/api/datasources",
        [
            {
                "uid": "codestra-prometheus",
                "type": "prometheus",
                "url": "http://prometheus:9090",
                "readOnly": True,
            },
            {
                "uid": "codestra-middleware-observability",
                "type": "yesoreyeram-infinity-datasource",
                "url": "http://middleware-integration-api:8095",
                "readOnly": True,
            },
        ],
    )
    server.json("/gf/api/datasources/uid/codestra-prometheus/health", {"status": "OK"})
    server.json(
        "/gf/api/datasources/uid/codestra-middleware-observability/health",
        {"status": "ERROR", "message": "401"},
    )
    server.json(
        "/gf/api/search",
        [
            {"uid": "codestra-openbao", "type": "dash-db"},
            {"uid": "codestra-middleware-operations", "type": "dash-db"},
        ],
    )
    server.text("/loki/ready", "ready")
    server.text("/loki/config", "auth_enabled: true\n")
    server.json(
        "/loki/loki/api/v1/labels",
        {"status": "success", "data": ["service", "environment", "level"]},
    )
    server.text("/tempo/ready", "ready")
    server.text("/tempo/status/config", "server:\n  http_listen_port: 3200\n")
    server.text("/tempo/api/echo", "echo")
    server.text("/alloy/-/ready", "Alloy is ready.")
    server.json(
        "/alloy/api/v0/web/components",
        [
            {
                "name": "loki.write",
                "localID": "loki.write.default",
                "health": {"state": "healthy"},
            }
        ],
    )
    server.json("/otel/", {"status": "Server available"})
    server.json(
        "/bao/v1/sys/health",
        {
            "initialized": True,
            "sealed": False,
            "standby": False,
            "version": "2.3.1",
            "cluster_name": "codestra-staging",
        },
    )
    server.text(
        "/node/metrics",
        '# TYPE node_exporter_build_info gauge\nnode_exporter_build_info{version="1.9.1"} 1\n',
    )
    server.text(
        "/cadvisor/metrics",
        '# TYPE cadvisor_version_info gauge\ncadvisor_version_info{cadvisorVersion="v0.52.1"} 1\n',
    )
    server.text("/redis/metrics", "# TYPE redis_up gauge\nredis_up 1\n")
    server.text("/pg/metrics", "# TYPE pg_up gauge\npg_up 1\n")
    server.text(
        "/bb/metrics",
        '# TYPE blackbox_exporter_build_info gauge\nblackbox_exporter_build_info{version="0.27.0"} 1\n',
    )
    server.json(
        "/mw/version",
        {
            "git_sha": "a" * 40,
            "image_digest": "sha256:" + "b" * 64,
            "schema_version": "0069_progressive_tenant_rls",
        },
    )
    yield server
    server.close()


def write_config(tmp_path: Path, fake: Fake, **overrides) -> Path:
    token = tmp_path / "middleware.token"
    token.write_text(FAKE_BEARER, encoding="utf-8")
    grafana = tmp_path / "grafana.token"
    grafana.write_text(GRAFANA_TOKEN, encoding="utf-8")
    components = [
        {
            "component": "prometheus",
            "service_id": "prometheus",
            "base_url": fake.base + "/prom",
            "expected_endpoint": "prometheus:9090",
            "authentication": "network-private",
            "contract_sha": "7c1e706" + "0" * 33,
        },
        {
            "component": "alertmanager",
            "service_id": "alertmanager",
            "base_url": fake.base + "/am",
        },
        {
            "component": "grafana",
            "service_id": "grafana",
            "base_url": fake.base + "/gf",
            "token_file": str(grafana),
            "authentication": "service-account-token-readonly",
        },
        {
            "component": "loki",
            "service_id": "loki",
            "base_url": fake.base + "/loki",
            "tenant_header": "codestra-staging",
        },
        {"component": "tempo", "service_id": "tempo", "base_url": fake.base + "/tempo"},
        {"component": "alloy", "service_id": "alloy", "base_url": fake.base + "/alloy"},
        {
            "component": "otel-gateway",
            "service_id": "otel-gateway",
            "base_url": fake.base + "/otel",
        },
        {
            "component": "openbao",
            "service_id": "openbao",
            "base_url": fake.base + "/bao",
            "expected_endpoint": "openbao:8200",
            "authentication": "oauth2-monitoring-readonly+mtls",
        },
        {
            "component": "node-exporter",
            "service_id": "node-exporter",
            "base_url": fake.base + "/node",
        },
        {
            "component": "cadvisor",
            "service_id": "cadvisor",
            "base_url": fake.base + "/cadvisor",
        },
        {
            "component": "redis-exporter",
            "service_id": "redis-exporter",
            "base_url": fake.base + "/redis",
        },
        {
            "component": "postgres-exporter",
            "service_id": "postgres-exporter",
            "base_url": fake.base + "/pg",
        },
        {
            "component": "blackbox",
            "service_id": "blackbox-exporter",
            "base_url": fake.base + "/bb",
        },
        {
            "component": "prometheus",
            "service_id": "middleware-integration-api",
            "base_url": fake.base + "/prom",
            "expected_endpoint": "middleware-integration-api:8095",
            "authentication": "oauth2-monitoring-readonly",
            "contract_sha": "281bb7a6f153917e5f7f98c81897bcc27cae4d34",
        },
    ]
    raw = {
        "environment": "staging",
        "source_deployment": "monitoring-collector-staging",
        "tenant": "codestra",
        "middleware": {"base_url": fake.base + "/mw", "token_file": str(token)},
        "state_dir": str(tmp_path / "state"),
        "components": components,
        "service_components": {
            c["service_id"]: [c["component"]]
            for c in components
            if c["service_id"] != "middleware-integration-api"
        },
        "version_endpoints": {"middleware-integration-api": fake.base + "/mw/version"},
    }
    raw.update(overrides)
    path = tmp_path / "collector.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_full_run_reads_actual_configuration_and_posts_observations(tmp_path, fake):
    config = CollectorConfig.load(write_config(tmp_path, fake))
    report = run(config, tmp_path / "out")

    components = report["components"]
    assert set(components) == {
        "prometheus",
        "alertmanager",
        "grafana",
        "loki",
        "tempo",
        "alloy",
        "otel-gateway",
        "openbao",
        "node-exporter",
        "cadvisor",
        "redis-exporter",
        "postgres-exporter",
        "blackbox",
    }
    assert all(components[name]["status"] == "observed" for name in components), (
        components
    )
    assert components["prometheus"]["config_digest"] == collector.digest_bytes(
        b"global:\n  scrape_interval: 15s\n"
    )
    assert components["alertmanager"]["config_digest"] == collector.digest_bytes(
        b"route:\n  receiver: middleware\n"
    )
    assert (
        components["prometheus"]["details"]["targets_up"] == 1
        and components["prometheus"]["details"]["targets_down"] == 1
    )
    assert components["grafana"]["details"] == {
        "datasources": 2,
        "dashboards": 2,
        "unhealthy_datasources": 1,
        "version": "11.6.0",
    }
    assert components["loki"]["details"] == {
        "label_names": 3,
        "label_names_bounded": True,
    }
    assert components["openbao"]["details"]["sealed"] is False
    assert 10 < components["prometheus"]["freshness_seconds"] < 60

    # every (service, component) posted one config observation with bounded headers and allowed data only
    observations = [
        p for p in fake.posts if p["path"] == "/mw/platform/v1/runtime/observations"
    ]
    assert len(observations) == 13
    for post in observations:
        body = post["body"]
        assert (
            body["kind"] == "config"
            and body["environment"] == "staging"
            and body["source_deployment"] == "monitoring-collector-staging"
        )
        assert (
            set(body["data"]) == {"component", "config_digest", "status"}
            and body["sequence"] == 1
        )
        assert collector.IDENTIFIER.fullmatch(
            post["headers"]["idempotency-key"]
        ) and collector.IDENTIFIER.fullmatch(post["headers"]["x-correlation-id"])
        assert post["headers"]["authorization"] == "Bearer " + FAKE_BEARER
    observed = [
        p for p in fake.posts if p["path"].endswith("/monitoring-state/observations")
    ]
    assert (
        len(observed) == 1
        and observed[0]["body"]["observed_git_sha"] == "a" * 40
        and observed[0]["body"]["observed_migration_head"]
        == "0069_progressive_tenant_rls"
    )
    assert (
        observed[0]["body"]["source"] == "monitoring-collector-staging"
        and observed[0]["body"]["status"] == "observed"
    )
    assert report["versions"]["middleware-integration-api"]["status"] == "observed"

    # Section 10 target records: expected vs actual endpoint, auth, scrape state, freshness, contract SHA
    records = {r["service_id"]: r for r in report["targets"]}
    mw = records["middleware-integration-api"]
    assert (
        mw["expected_endpoint"] == "middleware-integration-api:8095"
        and mw["actual_endpoint"] == "middleware-integration-api:8095"
        and mw["endpoint_matches"] is True
    )
    assert (
        mw["authentication"] == "oauth2-monitoring-readonly"
        and mw["scrape_status"] == "up"
        and mw["metric_freshness"] == "fresh"
        and mw["contract_sha"].startswith("281bb7a6")
    )
    bao = records["openbao"]
    assert (
        bao["scrape_status"] == "down"
        and bao["metric_freshness"] == "stale"
        and bao["endpoint_matches"] is True
    )
    assert (
        "[REDACTED]" in bao["scrape_error"] and FAKE_BEARER not in bao["scrape_error"]
    )

    # outputs on disk are redacted and sequence state persists
    written = (tmp_path / "out" / "collector-report.json").read_text(encoding="utf-8")
    assert (
        FAKE_BEARER not in written
        and GRAFANA_TOKEN not in written
        and "Bearer " not in written
    )
    assert "| middleware-integration-api | staging |" in (
        tmp_path / "out" / "target-records.md"
    ).read_text(encoding="utf-8")
    state = json.loads(
        (tmp_path / "state" / "sequence.json").read_text(encoding="utf-8")
    )
    assert state["staging:openbao:openbao"] == 1
    assert (
        report["middleware_mutated_runtime"] is False
        and report["secret_values_recorded"] is False
    )


def test_grafana_and_loki_requests_carry_their_read_only_credentials_only(
    tmp_path, fake
):
    config = CollectorConfig.load(write_config(tmp_path, fake))
    run(config, tmp_path / "out")
    by_path = {
        path.split("?")[0]: headers
        for method, path, headers, _ in fake.requests
        if method == "GET"
    }
    assert by_path["/gf/api/datasources"]["authorization"] == "Bearer " + GRAFANA_TOKEN
    assert by_path["/loki/loki/api/v1/labels"]["x-scope-orgid"] == "codestra-staging"
    assert "authorization" not in by_path["/prom/api/v1/status/config"]
    assert "authorization" not in by_path["/bao/v1/sys/health"]
    assert all(
        method == "GET"
        for method, path, _, _ in fake.requests
        if not path.startswith("/mw/")
    )


def test_sequence_is_monotonic_across_runs(tmp_path, fake):
    config = CollectorConfig.load(write_config(tmp_path, fake))
    run(config, tmp_path / "out")
    run(config, tmp_path / "out")
    sequences = [
        p["body"]["sequence"]
        for p in fake.posts
        if p["body"].get("resource_id") == "prometheus"
        and p["body"]["service_id"] == "prometheus"
    ]
    assert sequences == [1, 2]


def test_component_failure_is_reported_not_omitted(tmp_path, fake):
    fake.text(
        "/loki/ready",
        "Ingester not ready: waiting for 15s after being ready",
        status=503,
    )
    del fake.routes["/tempo/status/config"]
    config = CollectorConfig.load(write_config(tmp_path, fake))
    report = run(config, tmp_path / "out")
    assert (
        report["components"]["loki"]["status"] == "failed"
        and "503" in report["components"]["loki"]["error"]
    )
    assert (
        report["components"]["tempo"]["status"] == "failed"
        and "active configuration unavailable" in report["components"]["tempo"]["error"]
    )
    posted = {
        p["body"]["resource_id"]: p["body"]["data"]["status"]
        for p in fake.posts
        if p["path"] == "/mw/platform/v1/runtime/observations"
    }
    assert (
        posted["loki"] == "failed"
        and posted["tempo"] == "failed"
        and posted["prometheus"] == "observed"
    )


def test_sealed_openbao_is_failed_and_never_unsealed(tmp_path, fake):
    fake.json(
        "/bao/v1/sys/health",
        {"initialized": True, "sealed": True, "standby": False},
        status=503,
    )
    config = CollectorConfig.load(write_config(tmp_path, fake))
    report = run(config, tmp_path / "out")
    bao = report["components"]["openbao"]
    assert (
        bao["status"] == "failed"
        and bao["details"]["sealed"] is True
        and "never unseals" in bao["error"]
    )
    assert all(
        method == "GET"
        for method, path, _, _ in fake.requests
        if path.startswith("/bao/")
    )


def test_exporter_without_sentinel_metric_is_failed(tmp_path, fake):
    fake.text("/redis/metrics", "# TYPE go_goroutines gauge\ngo_goroutines 12\n")
    config = CollectorConfig.load(write_config(tmp_path, fake))
    report = run(config, tmp_path / "out")
    assert (
        report["components"]["redis-exporter"]["status"] == "failed"
        and "redis_up" in report["components"]["redis-exporter"]["error"]
    )


def test_middleware_unavailable_fails_closed_without_advancing_state(tmp_path, fake):
    path = write_config(
        tmp_path,
        fake,
        middleware={
            "base_url": "http://127.0.0.1:9",
            "token_file": str(tmp_path / "middleware.token"),
        },
    )
    config = CollectorConfig.load(path)
    with pytest.raises(CollectorError, match="middleware unreachable"):
        run(config, tmp_path / "out")
    assert not (tmp_path / "state" / "sequence.json").exists()
    assert not (tmp_path / "out" / "collector-report.json").exists()


def test_middleware_server_error_fails_closed(tmp_path, fake):
    fake.routes["/mw/platform/v1/runtime/observations"] = (500, b"boom", {})
    original = fake.server.RequestHandlerClass._serve

    def failing(self):
        if (
            self.command == "POST"
            and self.path == "/mw/platform/v1/runtime/observations"
        ):
            self._respond(500, b"{}", {})
            return
        original(self)

    fake.server.RequestHandlerClass._serve = failing
    fake.server.RequestHandlerClass.do_POST = failing
    config = CollectorConfig.load(write_config(tmp_path, fake))
    with pytest.raises(CollectorError, match="rejected observation with 500"):
        run(config, tmp_path / "out")


def test_missing_middleware_token_fails_closed(tmp_path, fake):
    path = write_config(
        tmp_path,
        fake,
        middleware={
            "base_url": fake.base + "/mw",
            "token_file": str(tmp_path / "absent.token"),
        },
    )
    config = CollectorConfig.load(path)
    with pytest.raises(CollectorError, match="token file is unavailable"):
        run(config, tmp_path / "out")
    assert not any(p["path"].startswith("/mw/") for p in fake.posts)


def test_redirects_are_refused(tmp_path, fake):
    fake.routes["/prom/-/ready"] = (302, b"", {"Location": "http://evil.example/steal"})
    config = CollectorConfig.load(write_config(tmp_path, fake))
    report = run(config, tmp_path / "out")
    assert (
        report["components"]["prometheus"]["status"] == "failed"
        and "redirect refused" in report["components"]["prometheus"]["error"]
    )
    assert not any("evil.example" in path for _, path, _, _ in fake.requests)


def test_no_post_mode_reads_only(tmp_path, fake):
    config = CollectorConfig.load(write_config(tmp_path, fake))
    report = run(config, tmp_path / "out", post=False)
    assert (
        report["posted"] == []
        and not fake.posts
        and not (tmp_path / "state" / "sequence.json").exists()
    )
    assert report["components"]["prometheus"]["status"] == "observed"


def test_secret_shaped_report_is_refused(tmp_path, fake):
    fake.json("/gf/api/health", {"database": "ok", "version": "hvs." + "Q" * 40})
    config = CollectorConfig.load(write_config(tmp_path, fake))
    with pytest.raises(CollectorError, match="secret-shaped"):
        run(config, tmp_path / "out")
    assert not (tmp_path / "out" / "collector-report.json").exists()


@pytest.mark.parametrize(
    "override, message",
    [
        ({"environment": "prod"}, "not governed"),
        ({"state_dir": "relative/state"}, "state_dir must be absolute"),
        ({"source_deployment": "bad value!"}, "bounded identifiers"),
    ],
)
def test_configuration_is_validated(tmp_path, fake, override, message):
    with pytest.raises(CollectorError, match=message):
        CollectorConfig.load(write_config(tmp_path, fake, **override))


def test_unknown_component_reader_is_rejected(tmp_path, fake):
    path = write_config(
        tmp_path,
        fake,
        components=[
            {"component": "kubernetes", "service_id": "k8s", "base_url": fake.base}
        ],
    )
    with pytest.raises(CollectorError, match="unknown component reader"):
        CollectorConfig.load(path)


def test_version_endpoint_values_are_shape_checked(tmp_path, fake):
    fake.json(
        "/mw/version",
        {
            "git_sha": "not-a-sha",
            "image_digest": "latest",
            "schema_version": "0069_progressive_tenant_rls",
        },
    )
    config = CollectorConfig.load(write_config(tmp_path, fake))
    run(config, tmp_path / "out")
    observed = [
        p for p in fake.posts if p["path"].endswith("/monitoring-state/observations")
    ]
    assert (
        observed[0]["body"].get("observed_git_sha") is None
        and "observed_image_digest" not in observed[0]["body"]
    )
    assert (
        observed[0]["body"]["observed_migration_head"]
        == "0069_progressive_tenant_rls"
    )


def test_cli_exit_codes(tmp_path, fake, capsys):
    config = write_config(tmp_path, fake)
    assert main(["--config", str(config), "--output", str(tmp_path / "out")]) == 0
    assert "MONITORING_COLLECTOR=PASS" in capsys.readouterr().out
    fake.text("/alloy/-/ready", "not ready", status=503)
    assert main(["--config", str(config), "--output", str(tmp_path / "out")]) == 2
    assert '"failed_components": ["alloy"]' in capsys.readouterr().out
    assert main(["--config", "relative.json", "--output", str(tmp_path / "out")]) == 3
    broken = write_config(
        tmp_path,
        fake,
        middleware={
            "base_url": "http://127.0.0.1:9",
            "token_file": str(tmp_path / "middleware.token"),
        },
    )
    assert main(["--config", str(broken), "--output", str(tmp_path / "out")]) == 3
    assert "MONITORING_COLLECTOR=FAIL" in capsys.readouterr().err
