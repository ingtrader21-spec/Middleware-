"""Behavioral coverage for all 36 operations with signed JWTs and real persistence."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import os
import importlib
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import jwt
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool
from alembic.migration import MigrationContext
from alembic.operations import Operations

from app.core.config import settings
from app.monitoring.backends import Backends, load_config, load_github_secret
from app.monitoring.routes import get_backends, get_session, router
from app.monitoring.store import metadata

DIGEST = "sha256:" + "a" * 64
SCOPES = " ".join(
    [
        "platform.services.read",
        "platform.services.write",
        "platform.sync.read",
        "platform.sync.reconcile",
        "platform.runtime.observe",
        "telemetry.heartbeat.write",
        "observability.health.read",
        "observability.metrics.read",
        "observability.logs.read",
        "observability.traces.read",
        "observability.backups.read",
        "observability.secrets.health.read",
        "observability.integrations.read",
        "observability.agents.read",
        "observability.campaigns.read",
        "observability.probes.run",
        "telemetry.browser.write",
    ]
)


@pytest.fixture
def system(tmp_path, monkeypatch):
    # The deployed entrypoint's lifespan builds the canonical domain runtime
    # from the environment; give it the explicit in-memory test runtime.
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ALLOW_IN_MEMORY_STORAGE", "true")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Keys:
        def __init__(self, *args, **kwargs):
            pass

        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=private.public_key())

    monkeypatch.setattr(jwt, "PyJWKClient", Keys)
    for k, v in {
        "keycloak_issuer": "https://identity.example.invalid/realms/test",
        "keycloak_audience": "middleware-api",
        "keycloak_jwks_url": "https://identity.example.invalid/realms/test/certs",
        "keycloak_authorized_parties": "operator,collector,browser-bff",
    }.items():
        monkeypatch.setattr(settings, k, v)

    def auth(
        role="platform_admin",
        tenant="codestra-platform",
        scope=SCOPES,
        campaigns=None,
        client="operator",
        **changes,
    ):
        now = datetime.now(UTC).timestamp()
        claims = {
            "iss": settings.keycloak_issuer,
            "aud": settings.keycloak_audience,
            "azp": client,
            "sub": client + "-subject",
            "iat": int(now),
            "exp": int(now) + 300,
            "tenant_id": tenant,
            "scope": scope,
            "realm_access": {"roles": [role]},
            "campaigns": campaigns if campaigns is not None else ["campaign-one"],
            "services": ["sample-api"],
        }
        claims.update(changes)
        return {
            "Authorization": "Bearer " + jwt.encode(claims, private, algorithm="RS256"),
            "X-Correlation-ID": "test-correlation",
            "Idempotency-Key": str(uuid4()),
        }

    artifact = tmp_path / "openapi.json"
    artifact.write_text(
        json.dumps(
            {
                "openapi": "3.1.0",
                "paths": {
                    "/orders": {"get": {"operationId": "listOrders"}},
                    "/health": {"get": {"operationId": "health"}},
                },
            }
        )
    )
    artifact_digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    secret = tmp_path / "github-secret"
    secret.write_text("synthetic-github-secret-for-tests-0000")
    config = {
        "schema_version": 1,
        "revision": "release-test-1",
        "artifact_root": str(tmp_path),
        "repositories": [
            {
                "repository": "ingtrader21-spec/Middleware-",
                "tenant": "codestra-platform",
                "group": "platform",
            }
        ],
        "services": {
            "sample-api": {
                "tenant": "codestra-platform",
                "repository": "ingtrader21-spec/Middleware-",
                "environments": ["production"],
                "dependencies": [],
                "required_signals": ["metrics", "logs", "traces"],
                "approved_config_digest": DIGEST,
                "required_components": ["prometheus"],
                "observation_sources": {
                    "release-a": {"client": "collector", "environments": ["production"]}
                },
                "browser_bff_clients": ["browser-bff"],
                "browser_origins": ["https://app.example.invalid"],
            }
        },
        "artifacts": {
            "sample-openapi": {
                "path": "openapi.json",
                "service_id": "sample-api",
                "environment": "production",
                "sha256": artifact_digest,
            }
        },
        "github": {"secret_file": str(secret)},
        "backends": {
            x: {
                "base_url": "https://" + x + ".example.invalid",
                "tenant_map": {"codestra-platform": "platform-tenant"},
            }
            for x in [
                "prometheus",
                "loki",
                "tempo",
                "openbao",
                "blackbox",
                "backstage",
                "sentry",
                "wazuh",
            ]
        },
        "queries": {
            x: {
                "family": x,
                "services": ["sample-api"],
                "query": "metric{tenant=${tenant},service=${service},environment=${environment}}",
            }
            for x in ["metrics", "metrics-range", "logs", "traces-search"]
        },
        "probe_targets": {
            "sample-health": {
                "service_id": "sample-api",
                "environment": "production",
                "url": "https://app.example.invalid/health",
                "module": "http_2xx",
            }
        },
        "integrations": {
            "backstage": {"service_id": "sample-api", "backend": "backstage"},
            "sentry": {
                "service_id": "sample-api",
                "backend": "sentry",
                "organization": "codestra",
                "project": "sample",
            },
            "wazuh": {"service_id": "sample-api", "backend": "wazuh"},
        },
    }
    calls = []

    def backend(request):
        calls.append(request)
        host = request.url.host
        if host.startswith("prometheus"):
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {"metric": {"service": "sample-api"}, "value": ["1", "2"]}
                        ],
                    },
                },
            )
        if host.startswith("loki"):
            assert request.headers["X-Scope-OrgID"] == "platform-tenant"
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {"result": [{"values": [["1", "sanitized log"]]}]},
                },
            )
        if host.startswith("tempo"):
            assert request.headers["X-Scope-OrgID"] == "platform-tenant"
            return httpx.Response(
                200, json={"traces": [{"traceID": "a" * 32}], "resourceSpans": []}
            )
        if host.startswith("openbao"):
            return httpx.Response(
                503,
                json={"sealed": True, "initialized": True, "token": "must-not-return"},
            )
        if host.startswith("blackbox"):
            return httpx.Response(200, text="probe_success 1\n")
        if host.startswith("backstage"):
            return httpx.Response(
                200, json={"items": [{"kind": "Component"}], "pageInfo": {}}
            )
        if host.startswith("sentry"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "one",
                        "status": "unresolved",
                        "count": "2",
                        "email": "private@example.com",
                    }
                ],
            )
        if host.startswith("wazuh"):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [{"id": "001", "status": "active"}],
                        "total_affected_items": 1,
                    }
                },
            )
        raise AssertionError(request.url)

    database_url = os.getenv(
        "MONITORING_TEST_DATABASE_URL"
    ) or "sqlite+aiosqlite:///" + str(tmp_path / "monitoring.db")
    if database_url.startswith("postgresql"):
        assert (make_url(database_url).database or "").startswith("monitoring_test"), (
            "disposable monitoring_test database required"
        )
    engine = create_async_engine(database_url, poolclass=NullPool)

    def apply_migration(connection):
        with Operations.context(MigrationContext.configure(connection)):
            importlib.import_module(
                "migrations.versions.0059_integrated_monitoring"
            ).upgrade()

    async def create():
        async with engine.begin() as connection:
            await connection.run_sync(apply_migration)

    asyncio.run(create())
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def db():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_session] = db
    monkeypatch.setattr("app.monitoring.artifacts.load_config", lambda: config)
    app.dependency_overrides[load_config] = lambda: config
    app.dependency_overrides[load_github_secret] = lambda: secret.read_bytes().strip()
    app.dependency_overrides[get_backends] = lambda: Backends(
        config, httpx.MockTransport(backend)
    )
    with TestClient(app) as client:
        yield SimpleNamespace(
            client=client,
            auth=auth,
            config=config,
            calls=calls,
            app=app,
            engine=engine,
            sessions=sessions,
            artifact=artifact,
            artifact_digest=artifact_digest,
            secret=secret,
        )

    async def cleanup():
        async with engine.begin() as connection:
            await connection.run_sync(metadata.drop_all)
        await engine.dispose()

    asyncio.run(cleanup())


def observation(kind, resource="test-resource", sequence=1, campaign=None, data=None):
    return {
        "kind": kind,
        "resource_id": resource,
        "service_id": "sample-api",
        "environment": "production",
        "source_deployment": "release-a",
        "sequence": sequence,
        "observed_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        "campaign_id": campaign,
        "data": data or {"status": "healthy"},
    }


def test_all_36_operations_have_working_success_paths(system):
    s = system
    c = s.client
    covered = set()

    def call(method, path, body=None, headers=None, **kwargs):
        response = c.request(
            method, path, json=body, headers=headers or s.auth(), **kwargs
        )
        assert response.status_code == 200, (method, path, response.text)
        route = next(
            r
            for r in router.routes
            if method in r.methods and r.path_regex.fullmatch(path.split("?")[0])
        )
        covered.add((method, route.path))
        return response

    for kind, data, campaign in [
        (
            "host",
            {"host_id": "host-one", "hostname": "host-one", "status": "healthy"},
            None,
        ),
        (
            "deployment",
            {"git_sha": "b" * 40, "image_digest": DIGEST, "status": "running"},
            None,
        ),
        ("health", {"liveness": True, "readiness": True, "status": "healthy"}, None),
        (
            "integration",
            {
                "source_service": "sample-api",
                "target_service": "sample-api",
                "transport": "connected",
            },
            None,
        ),
        (
            "agent",
            {
                "agent_id": "agent-one",
                "username": "ralph",
                "active": True,
                "presence": "available",
            },
            "campaign-one",
        ),
        (
            "campaign",
            {"campaign_id": "campaign-one", "active_agents": 1, "status": "healthy"},
            "campaign-one",
        ),
        ("certificate", {"hostname": "app.example.invalid", "status": "valid"}, None),
        ("backup", {"backup_id": "backup-one", "restore_verified": True}, None),
        ("slo", {"slo_id": "availability", "target": 99.9, "actual": 99.95}, None),
        ("dashboard", {"dashboard_id": "operations", "title": "Operations"}, None),
        ("config", {"component": "prometheus", "config_digest": DIGEST}, None),
    ]:
        call(
            "POST",
            "/platform/v1/runtime/observations",
            observation(kind, data=data, campaign=campaign),
            s.auth(role="monitoring_collector", client="collector"),
        )
    heart = {
        "service_id": "sample-api",
        "environment": "production",
        "source_deployment": "release-a",
        "sequence": 1,
        "observed_at": datetime.now(UTC).isoformat(),
        "signals": ["metrics", "logs", "traces"],
    }
    call(
        "POST",
        "/platform/v1/telemetry/heartbeats",
        heart,
        s.auth(role="monitoring_collector", client="collector"),
    )
    call(
        "POST",
        "/platform/v1/services/sample-api/telemetry-profile",
        {
            "environment": "production",
            "expected_revision": 0,
            "config_digest": DIGEST,
            "metrics_owner": "prometheus",
            "logs_owner": "alloy",
            "traces_owner": "otel",
        },
    )
    imported = call(
        "POST",
        "/platform/v1/services/sample-api/contract-refresh",
        {
            "environment": "production",
            "expected_revision": 0,
            "artifact_id": "sample-openapi",
            "sha256": s.artifact_digest,
        },
    )
    assert imported.json()["data"]["endpoint_count"] == 2
    reconciliation = call(
        "POST",
        "/platform/v1/sync/reconciliations",
        {"environment": "production", "service_ids": ["sample-api"]},
    ).json()["data"]
    assert reconciliation["results"][0]["state"] == "synced"
    assert reconciliation["results"][0]["component_states"] == {"prometheus": "synced"}
    probe = call(
        "POST",
        "/v1/observability/probe-runs",
        {
            "service_id": "sample-api",
            "environment": "production",
            "target_id": "sample-health",
        },
    ).json()["data"]
    assert probe["success"] is True
    paths = [
        "/platform/v1/repositories",
        "/platform/v1/hosts",
        "/platform/v1/hosts/host-one",
        *[
            "/platform/v1/services/sample-api/" + x
            for x in ["deployments", "endpoints", "dependencies", "coverage"]
        ],
        "/platform/v1/sync/status",
        "/platform/v1/sync/reconciliations/" + reconciliation["operation_id"],
        "/v1/observability/overview",
        "/v1/observability/services/sample-api/health",
        "/v1/observability/topology",
        "/v1/observability/traces/" + "a" * 32,
        *[
            "/v1/observability/" + x
            for x in [
                "slo",
                "dashboards",
                "certificates",
                "backups",
                "secrets/health",
                "integrations",
                "integrations/backstage",
                "agents",
                "campaigns/campaign-one",
                "events/stream",
            ]
        ],
        "/v1/observability/probe-runs/" + probe["operation_id"],
    ]
    for path in paths:
        call("GET", path)
    for path, family in [
        ("metrics/query", "metrics"),
        ("metrics/query-range", "metrics-range"),
        ("logs/query", "logs"),
        ("traces/search", "traces-search"),
    ]:
        call(
            "POST",
            "/v1/observability/" + path,
            {
                "service_id": "sample-api",
                "environment": "production",
                "query_id": family,
            },
        )
    event = {
        "repository": {"full_name": "ingtrader21-spec/Middleware-"},
        "after": "b" * 40,
    }
    raw = json.dumps(event).encode()
    gh = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": str(uuid4()),
        "X-Hub-Signature-256": "sha256="
        + hmac.new(s.secret.read_bytes(), raw, hashlib.sha256).hexdigest(),
        "Content-Type": "application/json",
    }
    response = call(
        "POST", "/platform/v1/integrations/github/events", headers=gh, content=raw
    )
    assert response.json()["data"]["deployment_authorized"] is False
    browser = s.auth(role="browser_ingest", client="browser-bff")
    browser["Origin"] = "https://app.example.invalid"
    call(
        "POST",
        "/v1/telemetry/browser-events",
        {
            "service_id": "sample-api",
            "environment": "production",
            "event_id": "event-one",
            "event_type": "performance",
            "release": "release-one",
            "route_template": "/orders/{id}",
            "metric": "lcp_ms",
            "value": 100,
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        browser,
    )
    assert covered == {(m, r.path) for r in router.routes for m in r.methods}
    assert len(covered) == 36


@pytest.mark.parametrize(
    "name,expected",
    [
        ("backstage", "catalog_entities"),
        ("sentry", "unresolved_issues_in_page"),
        ("wazuh", "total_agents"),
    ],
)
def test_new_component_adapters(system, name, expected):
    response = system.client.get(
        "/v1/observability/integrations/" + name, headers=system.auth()
    )
    assert response.status_code == 200
    assert response.json()["data"][expected] == 1
    assert "private@example.com" not in response.text


def test_signature_scope_and_tenant_enforcement(system):
    c = system.client
    assert c.get("/v1/observability/overview").status_code == 401
    assert (
        c.get(
            "/v1/observability/overview",
            headers=system.auth(scope="platform.services.read"),
        ).status_code
        == 403
    )
    assert (
        c.get(
            "/v1/observability/overview", headers=system.auth(tenant="other-tenant")
        ).json()["data"]["registered_services"]
        == 0
    )
    assert (
        c.get(
            "/platform/v1/services/sample-api/dependencies",
            headers=system.auth(tenant="other-tenant"),
        ).status_code
        == 404
    )
    token = system.auth()
    token["Authorization"] = token["Authorization"][:-12] + "not-valid"
    assert c.get("/v1/observability/overview", headers=token).status_code == 403
    assert (
        c.get("/v1/observability/overview", headers=system.auth(exp=1)).status_code
        == 403
    )


def test_campaigns_are_enforced_in_database_queries_and_stream(system):
    s = system
    for campaign in ["campaign-one", "campaign-two"]:
        body = observation(
            "agent",
            resource=campaign,
            campaign=campaign,
            data={"agent_id": campaign, "username": campaign, "active": True},
        )
        response = s.client.post(
            "/platform/v1/runtime/observations",
            json=body,
            headers=s.auth(
                role="monitoring_collector", client="collector", campaigns=[campaign]
            ),
        )
        assert response.status_code == 200, response.text
    supervisor = s.auth(role="campaign_supervisor", campaigns=["campaign-one"])
    result = s.client.get("/v1/observability/agents", headers=supervisor)
    assert [r["username"] for r in result.json()["data"]] == ["campaign-one"]
    assert (
        s.client.get(
            "/v1/observability/agents?campaign_id=campaign-two", headers=supervisor
        ).status_code
        == 403
    )
    assert (
        s.client.get(
            "/v1/observability/campaigns/campaign-two", headers=supervisor
        ).status_code
        == 403
    )
    stream = s.client.get("/v1/observability/events/stream", headers=supervisor)
    assert "campaign-two" not in stream.text
    assert (
        s.client.get("/v1/observability/metrics/query", headers=supervisor).status_code
        == 405
    )


def test_replay_stale_observation_and_failed_transaction(system):
    s = system
    h = s.auth(role="monitoring_collector", client="collector")
    body = observation("health")
    first = s.client.post("/platform/v1/runtime/observations", json=body, headers=h)
    replay = s.client.post("/platform/v1/runtime/observations", json=body, headers=h)
    assert first.status_code == 200 and replay.json()["data"] == first.json()["data"]
    changed = {**body, "data": {"status": "failed"}}
    assert (
        s.client.post(
            "/platform/v1/runtime/observations", json=changed, headers=h
        ).status_code
        == 409
    )
    assert (
        s.client.post(
            "/platform/v1/runtime/observations",
            json=body,
            headers=s.auth(role="monitoring_collector", client="collector"),
        ).status_code
        == 409
    )
    latest = s.client.get(
        "/v1/observability/services/sample-api/health", headers=s.auth()
    ).json()["data"]
    assert latest[0]["status"] == "healthy" and latest[0]["revision"] == 1
    # Database persistence survives another client/session; no in-memory store.
    with TestClient(s.app) as second:
        assert (
            second.get(
                "/v1/observability/services/sample-api/health", headers=s.auth()
            ).json()["data"][0]["revision"]
            == 1
        )


def test_profile_cas_artifact_binding_and_drift(system):
    s = system
    c = s.client
    profile = {
        "environment": "production",
        "expected_revision": 0,
        "config_digest": DIGEST,
        "metrics_owner": "prometheus",
        "logs_owner": "alloy",
        "traces_owner": "otel",
    }
    assert (
        c.post(
            "/platform/v1/services/sample-api/telemetry-profile",
            json=profile,
            headers=s.auth(),
        ).status_code
        == 200
    )
    assert (
        c.post(
            "/platform/v1/services/sample-api/telemetry-profile",
            json=profile,
            headers=s.auth(),
        ).status_code
        == 409
    )
    profile.update(expected_revision=1, config_digest="sha256:" + "b" * 64)
    assert (
        c.post(
            "/platform/v1/services/sample-api/telemetry-profile",
            json=profile,
            headers=s.auth(),
        ).status_code
        == 200
    )
    state = c.get("/platform/v1/sync/status", headers=s.auth()).json()["data"][0]
    assert state["state"] == "pending-release-approval"
    body = {
        "environment": "production",
        "expected_revision": 0,
        "artifact_id": "sample-openapi",
        "sha256": s.artifact_digest,
    }
    s.artifact.write_text('{"openapi":"3.1.0","paths":{}}')
    assert (
        c.post(
            "/platform/v1/services/sample-api/contract-refresh",
            json=body,
            headers=s.auth(),
        ).status_code
        == 422
    )


def test_missing_stale_data_is_not_success(system):
    s = system
    initial = s.client.get(
        "/v1/observability/services/sample-api/health", headers=s.auth()
    ).json()
    assert initial["freshness"] == "unknown" and initial["data"] == []
    body = observation("health")
    body["observed_at"] = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    assert (
        s.client.post(
            "/platform/v1/runtime/observations",
            json=body,
            headers=s.auth(role="monitoring_collector", client="collector"),
        ).status_code
        == 200
    )
    assert (
        s.client.get(
            "/v1/observability/services/sample-api/health", headers=s.auth()
        ).json()["freshness"]
        == "stale"
    )
    s.config["backends"].pop("prometheus")
    assert (
        s.client.post(
            "/v1/observability/metrics/query",
            json={
                "service_id": "sample-api",
                "environment": "production",
                "query_id": "metrics",
            },
            headers=s.auth(),
        ).status_code
        == 503
    )


def test_query_template_tenant_headers_and_budgets(system):
    s = system
    c = s.client
    body = {
        "service_id": "sample-api",
        "environment": "production",
        "query_id": "metrics",
    }
    assert (
        c.post(
            "/v1/observability/metrics/query", json=body, headers=s.auth()
        ).status_code
        == 200
    )
    q = s.calls[-1].url.params["query"]
    assert 'tenant="codestra-platform"' in q and 'service="sample-api"' in q
    assert (
        c.post(
            "/v1/observability/metrics/query",
            json={**body, "query": "arbitrary"},
            headers=s.auth(),
        ).status_code
        == 422
    )
    assert (
        c.post(
            "/v1/observability/metrics/query",
            json={**body, "query_id": "unknown"},
            headers=s.auth(),
        ).status_code
        == 422
    )
    end = datetime.now(UTC)
    assert (
        c.post(
            "/v1/observability/metrics/query",
            json={
                **body,
                "start": (end - timedelta(days=8)).isoformat(),
                "end": end.isoformat(),
            },
            headers=s.auth(),
        ).status_code
        == 422
    )
    s.config["backends"]["tempo"]["tenant_map"] = {}
    assert (
        c.get("/v1/observability/traces/" + "a" * 32, headers=s.auth()).status_code
        == 403
    )


def test_webhooks_origin_source_and_sensitive_fields(system):
    s = system
    c = s.client
    assert (
        c.post(
            "/platform/v1/integrations/github/events",
            content=b"{}",
            headers={"X-Hub-Signature-256": "sha256=bad"},
        ).status_code
        == 403
    )
    body = observation("health", data={"status": "healthy", "password": "bad"})
    assert (
        c.post(
            "/platform/v1/runtime/observations",
            json=body,
            headers=s.auth(role="monitoring_collector", client="collector"),
        ).status_code
        == 422
    )
    body = observation("health")
    body["source_deployment"] = "unbound"
    assert (
        c.post(
            "/platform/v1/runtime/observations",
            json=body,
            headers=s.auth(role="monitoring_collector", client="collector"),
        ).status_code
        == 403
    )
    data = c.get("/v1/observability/secrets/health", headers=s.auth()).json()["data"]
    assert data == {"initialized": True, "sealed": True}
    browser = {
        "service_id": "sample-api",
        "environment": "production",
        "event_id": "one",
        "event_type": "error",
        "release": "one",
        "route_template": "/orders",
        "metric": "error_count",
        "value": 1,
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    assert (
        c.post(
            "/v1/telemetry/browser-events",
            json=browser,
            headers=s.auth(role="browser_ingest", client="browser-bff"),
        ).status_code
        == 403
    )


@pytest.mark.parametrize("failure", ["timeout", "redirect", "oversized", "bad-json"])
def test_backend_failure_is_bounded_and_explicit(system, failure):
    def fail(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("backend timeout")
        if failure == "redirect":
            return httpx.Response(
                302, headers={"Location": "https://elsewhere.invalid"}
            )
        if failure == "oversized":
            return httpx.Response(200, content=b"x" * (2 * 1024 * 1024 + 1))
        return httpx.Response(200, content=b"invalid json")

    system.app.dependency_overrides[get_backends] = lambda: Backends(
        system.config, httpx.MockTransport(fail)
    )
    response = system.client.post(
        "/v1/observability/metrics/query",
        json={
            "service_id": "sample-api",
            "environment": "production",
            "query_id": "metrics",
        },
        headers=system.auth(),
    )
    assert response.status_code in {502, 503}


@pytest.mark.parametrize("module", ["app.main", "app.entrypoints.integration_api"])
def test_existing_entrypoints_use_jwt_route_auth_without_shared_secret(system, module):
    import importlib

    target = importlib.import_module(module).app
    target.dependency_overrides[load_config] = lambda: system.config
    try:
        with TestClient(target) as client:
            response = client.get("/platform/v1/repositories", headers=system.auth())
            assert response.status_code == 200, response.text
            response = client.get("/v1/observability/topology", headers=system.auth())
            assert response.status_code == 200, response.text
            assert (
                client.get(
                    "/v1/observability/topology",
                    headers={"Authorization": "Bearer shared-secret"},
                ).status_code
                == 403
            )
            assert client.get("/v1/observability/topology").status_code == 401
    finally:
        target.dependency_overrides.clear()


def test_openapi_matches_original_36_operation_inventory(system):
    source = (
        Path(__file__).resolve().parents[1]
        / "contracts/observability/integrated-monitoring.v1.json"
    )
    expected = {
        (a["method"], a["path"]) for a in json.loads(source.read_text())["operations"]
    }
    actual = {
        (m.upper(), p)
        for p, item in system.app.openapi()["paths"].items()
        for m in item
        if m in {"get", "post"}
    }
    assert actual == expected and len(actual) == 36


def test_canonical_factory_exposes_verified_monitoring(system, test_settings, runtime):
    from app.appolon_factory import create_app

    target = create_app(settings=test_settings, runtime=runtime)
    target.dependency_overrides[load_config] = lambda: system.config
    with TestClient(target) as client:
        assert (
            client.get("/platform/v1/repositories", headers=system.auth()).status_code
            == 200
        )
        assert (
            client.get("/v1/observability/topology", headers=system.auth()).status_code
            == 200
        )
        assert client.get("/v1/observability/topology").status_code == 401


def test_concurrent_duplicate_has_one_durable_effect(system):
    from app.monitoring.auth import Principal
    from app.monitoring.store import Store, events, operations
    from sqlalchemy import select, func

    principal = Principal(
        "collector",
        "codestra-platform",
        frozenset(),
        frozenset(),
        frozenset(),
        "collector",
    )

    async def run():
        async def submit():
            async with system.sessions() as session:
                store = Store(session)

                async def action(operation_id):
                    await store.event(
                        principal.tenant,
                        "concurrency.test",
                        {"operation_id": operation_id},
                    )
                    return {"state": "recorded"}

                return await store.mutate(
                    principal, "concurrency", "same-key", {"input": 1}, action
                )

        results = await asyncio.gather(submit(), submit())
        assert results[0] == results[1]
        async with system.sessions() as session:
            assert (
                await session.scalar(select(func.count()).select_from(operations)) == 1
            )
            assert await session.scalar(select(func.count()).select_from(events)) == 1

    asyncio.run(run())


def test_ingress_budget_and_backend_error_are_not_success(system):
    response = system.client.post(
        "/platform/v1/runtime/observations", content=b"x" * 65537, headers=system.auth()
    )
    assert response.status_code == 413
    system.app.dependency_overrides[get_backends] = lambda: Backends(
        system.config,
        httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"status": "error", "error": "failure"}
            )
        ),
    )
    response = system.client.post(
        "/v1/observability/logs/query",
        json={
            "service_id": "sample-api",
            "environment": "production",
            "query_id": "logs",
        },
        headers=system.auth(),
    )
    assert response.status_code == 503


def test_empty_migration_downgrade_and_reupgrade(system):
    from sqlalchemy import inspect

    def rehearsal(connection):
        migration = importlib.import_module(
            "migrations.versions.0059_integrated_monitoring"
        )
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
            assert not set(metadata.tables).intersection(
                inspect(connection).get_table_names()
            )
            migration.upgrade()
            assert set(metadata.tables).issubset(inspect(connection).get_table_names())

    async def run():
        async with system.engine.begin() as connection:
            await connection.run_sync(rehearsal)

    asyncio.run(run())


def test_downgrade_cannot_delete_observation_evidence(system):
    response = system.client.post(
        "/platform/v1/runtime/observations",
        json=observation("host", data={"host_id": "retained"}),
        headers=system.auth(role="monitoring_collector", client="collector"),
    )
    assert response.status_code == 200

    def downgrade(connection):
        with Operations.context(MigrationContext.configure(connection)):
            importlib.import_module(
            "migrations.versions.0059_integrated_monitoring"
            ).downgrade()

    async def run():
        with pytest.raises(RuntimeError, match="evidence is nonempty"):
            async with system.engine.begin() as connection:
                await connection.run_sync(downgrade)

    asyncio.run(run())
    response = system.client.get("/platform/v1/hosts/retained", headers=system.auth())
    assert response.status_code == 200


def test_host_lookup_filters_before_pagination(system):
    from sqlalchemy import insert
    from app.monitoring.store import resources

    async def seed():
        now = datetime.now(UTC)
        rows = [
            dict(
                tenant="codestra-platform",
                kind="host",
                resource_key=f"host-{i:04d}",
                service_id="sample-api",
                environment="production",
                campaign_id=None,
                source_deployment="release-a",
                sequence=1,
                revision=1,
                observed_at=now,
                payload={"host_id": "target" if i >= 1001 else "other"},
            )
            for i in range(1004)
        ]
        rows.append(
            {**rows[-1], "tenant": "another-tenant", "resource_key": "host-foreign"}
        )
        async with system.engine.begin() as connection:
            await connection.execute(insert(resources), rows)

    asyncio.run(seed())
    response = system.client.get(
        "/platform/v1/hosts/target", params={"limit": 2}, headers=system.auth()
    )
    assert response.status_code == 200
    page = response.json()
    assert [r["resource_id"] for r in page["data"]] == ["host-1001", "host-1002"]
    response = system.client.get(
        "/platform/v1/hosts/target",
        params={"limit": 2, "cursor": page["next_cursor"]},
        headers=system.auth(),
    )
    assert [r["resource_id"] for r in response.json()["data"]] == ["host-1003"]
    assert response.json()["next_cursor"] is None
    assert (
        system.client.get(
            "/platform/v1/hosts/absent", headers=system.auth()
        ).status_code
        == 404
    )


def test_generic_integration_details_isolate_resource_identity(system):
    for name in ("queue-one", "queue-two", "prefix:queue-one"):
        system.config["integrations"][name] = {
            "service_id": "sample-api",
            "backend": "queue",
        }
        response = system.client.post(
            "/platform/v1/runtime/observations",
            json=observation("integration", resource=name, data={"queue_depth": 1}),
            headers=system.auth(role="monitoring_collector", client="collector"),
        )
        assert response.status_code == 200
    response = system.client.get(
        "/v1/observability/integrations/queue-one", headers=system.auth()
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert len(data) == 1
    assert data[0]["resource_id"] == "production:sample-api:release-a:queue-one"


def test_alembic_tracks_monitoring_tables_and_indexes(system):
    from alembic.autogenerate import compare_metadata
    from alembic.config import Config
    from alembic.runtime.environment import EnvironmentContext
    from alembic.script import ScriptDirectory

    def check(connection):
        config = Config()
        config.set_main_option(
            "script_location", str(Path(__file__).parents[1] / "migrations")
        )
        config.attributes["connection"] = connection
        script = ScriptDirectory.from_config(config)
        seen = []

        def inspect_environment(revision, context):
            seen.extend(context.opts["target_metadata"])
            return []

        # The application Alembic environment owns PostgreSQL's public schema;
        # SQLite exercises the isolated monitoring migration and index model.
        if connection.dialect.name == "postgresql":
            with EnvironmentContext(config, script, fn=inspect_environment):
                script.run_env()
            assert metadata in seen
        context = MigrationContext.configure(connection)
        assert compare_metadata(context, metadata) == []

    async def run():
        async with system.engine.begin() as connection:
            await connection.run_sync(check)

    asyncio.run(run())


def test_release_artifact_reader_accepts_nested_regular_files(tmp_path):
    from app.monitoring.artifacts import read_artifact

    directory = tmp_path / "contracts"
    directory.mkdir()
    content = b'{"openapi":"3.1.0","paths":{}}'
    (directory / "api.json").write_bytes(content)
    expected = "sha256:" + hashlib.sha256(content).hexdigest()
    assert read_artifact(str(tmp_path), "contracts/api.json", expected) == content
    with pytest.raises(ValueError, match="digest mismatch"):
        read_artifact(str(tmp_path), "contracts/api.json", DIGEST)


def test_release_artifact_reader_rejects_links_and_oversized_files(tmp_path):
    from app.monitoring.artifacts import read_artifact
    from app.monitoring.backends import MAX_RESPONSE_BYTES

    artifact = tmp_path / "api.json"
    artifact.write_bytes(b"{}")
    expected = "sha256:" + hashlib.sha256(b"{}").hexdigest()
    link = tmp_path / "linked.json"
    link.symlink_to(artifact)
    with pytest.raises((OSError, ValueError)):
        read_artifact(str(tmp_path), "linked.json", expected)
    artifact.write_bytes(b"x" * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(ValueError, match="size limit"):
        read_artifact(str(tmp_path), "api.json", expected)


def test_webhook_secret_uses_mounted_release_configuration(tmp_path, monkeypatch):
    secret = tmp_path / "webhook-key"
    value = b"synthetic-webhook-key-for-isolated-tests"
    secret.write_bytes(value + b"\n")
    config = tmp_path / "release.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "revision": "test",
                "services": {},
                "github": {"secret_file": str(secret)},
            }
        )
    )
    monkeypatch.setenv("MONITORING_CONFIG_FILE", str(config))
    assert load_github_secret() == value


@pytest.mark.parametrize("size", [8, 8193])
def test_webhook_secret_rejects_invalid_length(tmp_path, monkeypatch, size):
    from fastapi import HTTPException

    secret = tmp_path / "webhook-key"
    secret.write_bytes(b"x" * size)
    config = tmp_path / "release.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "revision": "test",
                "services": {},
                "github": {"secret_file": str(secret)},
            }
        )
    )
    monkeypatch.setenv("MONITORING_CONFIG_FILE", str(config))
    with pytest.raises(HTTPException) as error:
        load_github_secret()
    assert error.value.status_code == 503
