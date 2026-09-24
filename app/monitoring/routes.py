"""The 36 integrated monitoring operations, all registered on real entrypoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import re
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_session
from .auth import Principal, READ_ROLES, require
from .artifacts import read_approved_artifact
from .backends import Backends, load_config, load_github_secret, redact, service_for
from .models import (
    BrowserEvent,
    ContractRefresh,
    Envelope,
    Heartbeat,
    Observation,
    ProbeRequest,
    Profile,
    QueryRequest,
    Reconciliation,
)
from .store import Store, utc


class MonitoringRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def bounded(request: Request):
            if request.method == "POST":
                raw = bytearray()
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise HTTPException(413, "monitoring request exceeds 64 KiB")
                # Cache the exact raw body for FastAPI validation and HMAC verification.
                request._body = bytes(raw)
            return await handler(request)

        return bounded


router = APIRouter(tags=["integrated-monitoring"], route_class=MonitoringRoute)
ADMIN = frozenset({"platform_admin"})
COLLECTOR = frozenset({"monitoring_collector"})
CAMPAIGN_READ = READ_ROLES | {"campaign_supervisor"}
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


async def get_store(db=Depends(get_session)):
    try:
        yield Store(db)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            503, "monitoring persistence unavailable; verify migration 0059"
        ) from None


def get_backends(config=Depends(load_config)):
    return Backends(config)


def headers(request: Request):
    key = request.headers.get("Idempotency-Key", "")
    correlation = request.headers.get("X-Correlation-ID", "")
    if not ID.fullmatch(key) or not ID.fullmatch(correlation):
        raise HTTPException(
            422, "bounded Idempotency-Key and X-Correlation-ID required"
        )
    return key, correlation


def envelope(request, data, observed=None, revision=None, freshness=None, cursor=None):
    observed = utc(observed) if observed else None
    status = freshness or (
        "unknown"
        if observed is None
        else "stale"
        if datetime.now(UTC) - observed > timedelta(seconds=90)
        else "fresh"
    )
    return dict(
        data=data,
        observed_at=observed.isoformat() if observed else None,
        freshness=status,
        source_revision=revision,
        correlation_id=getattr(request.state, "correlation_id", None)
        or request.headers.get("X-Correlation-ID")
        or str(uuid4()),
        next_cursor=cursor,
    )


def row_data(row):
    return {
        "resource_id": row["resource_key"],
        "service_id": row["service_id"],
        "environment": row["environment"],
        "campaign_id": row["campaign_id"],
        "observed_at": utc(row["observed_at"]).isoformat(),
        "revision": row["revision"],
        **row["payload"],
    }


async def resource_page(
    request,
    store,
    principal,
    kind,
    *,
    service=None,
    environment=None,
    host_id=None,
    resource_id=None,
    campaign=None,
    cursor="",
    limit=100,
):
    campaigns = None
    if "campaign_supervisor" in principal.roles and not principal.roles.intersection(
        READ_ROLES
    ):
        principal.check_campaign(campaign)
        campaigns = {campaign} if campaign else principal.campaigns
    elif campaign:
        campaigns = {campaign}
    rows = await store.list(
        principal.tenant,
        kind,
        service=service,
        environment=environment,
        host_id=host_id,
        resource_id=resource_id,
        campaigns=campaigns,
        cursor=cursor,
        limit=limit + 1,
    )
    more = len(rows) > limit
    rows = rows[:limit]
    return envelope(
        request,
        [row_data(r) for r in rows],
        min((r["observed_at"] for r in rows), default=None),
        cursor=rows[-1]["resource_key"] if more else None,
    )


@router.get("/platform/v1/repositories", response_model=Envelope)
async def repositories(
    request: Request,
    principal: Principal = Depends(require("platform.services.read")),
    config=Depends(load_config),
):
    rows = [
        x for x in config.get("repositories", []) if x.get("tenant") == principal.tenant
    ]
    return envelope(request, rows, revision=config["revision"])


@router.get("/platform/v1/hosts", response_model=Envelope)
async def hosts(
    request: Request,
    cursor: str = Query("", max_length=512),
    limit: int = Query(100, ge=1, le=200),
    principal: Principal = Depends(require("platform.services.read")),
    store=Depends(get_store),
):
    return await resource_page(
        request, store, principal, "host", cursor=cursor, limit=limit
    )


@router.get("/platform/v1/hosts/{host_id}", response_model=Envelope)
async def host(
    request: Request,
    host_id: str,
    cursor: str = Query("", max_length=512),
    limit: int = Query(100, ge=1, le=200),
    principal: Principal = Depends(require("platform.services.read")),
    store=Depends(get_store),
):
    page = await resource_page(
        request,
        store,
        principal,
        "host",
        host_id=host_id,
        cursor=cursor,
        limit=limit,
    )
    if not page["data"] and not cursor:
        raise HTTPException(404, "host not observed")
    return page


@router.get("/platform/v1/services/{service_id}/deployments", response_model=Envelope)
async def deployments(
    request: Request,
    service_id: str,
    environment: str = Query("production"),
    principal: Principal = Depends(require("platform.services.read")),
    store=Depends(get_store),
    config=Depends(load_config),
):
    service_for(config, principal, service_id, environment)
    return await resource_page(
        request,
        store,
        principal,
        "deployment",
        service=service_id,
        environment=environment,
    )


@router.get("/platform/v1/services/{service_id}/endpoints", response_model=Envelope)
async def endpoints(
    request: Request,
    service_id: str,
    environment: str = Query("production"),
    principal: Principal = Depends(require("platform.services.read")),
    store=Depends(get_store),
    config=Depends(load_config),
):
    service_for(config, principal, service_id, environment)
    row = await store.get(principal.tenant, "contract", environment + ":" + service_id)
    return envelope(
        request,
        row["payload"] if row else {"endpoints": [], "status": "not-imported"},
        row["observed_at"] if row else None,
        row["revision"] if row else None,
    )


@router.get("/platform/v1/services/{service_id}/dependencies", response_model=Envelope)
async def dependencies(
    request: Request,
    service_id: str,
    principal: Principal = Depends(require("platform.services.read")),
    config=Depends(load_config),
):
    service = service_for(config, principal, service_id)
    visible = [
        s
        for s in service.get("dependencies", [])
        if config["services"].get(s, {}).get("tenant") == principal.tenant
    ]
    return envelope(
        request,
        {"declared": visible, "basis": "approved-release-catalog"},
        revision=config["revision"],
    )


@router.get("/platform/v1/services/{service_id}/coverage", response_model=Envelope)
async def coverage(
    request: Request,
    service_id: str,
    environment: str = Query("production"),
    principal: Principal = Depends(require("observability.health.read")),
    store=Depends(get_store),
    config=Depends(load_config),
):
    service = service_for(config, principal, service_id, environment)
    rows = await store.list(
        principal.tenant, "heartbeat", service=service_id, environment=environment
    )
    required = set(service.get("required_signals", ["metrics", "logs", "traces"]))
    fresh = [
        r
        for r in rows
        if datetime.now(UTC) - utc(r["observed_at"]) <= timedelta(seconds=90)
    ]
    seen = set(s for r in fresh for s in r["payload"].get("signals", []))
    return envelope(
        request,
        {
            "required": sorted(required),
            "fresh_signals": sorted(seen),
            "missing": sorted(required - seen),
            "status": "covered"
            if required and required <= seen
            else "not-applicable"
            if not required
            else "incomplete",
            "proof": "collector-observation; independent query/alert certification is separate",
        },
        min((r["observed_at"] for r in rows), default=None),
        config["revision"],
        freshness="not-applicable" if not required else None,
    )


@router.post(
    "/platform/v1/services/{service_id}/telemetry-profile", response_model=Envelope
)
async def profile(
    request: Request,
    service_id: str,
    body: Profile,
    principal: Principal = Depends(require("platform.services.write", ADMIN)),
    store=Depends(get_store),
    config=Depends(load_config),
):
    service_for(config, principal, service_id, body.environment)
    key, _ = headers(request)

    async def action(operation_id):
        revision = await store.put(
            principal.tenant,
            "profile",
            body.environment + ":" + service_id,
            body.model_dump(mode="json"),
            service=service_id,
            environment=body.environment,
            source="catalog",
            sequence=body.expected_revision + 1,
            observed_at=datetime.now(UTC),
            expected_revision=body.expected_revision,
        )
        await store.event(
            principal.tenant,
            "profile.staged",
            {
                "service_id": service_id,
                "revision": revision,
                "operation_id": operation_id,
            },
        )
        return {
            "state": "staged",
            "revision": revision,
            "config_digest": body.config_digest,
            "runtime_applied": False,
        }

    result = await store.mutate(
        principal, request.url.path, key, body.model_dump(mode="json"), action
    )
    return envelope(request, result, revision=result["revision"])


@router.post(
    "/platform/v1/services/{service_id}/contract-refresh", response_model=Envelope
)
async def contract_refresh(
    request: Request,
    service_id: str,
    body: ContractRefresh,
    principal: Principal = Depends(require("platform.services.write", ADMIN)),
    store=Depends(get_store),
):
    try:
        service, raw = read_approved_artifact(
            principal, service_id, body.environment, body.artifact_id, body.sha256
        )
        schema = json.loads(raw)
        if not str(schema.get("openapi", "")).startswith("3.") or not isinstance(
            schema.get("paths"), dict
        ):
            raise ValueError("schema")
        inventory = []
        for path, operations in schema["paths"].items():
            if (
                not path.startswith("/")
                or len(path) > 512
                or not isinstance(operations, dict)
            ):
                raise ValueError("path")
            for method, operation in operations.items():
                if method in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "head",
                    "options",
                    "trace",
                }:
                    inventory.append(
                        {
                            "method": method.upper(),
                            "path": path,
                            "operation_id": operation.get("operationId"),
                            "deprecated": bool(operation.get("deprecated", False)),
                        }
                    )
        if len(inventory) > 5000:
            raise ValueError("budget")
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(
            422, "approved OpenAPI artifact could not be verified"
        ) from None
    key, _ = headers(request)

    async def action(operation_id):
        revision = await store.put(
            principal.tenant,
            "contract",
            body.environment + ":" + service_id,
            {
                "sha256": body.sha256,
                "endpoints": inventory,
                "repository": service["repository"],
            },
            service=service_id,
            environment=body.environment,
            source="release-artifact",
            sequence=body.expected_revision + 1,
            observed_at=datetime.now(UTC),
            expected_revision=body.expected_revision,
        )
        await store.event(
            principal.tenant,
            "contract.imported",
            {"service_id": service_id, "revision": revision},
        )
        return {
            "state": "imported",
            "revision": revision,
            "endpoint_count": len(inventory),
        }

    result = await store.mutate(
        principal, request.url.path, key, body.model_dump(mode="json"), action
    )
    return envelope(request, result, revision=result["revision"])


async def reconcile_one(store, principal, config, service_id, environment):
    service = service_for(config, principal, service_id, environment)
    profile_row = await store.get(
        principal.tenant, "profile", environment + ":" + service_id
    )
    approved = service.get("approved_config_digest")
    desired = profile_row["payload"]["config_digest"] if profile_row else approved
    observed = await store.list(
        principal.tenant, "config", service=service_id, environment=environment
    )
    fresh = [
        r
        for r in observed
        if datetime.now(UTC) - utc(r["observed_at"]) <= timedelta(seconds=90)
    ]
    required = set(service.get("required_components", []))
    actual = {
        r["payload"].get("component"): r["payload"].get("config_digest") for r in fresh
    }
    reported = {
        r["payload"].get("component"): r["payload"].get("status") for r in fresh
    }
    component_states = {
        component: component_state(
            component, desired, approved, actual, reported, required
        )
        for component in sorted(required | actual.keys())
    }
    state = service_state(desired, approved, required, component_states)
    return {
        "service_id": service_id,
        "environment": environment,
        "desired_digest": desired,
        "approved_digest": approved,
        "components": actual,
        "component_states": component_states,
        "missing_components": sorted(required - actual.keys()),
        "state": state,
    }


def service_state(desired, approved, required, component_states):
    """Fold per-component states into the service state, worst first.

    A collector-reported ``failed`` or ``applying`` component wins over digest
    comparison; a required component without a fresh digest read-back keeps the
    service ``unknown`` (an unreachable Prometheus never yields ``synced``).
    """
    if desired != approved:
        return "pending-release-approval"
    if not desired or not required:
        return "unknown"
    states = [component_states.get(component, "unknown") for component in required]
    for worst in ("failed", "applying", "unknown", "drifted"):
        if worst in states:
            return worst
    return "synced"


def component_state(component, desired, approved, actual, reported, required):
    """One of pending, applying, synced, drifted, failed, unknown for a single component.

    ``synced`` needs a fresh read-back of the active configuration whose digest
    equals the approved desired revision; an HTTP 200 without a digest is
    ``unknown``. A collector may report ``applying`` or ``failed`` explicitly.
    """
    status = reported.get(component)
    if status == "failed":
        return "failed"
    if status == "applying":
        return "applying"
    if desired != approved:
        return "pending"
    if component not in actual or not actual.get(component):
        return "unknown"
    if not desired:
        return "unknown"
    if component not in required:
        return "unknown"
    return "synced" if actual[component] == desired else "drifted"


@router.get("/platform/v1/sync/status", response_model=Envelope)
async def sync_status(
    request: Request,
    environment: str = Query("production"),
    principal: Principal = Depends(require("platform.sync.read")),
    store=Depends(get_store),
    config=Depends(load_config),
):
    results = []
    for sid, service in list(config["services"].items())[:1000]:
        if service.get("tenant") == principal.tenant and environment in service.get(
            "environments", []
        ):
            results.append(
                await reconcile_one(store, principal, config, sid, environment)
            )
    return envelope(request, results, datetime.now(UTC), config["revision"])


@router.post("/platform/v1/sync/reconciliations", response_model=Envelope)
async def reconcile(
    request: Request,
    body: Reconciliation,
    principal: Principal = Depends(require("platform.sync.reconcile", ADMIN)),
    store=Depends(get_store),
    config=Depends(load_config),
):
    key, _ = headers(request)

    async def action(operation_id):
        result = [
            await reconcile_one(store, principal, config, sid, body.environment)
            for sid in dict.fromkeys(body.service_ids)
        ]
        await store.event(
            principal.tenant,
            "sync.reconciled",
            {"operation_id": operation_id, "results": result},
        )
        return {
            "state": "completed",
            "mode": "compare-approved-configuration-with-runtime-evidence",
            "results": result,
            "runtime_mutated": False,
        }

    result = await store.mutate(
        principal, request.url.path, key, body.model_dump(mode="json"), action
    )
    return envelope(request, result, datetime.now(UTC), config["revision"])


@router.get(
    "/platform/v1/sync/reconciliations/{reconciliation_id}", response_model=Envelope
)
async def reconciliation_result(
    request: Request,
    reconciliation_id: str,
    principal: Principal = Depends(require("platform.sync.read")),
    store=Depends(get_store),
):
    row = await store.operation(principal.tenant, reconciliation_id)
    if row["operation"] != "/platform/v1/sync/reconciliations":
        raise HTTPException(404, "reconciliation not found")
    return envelope(request, row["result"], row["created_at"])


async def bounded_body(request):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 65536:
            raise HTTPException(413, "monitoring event exceeds budget")
    return bytes(data)


@router.post("/platform/v1/integrations/github/events", response_model=Envelope)
async def github_event(
    request: Request,
    store=Depends(get_store),
    config=Depends(load_config),
    secret: bytes = Depends(load_github_secret),
):
    raw = await bounded_body(request)
    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(secret, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(403, "GitHub signature denied")
    event = request.headers.get("X-GitHub-Event", "")
    delivery = request.headers.get("X-GitHub-Delivery", "")
    if event not in {
        "push",
        "release",
        "workflow_run",
        "check_run",
    } or not ID.fullmatch(delivery):
        raise HTTPException(422, "unsupported GitHub event")
    try:
        payload = json.loads(raw)
        repository = payload["repository"]["full_name"]
        approved = next(
            r for r in config["repositories"] if r["repository"] == repository
        )
    except (ValueError, KeyError, TypeError, StopIteration):
        raise HTTPException(403, "repository not registered") from None
    principal = Principal(
        "github-webhook",
        approved["tenant"],
        frozenset(),
        frozenset(),
        frozenset(),
        "github-webhook",
    )
    # Retain identity and lifecycle fields only; GitHub payloads can contain
    # personal email addresses and workflow bodies that do not belong in logs.
    run = payload.get("workflow_run", payload.get("check_run", {}))
    projection = {
        "repository": repository,
        "event": event,
        "delivery_id": delivery,
        "git_sha": payload.get("after", run.get("head_sha")),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
    }

    async def action(operation_id):
        await store.event(principal.tenant, "github.observed", projection)
        return {
            "state": "recorded",
            "repository": repository,
            "deployment_authorized": False,
        }

    result = await store.mutate(
        principal,
        request.url.path,
        delivery,
        {"event": event, "sha256": hashlib.sha256(raw).hexdigest()},
        action,
    )
    return envelope(request, result, datetime.now(UTC))


ALLOWED_DATA = {
    "host": {
        "host_id",
        "hostname",
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "status",
    },
    "deployment": {
        "git_sha",
        "image_digest",
        "config_digest",
        "migration_head",
        "host_id",
        "status",
    },
    "health": {"liveness", "readiness", "dependencies", "status"},
    "integration": {
        "source_service",
        "target_service",
        "transport",
        "authentication",
        "contract",
        "queue_depth",
        "oldest_age_seconds",
        "delivery",
        "reconciliation",
    },
    "agent": {"agent_id", "username", "active", "presence"},
    "campaign": {"campaign_id", "active_agents", "queue_depth", "status"},
    "certificate": {"hostname", "expires_at", "issuer", "status"},
    "backup": {
        "backup_id",
        "created_at",
        "ciphertext_verified",
        "recovery_key_verified",
        "restore_verified",
        "status",
    },
    "slo": {"slo_id", "target", "actual", "window_seconds", "status"},
    "dashboard": {"dashboard_id", "title", "url", "revision"},
    "security": {"rule_id", "rule_level", "agent_id", "severity", "status"},
    "error": {"issue_id", "release", "count", "status"},
    "config": {"component", "config_digest", "status"},
}


def validate_source(config, principal, body):
    service = service_for(config, principal, body.service_id, body.environment)
    if body.service_id not in principal.services:
        raise HTTPException(403, "collector service authority denied")
    binding = service.get("observation_sources", {}).get(body.source_deployment, {})
    if binding.get("client") != principal.client or body.environment not in binding.get(
        "environments", []
    ):
        raise HTTPException(403, "source deployment is not registered to collector")
    if body.observed_at > datetime.now(UTC) + timedelta(seconds=30):
        raise HTTPException(422, "future observation")


@router.post("/platform/v1/runtime/observations", response_model=Envelope)
async def observe(
    request: Request,
    body: Observation,
    principal: Principal = Depends(require("platform.runtime.observe", COLLECTOR)),
    store=Depends(get_store),
    config=Depends(load_config),
):
    validate_source(config, principal, body)
    if set(body.data) - ALLOWED_DATA[body.kind] or not body.data:
        raise HTTPException(422, "unsupported observation fields")
    if len(json.dumps(body.data)) > 32768:
        raise HTTPException(413, "observation exceeds budget")
    if body.campaign_id and body.campaign_id not in principal.campaigns:
        raise HTTPException(403, "collector campaign denied")
    key, _ = headers(request)

    async def action(operation_id):
        resource_key = ":".join(
            [
                body.environment,
                body.service_id,
                body.source_deployment,
                body.resource_id,
            ]
        )
        revision = await store.put(
            principal.tenant,
            body.kind,
            resource_key,
            redact(body.data),
            service=body.service_id,
            environment=body.environment,
            source=body.source_deployment,
            sequence=body.sequence,
            observed_at=body.observed_at,
            campaign=body.campaign_id,
        )
        await store.event(
            principal.tenant,
            body.kind + ".observed",
            {
                "service_id": body.service_id,
                "resource_id": body.resource_id,
                "revision": revision,
            },
            body.campaign_id,
        )
        return {"state": "recorded", "revision": revision}

    result = await store.mutate(
        principal, request.url.path, key, body.model_dump(mode="json"), action
    )
    return envelope(request, result, body.observed_at, result["revision"])


@router.post("/platform/v1/telemetry/heartbeats", response_model=Envelope)
async def heartbeat(
    request: Request,
    body: Heartbeat,
    principal: Principal = Depends(require("telemetry.heartbeat.write", COLLECTOR)),
    store=Depends(get_store),
    config=Depends(load_config),
):
    validate_source(config, principal, body)
    key, _ = headers(request)

    async def action(operation_id):
        revision = await store.put(
            principal.tenant,
            "heartbeat",
            ":".join([body.environment, body.service_id, body.source_deployment]),
            {"signals": sorted(set(body.signals))},
            service=body.service_id,
            environment=body.environment,
            source=body.source_deployment,
            sequence=body.sequence,
            observed_at=body.observed_at,
        )
        await store.event(
            principal.tenant,
            "heartbeat.observed",
            {"service_id": body.service_id, "signals": body.signals},
        )
        return {"state": "recorded", "revision": revision}

    result = await store.mutate(
        principal, request.url.path, key, body.model_dump(mode="json"), action
    )
    return envelope(request, result, body.observed_at, result["revision"])


@router.get("/v1/observability/overview", response_model=Envelope)
async def overview(
    request: Request,
    principal: Principal = Depends(require("observability.health.read")),
    store=Depends(get_store),
    config=Depends(load_config),
):
    services = {
        sid: s
        for sid, s in config["services"].items()
        if s.get("tenant") == principal.tenant
    }
    rows = await store.list(principal.tenant, "heartbeat", limit=1000)
    fresh = {
        r["service_id"]
        for r in rows
        if datetime.now(UTC) - utc(r["observed_at"]) <= timedelta(seconds=90)
    }
    return envelope(
        request,
        {
            "registered_services": len(services),
            "services_with_fresh_heartbeat": len(fresh & services.keys()),
            "missing_heartbeat": sorted(services.keys() - fresh),
            "runtime_certification": "not-implied-by-heartbeat",
        },
        datetime.now(UTC),
        config["revision"],
    )


@router.get("/v1/observability/services/{service_id}/health", response_model=Envelope)
async def health(
    request: Request,
    service_id: str,
    environment: str = Query("production"),
    principal: Principal = Depends(require("observability.health.read")),
    store=Depends(get_store),
    config=Depends(load_config),
):
    service_for(config, principal, service_id, environment)
    return await resource_page(
        request, store, principal, "health", service=service_id, environment=environment
    )


@router.get("/v1/observability/topology", response_model=Envelope)
async def topology(
    request: Request,
    principal: Principal = Depends(require("observability.health.read")),
    config=Depends(load_config),
):
    services = {
        sid: s
        for sid, s in config["services"].items()
        if s.get("tenant") == principal.tenant
    }
    edges = [
        {"source": sid, "target": target, "basis": "declared"}
        for sid, s in services.items()
        for target in s.get("dependencies", [])
        if target in services
    ]
    return envelope(
        request, {"nodes": list(services), "edges": edges}, revision=config["revision"]
    )


def query_endpoint(family):
    async def execute(
        request: Request,
        body: QueryRequest,
        principal: Principal = Depends(
            require(
                "observability."
                + (
                    {"metrics-range": "metrics", "traces-search": "traces"}.get(
                        family, family
                    )
                )
                + ".read"
            )
        ),
        backends=Depends(get_backends),
    ):
        result = await backends.query(family, body, principal)
        return envelope(request, result, datetime.now(UTC))

    execute.__name__ = "query_" + family.replace("-", "_")
    return execute


for path, family in [
    ("metrics/query", "metrics"),
    ("metrics/query-range", "metrics-range"),
    ("logs/query", "logs"),
    ("traces/search", "traces-search"),
]:
    router.add_api_route(
        "/v1/observability/" + path,
        query_endpoint(family),
        methods=["POST"],
        response_model=Envelope,
    )


@router.get("/v1/observability/traces/{trace_id}", response_model=Envelope)
async def trace(
    request: Request,
    trace_id: str,
    principal: Principal = Depends(require("observability.traces.read")),
    backends=Depends(get_backends),
):
    if not re.fullmatch(r"[0-9a-f]{32}", trace_id):
        raise HTTPException(422, "trace_id must be 32 lowercase hexadecimal characters")
    data = await backends.get(
        "tempo", "/api/v2/traces/" + trace_id, tenant=principal.tenant
    )
    return envelope(request, data, datetime.now(UTC))


def projection_endpoint(kind, scope):
    async def projection(
        request: Request,
        cursor: str = Query("", max_length=512),
        limit: int = Query(100, ge=1, le=200),
        principal: Principal = Depends(require(scope)),
        store=Depends(get_store),
    ):
        return await resource_page(
            request, store, principal, kind, cursor=cursor, limit=limit
        )

    projection.__name__ = "list_monitoring_" + kind
    return projection


for path, kind, scope in [
    ("slo", "slo", "observability.health.read"),
    ("dashboards", "dashboard", "observability.health.read"),
    ("certificates", "certificate", "observability.health.read"),
    ("backups", "backup", "observability.backups.read"),
]:
    router.add_api_route(
        "/v1/observability/" + path,
        projection_endpoint(kind, scope),
        methods=["GET"],
        response_model=Envelope,
    )


@router.get("/v1/observability/secrets/health", response_model=Envelope)
async def secrets_health(
    request: Request,
    principal: Principal = Depends(require("observability.secrets.health.read")),
    backends=Depends(get_backends),
):
    data = await backends.get("openbao", "/v1/sys/health")
    selected = {
        k: v
        for k, v in data.items()
        if k
        in {
            "initialized",
            "sealed",
            "standby",
            "performance_standby",
            "version",
            "server_time_utc",
        }
    }
    return envelope(request, selected, datetime.now(UTC))


@router.get("/v1/observability/integrations", response_model=Envelope)
async def integrations(
    request: Request,
    principal: Principal = Depends(require("observability.integrations.read")),
    config=Depends(load_config),
    store=Depends(get_store),
):
    configured = [
        {"integration_id": name, "service_id": v["service_id"], "backend": v["backend"]}
        for name, v in config.get("integrations", {}).items()
        if config["services"].get(v["service_id"], {}).get("tenant") == principal.tenant
    ]
    rows = await resource_page(request, store, principal, "integration")
    return envelope(
        request,
        {"registered": configured, "observed": rows["data"]},
        revision=config["revision"],
    )


@router.get("/v1/observability/integrations/{integration_id}", response_model=Envelope)
async def integration(
    request: Request,
    integration_id: str,
    cursor: str = Query("", max_length=512),
    limit: int = Query(100, ge=1, le=200),
    principal: Principal = Depends(require("observability.integrations.read")),
    config=Depends(load_config),
    store=Depends(get_store),
    backends=Depends(get_backends),
):
    binding = config.get("integrations", {}).get(integration_id)
    if not binding:
        raise HTTPException(404, "integration not registered")
    service_for(config, principal, binding["service_id"])
    if binding.get("backend") in {"backstage", "sentry", "wazuh"}:
        return envelope(
            request,
            await backends.integration(integration_id, binding, principal),
            datetime.now(UTC),
        )
    return await resource_page(
        request,
        store,
        principal,
        "integration",
        service=binding["service_id"],
        resource_id=integration_id,
        cursor=cursor,
        limit=limit,
    )


@router.get("/v1/observability/agents", response_model=Envelope)
async def agents(
    request: Request,
    campaign_id: str | None = None,
    cursor: str = Query("", max_length=512),
    limit: int = Query(100, ge=1, le=200),
    principal: Principal = Depends(require("observability.agents.read", CAMPAIGN_READ)),
    store=Depends(get_store),
):
    return await resource_page(
        request,
        store,
        principal,
        "agent",
        campaign=campaign_id,
        cursor=cursor,
        limit=limit,
    )


@router.get("/v1/observability/campaigns/{campaign_id}", response_model=Envelope)
async def campaign(
    request: Request,
    campaign_id: str,
    principal: Principal = Depends(
        require("observability.campaigns.read", CAMPAIGN_READ)
    ),
    store=Depends(get_store),
):
    principal.check_campaign(campaign_id)
    return await resource_page(
        request, store, principal, "campaign", campaign=campaign_id
    )


@router.get("/v1/observability/events/stream")
async def stream(
    request: Request,
    last_event_id: str = Header("0", alias="Last-Event-ID"),
    principal: Principal = Depends(require("observability.health.read", CAMPAIGN_READ)),
    store=Depends(get_store),
):
    if not re.fullmatch(r"[0-9]{1,18}", last_event_id):
        raise HTTPException(422, "invalid event cursor")
    campaigns = (
        principal.campaigns
        if "campaign_supervisor" in principal.roles
        and not principal.roles.intersection(READ_ROLES)
        else None
    )
    rows = await store.stream(principal.tenant, int(last_event_id), campaigns)

    # Bounded batch SSE: reconnect through the same-origin BFF for renewed JWT
    # validation. No access token is accepted in a query string or event payload.
    async def generate():
        yield "retry: 30000\n\n"
        for row in rows:
            yield (
                "id: "
                + str(row["id"])
                + "\nevent: "
                + row["topic"]
                + "\ndata: "
                + json.dumps(row["data"], separators=(",", ":"))
                + "\n\n"
            )
        yield ": heartbeat\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/v1/observability/probe-runs", response_model=Envelope)
async def probe(
    request: Request,
    body: ProbeRequest,
    principal: Principal = Depends(require("observability.probes.run", ADMIN)),
    store=Depends(get_store),
    config=Depends(load_config),
    backends=Depends(get_backends),
):
    service_for(config, principal, body.service_id, body.environment)
    target = config.get("probe_targets", {}).get(body.target_id, {})
    if (
        target.get("service_id") != body.service_id
        or target.get("environment") != body.environment
    ):
        raise HTTPException(
            403, "probe target is not registered for service/environment"
        )
    key, _ = headers(request)

    async def action(operation_id):
        data = await backends.get(
            "blackbox",
            "/probe",
            {"module": target["module"], "target": target["url"]},
            text_response=True,
        )
        match = re.search(
            r"^probe_success(?:\{[^\n]*\})?\s+([01](?:\.0)?)\s*$", data, re.M
        )
        if not match:
            raise HTTPException(503, "probe result missing")
        result = {
            "state": "completed",
            "target_id": body.target_id,
            "success": float(match.group(1)) == 1,
        }
        await store.event(principal.tenant, "probe.completed", result)
        return result

    result = await store.mutate(
        principal, request.url.path, key, body.model_dump(mode="json"), action
    )
    return envelope(request, result, datetime.now(UTC))


@router.get("/v1/observability/probe-runs/{probe_run_id}", response_model=Envelope)
async def probe_result(
    request: Request,
    probe_run_id: str,
    principal: Principal = Depends(require("observability.health.read")),
    store=Depends(get_store),
):
    row = await store.operation(principal.tenant, probe_run_id)
    if row["operation"] != "/v1/observability/probe-runs":
        raise HTTPException(404, "probe run not found")
    return envelope(request, row["result"], row["created_at"])


@router.post("/v1/telemetry/browser-events", response_model=Envelope)
async def browser_event(
    request: Request,
    body: BrowserEvent,
    principal: Principal = Depends(
        require("telemetry.browser.write", frozenset({"browser_ingest"}))
    ),
    store=Depends(get_store),
    config=Depends(load_config),
):
    service = service_for(config, principal, body.service_id, body.environment)
    if body.service_id not in principal.services or principal.client not in service.get(
        "browser_bff_clients", []
    ):
        raise HTTPException(403, "browser BFF not bound")
    if request.headers.get("Origin") not in service.get("browser_origins", []):
        raise HTTPException(403, "browser origin denied")
    if body.occurred_at > datetime.now(UTC) + timedelta(seconds=30):
        raise HTTPException(422, "future browser event")
    key, _ = headers(request)

    async def action(operation_id):
        await store.event(
            principal.tenant, "browser." + body.event_type, body.model_dump(mode="json")
        )
        return {"state": "recorded", "event_id": body.event_id}

    result = await store.mutate(
        principal, request.url.path, key, body.model_dump(mode="json"), action
    )
    return envelope(request, result, body.occurred_at)


def is_monitoring_route(request: Request) -> bool:
    """Exact registered method/path only; every route owns authentication."""
    return any(
        isinstance(route, APIRoute)
        and request.method in (route.methods or set())
        and route.path_regex.fullmatch(request.url.path)
        for route in router.routes
    )
