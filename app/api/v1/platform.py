"""Canonical service catalog and review-gated provisioning workflow."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.platform_auth import PlatformPrincipal, require_platform_scope
from app.db.session import get_session
from app.platform_catalog_monitoring import (
    CertificationEvidence,
    MonitoringDescriptor,
    ObservedState,
    certification_blockers,
    compare,
    declared_expectations,
    derive_state,
    freshness,
)
from app.secret_reference import SecretReferenceError, parse_references, references_for_environments

router = APIRouter(prefix="/platform/v1", tags=["platform-service-catalog"])
SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
REPOSITORY = re.compile(r"^appolon1908-hue/[A-Za-z0-9._-]+$")
ENVIRONMENTS = {"development", "test", "staging", "production"}
ADMIN_ROLES = {"platform_admin", "platform_reviewer"}


class ServiceCreate(MonitoringDescriptor):
    service_id: str
    owner: str = Field(min_length=2, max_length=128)
    tenant_mode: Literal["single-tenant", "multi-tenant", "platform"]
    type: Literal["api", "website", "worker", "adapter", "scheduled-job", "websocket"]
    repository: str
    environments: list[str]
    health_path: str = "/health/ready"
    metrics_path: str = "/metrics"
    openapi_path: str = "/openapi.json"
    dependencies: list[str] = Field(default_factory=list, max_length=64)
    data_classification: Literal["public", "internal", "confidential", "restricted"]
    slo_profile: str = Field(min_length=2, max_length=64)
    alert_profile: str = Field(min_length=2, max_length=64)

    @field_validator("service_id")
    @classmethod
    def service_id_is_safe(cls, value: str) -> str:
        if not SERVICE_ID.fullmatch(value):
            raise ValueError("service_id must be lowercase kebab-case")
        return value

    @field_validator("repository")
    @classmethod
    def repository_is_governed(cls, value: str) -> str:
        if not REPOSITORY.fullmatch(value):
            raise ValueError("repository must belong to appolon1908-hue")
        return value

    @field_validator("environments")
    @classmethod
    def environments_are_governed(cls, value: list[str]) -> list[str]:
        if not value or len(value) != len(set(value)) or not set(value) <= ENVIRONMENTS:
            raise ValueError("environments must be unique governed values")
        return value

    @field_validator("health_path", "metrics_path", "openapi_path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//") or "?" in value or "#" in value:
            raise ValueError("contract paths must be absolute and query-free")
        return value


class ServicePatch(MonitoringDescriptor):
    owner: str | None = Field(default=None, min_length=2, max_length=128)
    dependencies: list[str] | None = Field(default=None, max_length=64)
    slo_profile: str | None = Field(default=None, min_length=2, max_length=64)
    alert_profile: str | None = Field(default=None, min_length=2, max_length=64)


class EnvironmentCreate(BaseModel):
    environment: Literal["development", "test", "staging", "production"]
    region: str = Field(pattern=r"^[a-z0-9-]{2,32}$")


class ProvisioningCreate(BaseModel):
    service_id: str
    environment: Literal["development", "test", "staging", "production"]
    manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    git_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    requested_components: list[Literal["caddy", "kong", "keycloak", "openbao", "prometheus", "alertmanager", "loki", "tempo", "alloy", "grafana", "cicd"]]


class Transition(BaseModel):
    reason: str = Field(min_length=20, max_length=1000)


class CertificationSubmission(Transition):
    manifest_valid: bool
    openapi_valid: bool
    authorization_tests: bool
    tenant_isolation: bool
    secrets_externalized: bool
    health_endpoints: bool
    metrics_scraped: bool
    logs_received: bool
    traces_received: bool
    alert_route_test: bool
    image_digest_pinned: bool
    sbom_present: bool
    provenance_verified: bool
    rollback_verified: bool
    live_delivery_disabled: bool

    def evidence(self) -> dict[str, bool]:
        return self.model_dump(exclude={"reason"})


def require_role(role: str, allowed: set[str] = ADMIN_ROLES) -> None:
    if role not in allowed:
        raise HTTPException(403, "eligible platform role required")


def now() -> datetime:
    return datetime.now(timezone.utc)


def audit_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


MONITORING_COLUMNS = (
    "deployment_id", "host_id", "instance_id", "public_origin", "private_origin",
    "liveness_path", "readiness_path", "metrics_profile", "logs_profile", "traces_profile",
    "prometheus_target_id", "blackbox_target_id", "expected_git_sha", "expected_image_digest",
    "expected_config_digest", "expected_migration_head",
)
JSON_COLUMNS = ("grafana_dashboard_ids", "secret_references")
EXPECTED_COLUMNS = ("expected_git_sha", "expected_image_digest", "expected_config_digest", "expected_migration_head")


def descriptor_values(body: MonitoringDescriptor, environments: list[str]) -> dict[str, Any]:
    """Validated monitoring descriptor columns; secret references are pointers only."""
    values: dict[str, Any] = {name: getattr(body, name) for name in MONITORING_COLUMNS}
    values["grafana_dashboard_ids"] = body.grafana_dashboard_ids
    if body.secret_references is not None:
        try:
            references = parse_references(body.secret_references)
            references_for_environments(references, environments)
        except (SecretReferenceError, ValueError) as exc:
            raise HTTPException(422, f"secret references rejected: {exc}") from exc
        values["secret_references"] = [reference.public() for reference in references]
    else:
        values["secret_references"] = None
    return values


def aware(value: Any) -> Any:
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def record_monitoring_transition(db: AsyncSession, catalog_id: Any, from_state: str, to_state: str, reason: str, actor: str, correlation_id: str, evidence: Any) -> None:
    await db.execute(text("""INSERT INTO platform_service_monitoring_audit(id,service_id,from_state,to_state,reason,actor,correlation_id,evidence_hash,created_at)
      VALUES (:id,:service_id,:from_state,:to_state,:reason,:actor,:correlation,:evidence,:now)"""), {
        "id": uuid4(), "service_id": catalog_id, "from_state": from_state, "to_state": to_state,
        "reason": reason[:1000], "actor": actor, "correlation": correlation_id, "evidence": audit_hash(evidence), "now": now(),
    })


@router.post("/services", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_platform_scope("platform.services.write", frozenset({"platform_admin"})))])
async def create_service(body: ServiceCreate, db: AsyncSession = Depends(get_session)):
    service_uuid = uuid4()
    descriptor = descriptor_values(body, body.environments)
    readiness_path = body.readiness_path or body.health_path
    try:
        await db.execute(text("""INSERT INTO platform_services
          (id,service_id,owner,tenant_mode,service_type,repository,environments,health_path,metrics_path,openapi_path,dependencies,data_classification,slo_profile,alert_profile,state,created_at,updated_at,
           deployment_id,host_id,instance_id,public_origin,private_origin,liveness_path,readiness_path,metrics_profile,logs_profile,traces_profile,
           prometheus_target_id,blackbox_target_id,grafana_dashboard_ids,expected_git_sha,expected_image_digest,expected_config_digest,expected_migration_head,
           secret_references,monitoring_state,monitoring_state_reason)
          VALUES (:id,:service_id,:owner,:tenant_mode,:service_type,:repository,CAST(:environments AS jsonb),:health_path,:metrics_path,:openapi_path,CAST(:dependencies AS jsonb),:classification,:slo,:alert,'registered',:now,:now,
           :deployment_id,:host_id,:instance_id,:public_origin,:private_origin,:liveness_path,:readiness_path,:metrics_profile,:logs_profile,:traces_profile,
           :prometheus_target_id,:blackbox_target_id,CAST(:grafana_dashboard_ids AS jsonb),:expected_git_sha,:expected_image_digest,:expected_config_digest,:expected_migration_head,
           CAST(:secret_references AS jsonb),'registered',:monitoring_reason)"""), {
            "id": service_uuid, "service_id": body.service_id, "owner": body.owner,
            "tenant_mode": body.tenant_mode, "service_type": body.type, "repository": body.repository,
            "environments": json.dumps(body.environments), "health_path": body.health_path,
            "metrics_path": body.metrics_path, "openapi_path": body.openapi_path,
            "dependencies": json.dumps(body.dependencies), "classification": body.data_classification,
            "slo": body.slo_profile, "alert": body.alert_profile, "now": now(),
            **{name: descriptor[name] for name in MONITORING_COLUMNS if name != "readiness_path"},
            "readiness_path": readiness_path,
            "grafana_dashboard_ids": json.dumps(descriptor["grafana_dashboard_ids"] or []),
            "secret_references": json.dumps(descriptor["secret_references"] or []),
            "monitoring_reason": "registered from an approved descriptor; runtime evidence not yet observed",
        })
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "service_id or repository already registered") from exc
    return {"service_id": body.service_id, "state": "registered", "monitoring_state": "registered", "catalog_id": str(service_uuid)}


@router.get("/services", dependencies=[Depends(require_platform_scope("platform.services.read"))])
async def list_services(db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(text("SELECT service_id,owner,tenant_mode,service_type,repository,environments,dependencies,data_classification,slo_profile,alert_profile,state,monitoring_state,last_observed_at,last_certified_at,updated_at FROM platform_services ORDER BY service_id"))).mappings().all()
    return {"items": [dict(row) for row in rows]}


@router.get("/services/{service_id}", dependencies=[Depends(require_platform_scope("platform.services.read"))])
async def get_service(service_id: str, db: AsyncSession = Depends(get_session)):
    row = (await db.execute(text("SELECT * FROM platform_services WHERE service_id=:id"), {"id": service_id})).mappings().one_or_none()
    if row is None:
        raise HTTPException(404, "service not found")
    result = dict(row)
    result.pop("id", None)
    return result


@router.patch("/services/{service_id}")
async def patch_service(
    service_id: str,
    body: ServicePatch,
    x_correlation_id: str = Header("", alias="X-Correlation-ID"),
    actor: PlatformPrincipal = Depends(require_platform_scope("platform.services.write", frozenset({"platform_admin"}))),
    db: AsyncSession = Depends(get_session),
):
    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(400, "at least one change is required")
    current = await get_service(service_id, db)
    descriptor = descriptor_values(body, current["environments"])
    merged = {**current, **changes}
    for name in MONITORING_COLUMNS + JSON_COLUMNS:
        if descriptor.get(name) is not None:
            merged[name] = descriptor[name]
    previous_state = current.get("monitoring_state") or "unregistered"
    if any(name in changes for name in EXPECTED_COLUMNS) and previous_state != "unregistered":
        # A new desired release invalidates certification until fresh evidence matches it.
        merged["monitoring_state"] = "registered" if previous_state == "certified" else previous_state
        merged["last_observed_at"] = aware(current.get("last_observed_at"))
        new_state, reason = derive_state(merged, now())
    else:
        new_state, reason = previous_state, current.get("monitoring_state_reason") or ""
    result = await db.execute(text("""UPDATE platform_services SET owner=:owner,dependencies=CAST(:dependencies AS jsonb),slo_profile=:slo,alert_profile=:alert,
        deployment_id=:deployment_id,host_id=:host_id,instance_id=:instance_id,public_origin=:public_origin,private_origin=:private_origin,
        liveness_path=:liveness_path,readiness_path=:readiness_path,metrics_profile=:metrics_profile,logs_profile=:logs_profile,traces_profile=:traces_profile,
        prometheus_target_id=:prometheus_target_id,blackbox_target_id=:blackbox_target_id,grafana_dashboard_ids=CAST(:grafana_dashboard_ids AS jsonb),
        expected_git_sha=:expected_git_sha,expected_image_digest=:expected_image_digest,expected_config_digest=:expected_config_digest,expected_migration_head=:expected_migration_head,
        secret_references=CAST(:secret_references AS jsonb),monitoring_state=:monitoring_state,monitoring_state_reason=:monitoring_reason,updated_at=:now
        WHERE service_id=:id RETURNING id"""), {
        "owner": merged["owner"], "dependencies": json.dumps(merged["dependencies"]), "slo": merged["slo_profile"], "alert": merged["alert_profile"],
        **{name: merged.get(name) for name in MONITORING_COLUMNS},
        "grafana_dashboard_ids": json.dumps(merged.get("grafana_dashboard_ids") or []),
        "secret_references": json.dumps(merged.get("secret_references") or []),
        "monitoring_state": new_state, "monitoring_reason": reason, "now": now(), "id": service_id,
    })
    updated = result.scalar_one_or_none()
    if updated is None:
        await db.rollback()
        raise HTTPException(404, "service not found")
    if new_state != previous_state:
        await record_monitoring_transition(db, updated, previous_state, new_state, reason, actor.subject, x_correlation_id or service_id, {"patch": sorted(changes)})
    await db.commit()
    return {"service_id": service_id, "state": current["state"], "monitoring_state": new_state}


@router.get("/services/{service_id}/monitoring-state", dependencies=[Depends(require_platform_scope("platform.services.read"))])
async def monitoring_state(service_id: str, db: AsyncSession = Depends(get_session)):
    row = dict(await get_service(service_id, db))
    row["last_observed_at"] = aware(row.get("last_observed_at"))
    moment = now()
    state, reason = derive_state(row, moment)
    matching, drifted, unobserved = compare(row)
    audit = (await db.execute(text("""SELECT a.from_state,a.to_state,a.reason,a.actor,a.correlation_id,a.evidence_hash,a.created_at
        FROM platform_service_monitoring_audit a JOIN platform_services s ON s.id=a.service_id WHERE s.service_id=:id ORDER BY a.created_at DESC LIMIT 20"""), {"id": service_id})).mappings().all()
    return {
        "service_id": service_id,
        "monitoring_state": row.get("monitoring_state"),
        "derived_state": state,
        "reason": reason,
        "freshness": freshness(row, moment),
        "expected": declared_expectations(row),
        "observed": {name: row.get(f"observed_{name}") for name in ("git_sha", "image_digest", "config_digest", "migration_head")},
        "matching": matching, "drifted": drifted, "unobserved": unobserved,
        "bindings": {k: row.get(k) for k in ("deployment_id", "host_id", "instance_id", "public_origin", "private_origin", "liveness_path", "readiness_path", "metrics_path", "openapi_path", "metrics_profile", "logs_profile", "traces_profile", "prometheus_target_id", "blackbox_target_id", "grafana_dashboard_ids")},
        "secret_references": row.get("secret_references") or [],
        "last_observed_at": row.get("last_observed_at"), "last_observation_source": row.get("last_observation_source"),
        "last_certified_at": row.get("last_certified_at"), "last_certified_by": row.get("last_certified_by"),
        "audit": [dict(item) for item in audit],
        "runtime_mutated": False,
    }


@router.post("/services/{service_id}/monitoring-state/observations", status_code=status.HTTP_202_ACCEPTED)
async def observe_service(
    service_id: str,
    body: ObservedState,
    x_correlation_id: str = Header("", alias="X-Correlation-ID"),
    actor: PlatformPrincipal = Depends(require_platform_scope("platform.runtime.observe", frozenset({"platform_admin", "platform_operator"}))),
    db: AsyncSession = Depends(get_session),
):
    """An authorized collector reports what the running service actually is; never a Git descriptor."""
    if not x_correlation_id.strip():
        raise HTTPException(422, "X-Correlation-ID is required")
    current = dict(await get_service(service_id, db))
    if (current.get("monitoring_state") or "unregistered") == "unregistered":
        raise HTTPException(409, "service is not registered; observations cannot precede registration")
    last = aware(current.get("last_observed_at"))
    if last is not None and body.observed_at < last:
        raise HTTPException(409, "observation is older than the recorded observation; delayed evidence cannot overwrite newer state")
    observed = body.model_dump(mode="json", exclude={"observed_at", "source", "status", "detail"}, exclude_none=True)
    merged = {**current, **observed, "last_observed_at": body.observed_at}
    previous_state = current.get("monitoring_state") or "registered"
    new_state, reason = derive_state(merged, now(), reporter_status=None if body.status == "observed" else body.status)
    if body.detail and body.status != "observed":
        reason = f"{reason}: {body.detail}"
    result = await db.execute(text("""UPDATE platform_services SET
        observed_git_sha=COALESCE(:git,observed_git_sha),observed_image_digest=COALESCE(:image,observed_image_digest),
        observed_config_digest=COALESCE(:config,observed_config_digest),observed_migration_head=COALESCE(:migration,observed_migration_head),
        last_observed_at=:observed_at,last_observation_source=:source,monitoring_state=:state,monitoring_state_reason=:reason,updated_at=:now
        WHERE service_id=:id RETURNING id"""), {
        "git": body.observed_git_sha, "image": body.observed_image_digest, "config": body.observed_config_digest, "migration": body.observed_migration_head,
        "observed_at": body.observed_at, "source": body.source, "state": new_state, "reason": reason, "now": now(), "id": service_id,
    })
    updated = result.scalar_one_or_none()
    if updated is None:
        await db.rollback()
        raise HTTPException(404, "service not found")
    if new_state != previous_state:
        await record_monitoring_transition(db, updated, previous_state, new_state, reason, actor.subject, x_correlation_id, body.model_dump(mode="json"))
    await db.commit()
    return {"service_id": service_id, "monitoring_state": new_state, "reason": reason, "previous_state": previous_state, "runtime_mutated": False}


@router.post("/services/{service_id}/monitoring-state/certification")
async def certify_service(
    service_id: str,
    body: CertificationEvidence,
    x_correlation_id: str = Header("", alias="X-Correlation-ID"),
    actor: PlatformPrincipal = Depends(require_platform_scope("platform.services.write", frozenset({"platform_admin", "platform_reviewer"}))),
    db: AsyncSession = Depends(get_session),
):
    """Certified requires synced, fresh runtime evidence plus proven signal, alert and dashboard coverage."""
    if not x_correlation_id.strip():
        raise HTTPException(422, "X-Correlation-ID is required")
    current = dict(await get_service(service_id, db))
    current["last_observed_at"] = aware(current.get("last_observed_at"))
    blockers = certification_blockers(current, body, now())
    if blockers:
        raise HTTPException(409, {"certified": False, "blockers": blockers})
    previous_state = current.get("monitoring_state") or "registered"
    reason = f"certified by {actor.role}: {body.reason}"
    result = await db.execute(text("""UPDATE platform_services SET monitoring_state='certified',monitoring_state_reason=:reason,
        last_certified_at=:now,last_certified_by=:actor,updated_at=:now WHERE service_id=:id RETURNING id"""), {"reason": reason, "now": now(), "actor": actor.subject, "id": service_id})
    updated = result.scalar_one_or_none()
    if updated is None:
        await db.rollback()
        raise HTTPException(404, "service not found")
    await record_monitoring_transition(db, updated, previous_state, "certified", reason, actor.subject, x_correlation_id, body.model_dump(mode="json"))
    await db.commit()
    return {"service_id": service_id, "monitoring_state": "certified", "previous_state": previous_state, "certified_by": actor.subject, "runtime_mutated": False}


@router.post("/services/{service_id}/environments", status_code=201, dependencies=[Depends(require_platform_scope("platform.services.write", frozenset({"platform_admin"})))])
async def add_environment(service_id: str, body: EnvironmentCreate, db: AsyncSession = Depends(get_session)):
    service = await get_service(service_id, db)
    if body.environment not in service["environments"]:
        raise HTTPException(409, "environment is not declared by the service")
    await db.execute(text("INSERT INTO platform_service_environments(id,service_id,environment,region,state,created_at) SELECT :uuid,id,:env,:region,'declared',:now FROM platform_services WHERE service_id=:id ON CONFLICT(service_id,environment,region) DO NOTHING"), {"uuid": uuid4(), "env": body.environment, "region": body.region, "now": now(), "id": service_id})
    await db.commit()
    return {"service_id": service_id, "environment": body.environment, "region": body.region, "state": "declared"}


async def service_state(service_id: str, target: str, role: str, db: AsyncSession):
    require_role(role, {"platform_admin"})
    result = await db.execute(text("UPDATE platform_services SET state=:state,updated_at=:now WHERE service_id=:id RETURNING id"), {"state": target, "now": now(), "id": service_id})
    updated = result.scalar_one_or_none()
    await db.commit()
    if updated is None:
        raise HTTPException(404, "service not found")
    return {"service_id": service_id, "state": target}


@router.post("/services/{service_id}/activate")
async def activate_service(service_id: str, actor: PlatformPrincipal = Depends(require_platform_scope("platform.services.write", frozenset({"platform_admin"}))), db: AsyncSession = Depends(get_session)):
    return await service_state(service_id, "active", actor.role, db)


@router.post("/services/{service_id}/decommission")
async def decommission_service(service_id: str, actor: PlatformPrincipal = Depends(require_platform_scope("platform.services.write", frozenset({"platform_admin"}))), db: AsyncSession = Depends(get_session)):
    return await service_state(service_id, "decommissioned", actor.role, db)


@router.post("/provisioning/requests", status_code=202)
async def create_provisioning(
    body: ProvisioningCreate,
    x_correlation_id: str = Header("", alias="X-Correlation-ID"),
    actor: PlatformPrincipal = Depends(require_platform_scope("platform.provisioning.request", frozenset({"platform_admin", "platform_operator"}))),
    db: AsyncSession = Depends(get_session),
):
    request_id = uuid4()
    service = await get_service(body.service_id, db)
    if body.environment not in service["environments"]:
        raise HTTPException(409, "environment is not declared by the service")
    payload = body.model_dump(mode="json")
    await db.execute(text("""INSERT INTO platform_provisioning_requests(id,service_id,environment,state,request_json,manifest_sha256,git_sha,correlation_id,requested_by,created_at,updated_at)
      SELECT :uuid,id,:env,'requested',CAST(:request AS jsonb),:manifest,:git,:correlation,:principal,:now,:now FROM platform_services WHERE service_id=:service_id"""), {"uuid": request_id, "service_id": body.service_id, "env": body.environment, "request": json.dumps(payload), "manifest": body.manifest_sha256, "git": body.git_sha, "correlation": x_correlation_id or str(request_id), "principal": actor.subject, "now": now()})
    await db.commit()
    return {"request_id": str(request_id), "state": "requested", "apply_authorized": False}


@router.get("/provisioning/requests/{request_id}", dependencies=[Depends(require_platform_scope("platform.provisioning.read"))])
async def get_provisioning(request_id: UUID, db: AsyncSession = Depends(get_session)):
    row = (await db.execute(text("SELECT id,environment,state,request_json,manifest_sha256,git_sha,correlation_id,requested_by,validation_json,approved_by,created_at,updated_at FROM platform_provisioning_requests WHERE id=:id"), {"id": request_id})).mappings().one_or_none()
    if row is None:
        raise HTTPException(404, "provisioning request not found")
    return dict(row)


async def transition(
    request_id: UUID,
    allowed: set[str],
    target: str,
    body: Transition,
    role: str,
    principal: str,
    db: AsyncSession,
    validation: dict[str, bool] | None = None,
):
    require_role(role, {"platform_admin"} if target in {"apply_requested", "rollback_requested"} else ADMIN_ROLES)
    if not principal:
        raise HTTPException(401, "authenticated principal is required")
    current = await get_provisioning(request_id, db)
    if current["state"] not in allowed:
        raise HTTPException(409, f"cannot transition {current['state']} to {target}")
    evidence = validation if validation is not None else current.get("validation_json")
    if target == "approved" and principal == current["requested_by"]:
        raise HTTPException(403, "requester cannot approve their own provisioning request")
    result = await db.execute(text("""UPDATE platform_provisioning_requests
      SET state=:state,validation_json=CAST(:validation AS jsonb),
          approved_by=CASE WHEN :state='approved' THEN :principal ELSE approved_by END,
          updated_at=:now
      WHERE id=:id AND state=ANY(CAST(:allowed AS text[])) RETURNING id"""), {
        "state": target, "validation": json.dumps(evidence), "principal": principal,
        "now": now(), "id": request_id, "allowed": sorted(allowed),
    })
    if result.scalar_one_or_none() is None:
        await db.rollback()
        raise HTTPException(409, "provisioning state changed concurrently")
    await db.execute(text("INSERT INTO platform_provisioning_audit(id,request_id,from_state,to_state,actor_role,reason,record_hash,created_at) VALUES (:id,:request,:from_state,:to_state,:actor,:reason,:hash,:now)"), {"id": uuid4(), "request": request_id, "from_state": current["state"], "to_state": target, "actor": f"{role}:{principal}", "reason": body.reason, "hash": audit_hash({"id": str(request_id), "from": current["state"], "to": target, "role": role, "principal": principal, "reason": body.reason}), "now": now()})
    await db.commit()
    return {"request_id": str(request_id), "state": target, "apply_authorized": False}


@router.post("/provisioning/requests/{request_id}/validate")
async def validate_provisioning(request_id: UUID, body: CertificationSubmission, actor: PlatformPrincipal = Depends(require_platform_scope("platform.provisioning.validate", frozenset({"platform_admin", "platform_reviewer"}))), db: AsyncSession = Depends(get_session)):
    evidence = body.evidence()
    failed = sorted(name for name, passed in evidence.items() if not passed)
    if failed:
        raise HTTPException(422, {"message": "certification gates failed", "failed_gates": failed})
    return await transition(request_id, {"requested"}, "validated", body, actor.role, actor.subject, db, evidence)


@router.post("/provisioning/requests/{request_id}/approve")
async def approve_provisioning(request_id: UUID, body: Transition, actor: PlatformPrincipal = Depends(require_platform_scope("platform.provisioning.approve", frozenset({"platform_admin", "platform_reviewer"}))), db: AsyncSession = Depends(get_session)):
    return await transition(request_id, {"validated"}, "approved", body, actor.role, actor.subject, db)


@router.post("/provisioning/requests/{request_id}/apply")
async def apply_provisioning(request_id: UUID, body: Transition, actor: PlatformPrincipal = Depends(require_platform_scope("platform.provisioning.apply", frozenset({"platform_admin"}))), db: AsyncSession = Depends(get_session)):
    return await transition(request_id, {"approved"}, "apply_requested", body, actor.role, actor.subject, db)


@router.post("/provisioning/requests/{request_id}/rollback")
async def rollback_provisioning(request_id: UUID, body: Transition, actor: PlatformPrincipal = Depends(require_platform_scope("platform.provisioning.rollback", frozenset({"platform_admin"}))), db: AsyncSession = Depends(get_session)):
    return await transition(request_id, {"applied", "failed"}, "rollback_requested", body, actor.role, actor.subject, db)
