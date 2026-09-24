"""Transactional PostgreSQL projections with replay evidence and ordered events.

The metadata is also usable against SQLite in isolated unit tests. Runtime never
creates tables: apply the reviewed Alembic migration before enabling the routes.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    Index,
    JSON,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    and_,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError

metadata = MetaData()
resources = Table(
    "monitoring_resources",
    metadata,
    Column("tenant", String(128), primary_key=True),
    Column("kind", String(32), primary_key=True),
    Column("resource_key", String(512), primary_key=True),
    Column("service_id", String(128), nullable=False),
    Column("environment", String(32), nullable=False),
    Column("campaign_id", String(128)),
    Column("source_deployment", String(128), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("payload", JSON, nullable=False),
)
Index(
    "ix_monitoring_resource_scope",
    resources.c.tenant,
    resources.c.kind,
    resources.c.service_id,
    resources.c.environment,
)
operations = Table(
    "monitoring_operations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("tenant", String(128), nullable=False),
    Column("actor", String(255), nullable=False),
    Column("operation", String(256), nullable=False),
    Column("idempotency_key", String(128), nullable=False),
    Column("digest", String(64), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("result", JSON, nullable=False),
    UniqueConstraint(
        "tenant",
        "actor",
        "operation",
        "idempotency_key",
        name="uq_monitoring_operation_replay",
    ),
)
events = Table(
    "monitoring_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant", String(128), nullable=False),
    Column("topic", String(64), nullable=False),
    Column("campaign_id", String(128)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("data", JSON, nullable=False),
)
Index("ix_monitoring_event_scope", events.c.tenant, events.c.id)


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


class Store:
    def __init__(self, db):
        self.db = db

    async def get(self, tenant, kind, key):
        return (
            (
                await self.db.execute(
                    select(resources).where(
                        resources.c.tenant == tenant,
                        resources.c.kind == kind,
                        resources.c.resource_key == key,
                    )
                )
            )
            .mappings()
            .one_or_none()
        )

    async def list(
        self,
        tenant,
        kind=None,
        *,
        service=None,
        environment=None,
        host_id=None,
        resource_id=None,
        campaigns=None,
        cursor="",
        limit=100,
    ):
        q = select(resources).where(
            resources.c.tenant == tenant, resources.c.resource_key > cursor
        )
        if kind:
            q = q.where(resources.c.kind == kind)
        if service:
            q = q.where(resources.c.service_id == service)
        if environment:
            q = q.where(resources.c.environment == environment)
        if host_id is not None:
            q = q.where(resources.c.payload["host_id"].as_string() == host_id)
        if resource_id is not None:
            q = q.where(
                resources.c.resource_key
                == resources.c.environment
                + ":"
                + resources.c.service_id
                + ":"
                + resources.c.source_deployment
                + ":"
                + resource_id
            )
        if campaigns is not None:
            q = q.where(resources.c.campaign_id.in_(list(campaigns)))
        return list(
            (
                await self.db.execute(q.order_by(resources.c.resource_key).limit(limit))
            ).mappings()
        )

    async def put(
        self,
        tenant,
        kind,
        key,
        data,
        *,
        service,
        environment,
        source,
        sequence,
        observed_at,
        campaign=None,
        expected_revision=None,
    ):
        old = await self.get(tenant, kind, key)
        revision = old["revision"] if old else 0
        if expected_revision is not None and revision != expected_revision:
            raise HTTPException(409, "resource revision conflict")
        if old and expected_revision is None:
            if source != old["source_deployment"]:
                raise HTTPException(
                    409,
                    "source deployment changed; rebind through approved configuration",
                )
            if sequence <= old["sequence"] or utc(observed_at) <= utc(
                old["observed_at"]
            ):
                raise HTTPException(409, "stale observation")
        values = dict(
            service_id=service,
            environment=environment,
            source_deployment=source,
            sequence=sequence,
            revision=revision + 1,
            observed_at=observed_at,
            payload=data,
            campaign_id=campaign,
        )
        if old:
            result = await self.db.execute(
                update(resources)
                .where(
                    and_(
                        resources.c.tenant == tenant,
                        resources.c.kind == kind,
                        resources.c.resource_key == key,
                        resources.c.revision == revision,
                    )
                )
                .values(**values)
            )
            if result.rowcount != 1:
                raise HTTPException(409, "concurrent observation")
        else:
            await self.db.execute(
                insert(resources).values(
                    tenant=tenant, kind=kind, resource_key=key, **values
                )
            )
        return revision + 1

    async def event(self, tenant, topic, data, campaign=None):
        await self.db.execute(
            insert(events).values(
                tenant=tenant,
                topic=topic,
                data=data,
                campaign_id=campaign,
                created_at=datetime.now(UTC),
            )
        )

    async def stream(self, tenant, after, campaigns=None, limit=100):
        q = select(events).where(events.c.tenant == tenant, events.c.id > after)
        if campaigns is not None:
            q = q.where(events.c.campaign_id.in_(list(campaigns)))
        return list(
            (await self.db.execute(q.order_by(events.c.id).limit(limit))).mappings()
        )

    async def operation(self, tenant, operation_id):
        row = (
            (
                await self.db.execute(
                    select(operations).where(
                        operations.c.tenant == tenant, operations.c.id == operation_id
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise HTTPException(404, "operation not found")
        return row

    async def mutate(self, principal, operation, key, payload, action):
        """Projection, event and replay response commit in one transaction."""
        where = and_(
            operations.c.tenant == principal.tenant,
            operations.c.actor == principal.subject,
            operations.c.operation == operation,
            operations.c.idempotency_key == key,
        )
        body_digest = digest(payload)

        async def replay():
            row = (
                (await self.db.execute(select(operations).where(where)))
                .mappings()
                .one_or_none()
            )
            if row:
                if row["digest"] != body_digest:
                    raise HTTPException(409, "idempotency payload conflict")
                return row["result"]

        prior = await replay()
        if prior is not None:
            return prior
        operation_id = str(uuid4())
        try:
            # Acquire unique replay identity before applying any state mutation.
            await self.db.execute(
                insert(operations).values(
                    id=operation_id,
                    tenant=principal.tenant,
                    actor=principal.subject,
                    operation=operation,
                    idempotency_key=key,
                    digest=body_digest,
                    created_at=datetime.now(UTC),
                    result={},
                )
            )
            result = await action(operation_id)
            result["operation_id"] = operation_id
            await self.db.execute(
                update(operations)
                .where(operations.c.id == operation_id)
                .values(result=result)
            )
            await self.db.commit()
            return result
        except IntegrityError:
            await self.db.rollback()
            prior = await replay()
            if prior is not None:
                return prior
            raise HTTPException(409, "concurrent resource update") from None
        except Exception:
            await self.db.rollback()
            raise
