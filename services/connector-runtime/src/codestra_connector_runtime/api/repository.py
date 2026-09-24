"""Transactional persistence for the Connector Management API."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import RowMapping, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from middleware.connector_sdk import manifest_digest, parse_manifest
from middleware.connector_sdk.errors import ManifestValidationError

from .config import RuntimeSettings
from .database import Database
from .problems import ProblemError


@dataclass(frozen=True, slots=True)
class IdempotentReplay:
    status: int
    body: dict[str, Any]


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _row_dict(row: RowMapping | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _etag_version(if_match: str | None) -> int:
    if if_match is None:
        raise ProblemError(
            status=428,
            code="PRECONDITION_REQUIRED",
            title="Precondition required",
            detail="If-Match is required for this operation.",
        )
    value = if_match.strip()
    if value.startswith("W/"):
        value = value[2:]
    value = value.strip('"')
    if value.startswith("v"):
        value = value[1:]
    try:
        version = int(value)
    except ValueError as error:
        raise ProblemError(
            status=400,
            code="ETAG_INVALID",
            title="Invalid ETag",
            detail="If-Match must contain a resource version.",
        ) from error
    if version < 1:
        raise ProblemError(
            status=400,
            code="ETAG_INVALID",
            title="Invalid ETag",
            detail="If-Match must contain a positive resource version.",
        )
    return version


class ConnectorRepository:
    def __init__(self, database: Database, settings: RuntimeSettings) -> None:
        self.database = database
        self.settings = settings

    @staticmethod
    def _claim_idempotency(
        session: Session,
        *,
        tenant_id: UUID,
        scope: str,
        key: str,
        request_sha256: str,
    ) -> IdempotentReplay | None:
        inserted = session.execute(
            text(
                """
                INSERT INTO connector_sdk.connector_idempotency_keys
                  (tenant_id, scope, idempotency_key, request_sha256)
                VALUES (:tenant_id, :scope, :key, :request_sha256)
                ON CONFLICT DO NOTHING
                RETURNING idempotency_key
                """
            ),
            {
                "tenant_id": tenant_id,
                "scope": scope,
                "key": key,
                "request_sha256": request_sha256,
            },
        ).scalar_one_or_none()
        if inserted is not None:
            return None
        prior = session.execute(
            text(
                """
                SELECT request_sha256, response_status, response_body
                  FROM connector_sdk.connector_idempotency_keys
                 WHERE tenant_id=:tenant_id AND scope=:scope
                   AND idempotency_key=:key
                 FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "scope": scope, "key": key},
        ).mappings().one()
        if prior["request_sha256"] != request_sha256:
            raise ProblemError(
                status=409,
                code="IDEMPOTENCY_CONFLICT",
                title="Idempotency conflict",
                detail="The idempotency key was already used with a different request.",
            )
        if prior["response_status"] is None or prior["response_body"] is None:
            raise ProblemError(
                status=409,
                code="IDEMPOTENCY_IN_PROGRESS",
                title="Request already in progress",
                detail="The original request is still being processed.",
                headers={"Retry-After": "1"},
            )
        return IdempotentReplay(
            status=int(prior["response_status"]),
            body=dict(prior["response_body"]),
        )

    @staticmethod
    def _complete_idempotency(
        session: Session,
        *,
        tenant_id: UUID,
        scope: str,
        key: str,
        operation_id: UUID,
        status: int,
        body: dict[str, Any],
    ) -> None:
        session.execute(
            text(
                """
                UPDATE connector_sdk.connector_idempotency_keys
                   SET operation_id=:operation_id,
                       response_status=:status,
                       response_body=CAST(:body AS jsonb)
                 WHERE tenant_id=:tenant_id AND scope=:scope
                   AND idempotency_key=:key
                """
            ),
            {
                "tenant_id": tenant_id,
                "scope": scope,
                "key": key,
                "operation_id": operation_id,
                "status": status,
                "body": json.dumps(body, default=str),
            },
        )

    @staticmethod
    def _audit(
        session: Session,
        *,
        tenant_id: UUID | None,
        actor_subject: str,
        actor_type: str,
        action: str,
        resource_type: str,
        resource_id: str,
        correlation_id: UUID,
        request_id: str | None,
        safe_metadata: dict[str, Any] | None = None,
    ) -> None:
        session.execute(
            text(
                """
                INSERT INTO connector_sdk.connector_audit_log
                  (audit_id, tenant_id, actor_subject, actor_type, action,
                   resource_type, resource_id, correlation_id, request_id,
                   safe_metadata)
                VALUES (:audit_id, :tenant_id, :actor_subject, :actor_type,
                        :action, :resource_type, :resource_id, :correlation_id,
                        :request_id, CAST(:safe_metadata AS jsonb))
                """
            ),
            {
                "audit_id": uuid4(),
                "tenant_id": tenant_id,
                "actor_subject": actor_subject,
                "actor_type": actor_type,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "correlation_id": correlation_id,
                "request_id": request_id,
                "safe_metadata": json.dumps(safe_metadata or {}),
            },
        )

    @staticmethod
    def _outbox(
        session: Session,
        *,
        tenant_id: UUID,
        aggregate_type: str,
        aggregate_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        correlation_id: UUID,
        causation_id: str,
        traceparent: str | None,
    ) -> None:
        session.execute(
            text(
                """
                INSERT INTO connector_sdk.connector_outbox
                  (outbox_id, tenant_id, aggregate_type, aggregate_id,
                   event_type, event_version, payload, correlation_id,
                   causation_id, traceparent)
                VALUES (:outbox_id, :tenant_id, :aggregate_type, :aggregate_id,
                        :event_type, 1, CAST(:payload AS jsonb), :correlation_id,
                        :causation_id, :traceparent)
                """
            ),
            {
                "outbox_id": uuid4(),
                "tenant_id": tenant_id,
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "event_type": event_type,
                "payload": json.dumps(payload, default=str),
                "correlation_id": correlation_id,
                "causation_id": causation_id,
                "traceparent": traceparent,
            },
        )

    def list_connectors(self, *, limit: int, after: str | None) -> list[dict[str, Any]]:
        with self.database.session() as session:
            rows = session.execute(
                text(
                    """
                    SELECT i.connector_id,
                           COALESCE(m.manifest->>'display_name', i.connector_id) AS display_name,
                           i.current_version AS version,
                           i.cell,
                           i.state,
                           i.current_manifest_digest AS manifest_digest,
                           COALESCE(m.manifest#>>'{runtime_binding,status}', 'UNKNOWN') AS runtime_binding_status,
                           COALESCE(m.manifest->'workflow_families', '[]'::jsonb) AS workflow_families,
                           i.resource_version
                      FROM connector_sdk.connector_installations i
                      JOIN connector_sdk.connector_manifests m
                        ON m.connector_id=i.connector_id
                       AND m.version=i.current_version
                       AND m.manifest_digest=i.current_manifest_digest
                     WHERE i.environment=:environment
                       AND (:after IS NULL OR i.connector_id > :after)
                     ORDER BY i.connector_id
                     LIMIT :limit
                    """
                ),
                {
                    "environment": self.settings.environment,
                    "after": after,
                    "limit": limit,
                },
            ).mappings().all()
        return [dict(row) for row in rows]

    def get_connector(self, connector_id: str) -> dict[str, Any]:
        with self.database.session() as session:
            row = session.execute(
                text(
                    """
                    SELECT i.connector_id,
                           COALESCE(m.manifest->>'display_name', i.connector_id) AS display_name,
                           i.current_version AS version,
                           i.cell,
                           i.state,
                           i.current_manifest_digest AS manifest_digest,
                           COALESCE(m.manifest#>>'{runtime_binding,status}', 'UNKNOWN') AS runtime_binding_status,
                           COALESCE(m.manifest->'workflow_families', '[]'::jsonb) AS workflow_families,
                           i.resource_version,
                           m.manifest
                      FROM connector_sdk.connector_installations i
                      JOIN connector_sdk.connector_manifests m
                        ON m.connector_id=i.connector_id
                       AND m.version=i.current_version
                       AND m.manifest_digest=i.current_manifest_digest
                     WHERE i.environment=:environment
                       AND i.connector_id=:connector_id
                    """
                ),
                {
                    "environment": self.settings.environment,
                    "connector_id": connector_id,
                },
            ).mappings().one_or_none()
        if row is None:
            raise ProblemError(
                status=404,
                code="CONNECTOR_NOT_FOUND",
                title="Connector not found",
                detail="The connector is not installed in this environment.",
            )
        return dict(row)

    def install_disabled(
        self,
        *,
        tenant_id: UUID,
        manifest_raw: dict[str, Any],
        expected_digest: str,
        idempotency_key: str,
        actor_subject: str,
        correlation_id: UUID,
        request_id: str | None,
        traceparent: str | None,
    ) -> IdempotentReplay | tuple[int, dict[str, Any]]:
        try:
            manifest = parse_manifest(manifest_raw)
        except ManifestValidationError as error:
            raise ProblemError(
                status=422,
                code="MANIFEST_INVALID",
                title="Connector manifest invalid",
                detail="The connector manifest violates the v1 contract.",
                extensions={"errors": list(error.errors)},
            ) from error
        actual_digest = manifest_digest(manifest_raw)
        if actual_digest != expected_digest:
            raise ProblemError(
                status=409,
                code="MANIFEST_DIGEST_CONFLICT",
                title="Manifest digest conflict",
                detail="The manifest does not match the expected digest.",
            )
        request_hash = _canonical_sha256(
            {"manifest": manifest_raw, "expected_manifest_digest": expected_digest}
        )
        operation_id = uuid4()
        with self.database.session(tenant_id) as session:
            replay = self._claim_idempotency(
                session,
                tenant_id=tenant_id,
                scope="connector.install",
                key=idempotency_key,
                request_sha256=request_hash,
            )
            if replay is not None:
                return replay
            existing = session.execute(
                text(
                    """
                    SELECT manifest_digest
                      FROM connector_sdk.connector_manifests
                     WHERE connector_id=:connector_id AND version=:version
                    """
                ),
                {"connector_id": manifest.connector_id, "version": manifest.version},
            ).scalar_one_or_none()
            if existing is not None and existing != actual_digest:
                raise ProblemError(
                    status=409,
                    code="CONNECTOR_VERSION_CONFLICT",
                    title="Connector version conflict",
                    detail="This connector version is already bound to another digest.",
                )
            session.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_manifests
                      (connector_id, version, manifest_digest, manifest,
                       created_by_subject)
                    VALUES (:connector_id, :version, :digest,
                            CAST(:manifest AS jsonb), :subject)
                    ON CONFLICT (connector_id, version) DO NOTHING
                    """
                ),
                {
                    "connector_id": manifest.connector_id,
                    "version": manifest.version,
                    "digest": actual_digest,
                    "manifest": json.dumps(manifest_raw),
                    "subject": actor_subject,
                },
            )
            installation_id = uuid4()
            try:
                session.execute(
                    text(
                        """
                        INSERT INTO connector_sdk.connector_installations
                          (installation_id, connector_id, environment, cell,
                           current_version, current_manifest_digest, state)
                        VALUES (:installation_id, :connector_id, :environment,
                                :cell, :version, :digest, 'INSTALLED_DISABLED')
                        """
                    ),
                    {
                        "installation_id": installation_id,
                        "connector_id": manifest.connector_id,
                        "environment": self.settings.environment,
                        "cell": manifest.cell.value,
                        "version": manifest.version,
                        "digest": actual_digest,
                    },
                )
            except IntegrityError as error:
                raise ProblemError(
                    status=409,
                    code="CONNECTOR_ALREADY_INSTALLED",
                    title="Connector already installed",
                    detail="The connector is already installed in this environment.",
                ) from error
            self._audit(
                session,
                tenant_id=tenant_id,
                actor_subject=actor_subject,
                actor_type="service",
                action="connector.install_disabled",
                resource_type="connector_installation",
                resource_id=str(installation_id),
                correlation_id=correlation_id,
                request_id=request_id,
                safe_metadata={
                    "connector_id": manifest.connector_id,
                    "version": manifest.version,
                    "manifest_digest": actual_digest,
                },
            )
            self._outbox(
                session,
                tenant_id=tenant_id,
                aggregate_type="connector_installation",
                aggregate_id=installation_id,
                event_type="connector.installed-disabled.v1",
                payload={
                    "connector_id": manifest.connector_id,
                    "version": manifest.version,
                    "manifest_digest": actual_digest,
                    "environment": self.settings.environment,
                },
                correlation_id=correlation_id,
                causation_id=str(operation_id),
                traceparent=traceparent,
            )
            body = {
                "data": {
                    "operation_id": str(operation_id),
                    "status": "accepted",
                    "resource_version": 1,
                },
                "meta": {
                    "correlation_id": str(correlation_id),
                    "api_version": "v1",
                },
            }
            self._complete_idempotency(
                session,
                tenant_id=tenant_id,
                scope="connector.install",
                key=idempotency_key,
                operation_id=operation_id,
                status=202,
                body=body,
            )
        return 202, body

    def disable_connector(
        self,
        *,
        tenant_id: UUID,
        connector_id: str,
        expected_version: int,
        idempotency_key: str,
        actor_subject: str,
        correlation_id: UUID,
        request_id: str | None,
    ) -> IdempotentReplay | tuple[int, dict[str, Any]]:
        request_hash = _canonical_sha256(
            {"connector_id": connector_id, "resource_version": expected_version}
        )
        operation_id = uuid4()
        with self.database.session(tenant_id) as session:
            replay = self._claim_idempotency(
                session,
                tenant_id=tenant_id,
                scope="connector.disable",
                key=idempotency_key,
                request_sha256=request_hash,
            )
            if replay is not None:
                return replay
            row = session.execute(
                text(
                    """
                    UPDATE connector_sdk.connector_installations
                       SET state='SUSPENDED', suspended_at=now()
                     WHERE connector_id=:connector_id
                       AND environment=:environment
                       AND resource_version=:expected_version
                       AND state <> 'SUSPENDED'
                    RETURNING installation_id, resource_version
                    """
                ),
                {
                    "connector_id": connector_id,
                    "environment": self.settings.environment,
                    "expected_version": expected_version,
                },
            ).mappings().one_or_none()
            if row is None:
                raise ProblemError(
                    status=412,
                    code="RESOURCE_VERSION_CONFLICT",
                    title="Resource version conflict",
                    detail="The connector state changed before this request was applied.",
                )
            self._audit(
                session,
                tenant_id=tenant_id,
                actor_subject=actor_subject,
                actor_type="service",
                action="connector.disable",
                resource_type="connector_installation",
                resource_id=str(row["installation_id"]),
                correlation_id=correlation_id,
                request_id=request_id,
                safe_metadata={"connector_id": connector_id},
            )
            body = {
                "data": {
                    "operation_id": str(operation_id),
                    "status": "accepted",
                    "resource_version": int(row["resource_version"]),
                },
                "meta": {
                    "correlation_id": str(correlation_id),
                    "api_version": "v1",
                },
            }
            self._complete_idempotency(
                session,
                tenant_id=tenant_id,
                scope="connector.disable",
                key=idempotency_key,
                operation_id=operation_id,
                status=202,
                body=body,
            )
        return 202, body

    def create_connection(
        self,
        *,
        tenant_id: UUID,
        connector_id: str,
        external_account_reference: str | None,
        configuration: dict[str, Any],
        secret_references: list[str],
        idempotency_key: str,
        actor_subject: str,
        correlation_id: UUID,
        request_id: str | None,
    ) -> IdempotentReplay | tuple[int, dict[str, Any]]:
        request_payload = {
            "connector_id": connector_id,
            "external_account_reference": external_account_reference,
            "configuration": configuration,
            "secret_references": secret_references,
        }
        request_hash = _canonical_sha256(request_payload)
        operation_id = uuid4()
        connection_id = uuid4()
        provider_hash = hashlib.sha256(
            (str(tenant_id) + ":" + connector_id + ":" + (external_account_reference or str(connection_id))).encode()
        ).hexdigest()
        with self.database.session(tenant_id) as session:
            replay = self._claim_idempotency(
                session,
                tenant_id=tenant_id,
                scope="connection.create",
                key=idempotency_key,
                request_sha256=request_hash,
            )
            if replay is not None:
                return replay
            installation_id = session.execute(
                text(
                    """
                    SELECT installation_id
                      FROM connector_sdk.connector_installations
                     WHERE connector_id=:connector_id
                       AND environment=:environment
                       AND state IN ('INSTALLED_DISABLED', 'ACTIVE')
                    """
                ),
                {
                    "connector_id": connector_id,
                    "environment": self.settings.environment,
                },
            ).scalar_one_or_none()
            if installation_id is None:
                raise ProblemError(
                    status=404,
                    code="CONNECTOR_NOT_INSTALLED",
                    title="Connector not installed",
                    detail="The connector is unavailable in this environment.",
                )
            session.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_connections
                      (connection_id, tenant_id, installation_id,
                       external_account_reference, provider_account_hash,
                       configuration, secret_references, state)
                    VALUES (:connection_id, :tenant_id, :installation_id,
                            :external_reference, :provider_hash,
                            CAST(:configuration AS jsonb),
                            CAST(:secret_references AS jsonb), 'PENDING')
                    """
                ),
                {
                    "connection_id": connection_id,
                    "tenant_id": tenant_id,
                    "installation_id": installation_id,
                    "external_reference": external_account_reference,
                    "provider_hash": provider_hash,
                    "configuration": json.dumps(configuration),
                    "secret_references": json.dumps(secret_references),
                },
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                actor_subject=actor_subject,
                actor_type="service",
                action="connection.create",
                resource_type="connector_connection",
                resource_id=str(connection_id),
                correlation_id=correlation_id,
                request_id=request_id,
                safe_metadata={"connector_id": connector_id},
            )
            body = {
                "data": {
                    "operation_id": str(operation_id),
                    "status": "accepted",
                    "resource_version": 1,
                },
                "meta": {
                    "correlation_id": str(correlation_id),
                    "api_version": "v1",
                },
            }
            self._complete_idempotency(
                session,
                tenant_id=tenant_id,
                scope="connection.create",
                key=idempotency_key,
                operation_id=operation_id,
                status=202,
                body=body,
            )
        return 202, body

    def get_connection(self, *, tenant_id: UUID, connection_id: UUID) -> dict[str, Any]:
        with self.database.session(tenant_id) as session:
            row = session.execute(
                text(
                    """
                    SELECT c.connection_id, c.tenant_id, i.connector_id,
                           c.external_account_reference, c.state,
                           c.resource_version, c.last_tested_at, c.last_test_code
                      FROM connector_sdk.connector_connections c
                      JOIN connector_sdk.connector_installations i
                        ON i.installation_id=c.installation_id
                     WHERE c.tenant_id=:tenant_id
                       AND c.connection_id=:connection_id
                    """
                ),
                {"tenant_id": tenant_id, "connection_id": connection_id},
            ).mappings().one_or_none()
        if row is None:
            raise ProblemError(
                status=404,
                code="CONNECTION_NOT_FOUND",
                title="Connection not found",
                detail="The connector connection was not found in this tenant.",
            )
        return dict(row)

    def list_webhooks(
        self,
        *,
        tenant_id: UUID,
        connection_id: UUID,
        limit: int,
        after: str | None,
    ) -> list[dict[str, Any]]:
        with self.database.session(tenant_id) as session:
            rows = session.execute(
                text(
                    """
                    SELECT w.webhook_id, w.connection_id, w.tenant_id,
                           i.connector_id, w.endpoint_key, w.public_path,
                           w.state, w.resource_version,
                           w.previous_secret_valid_until
                      FROM connector_sdk.connector_webhook_endpoints w
                      JOIN connector_sdk.connector_connections c
                        ON c.tenant_id=w.tenant_id
                       AND c.connection_id=w.connection_id
                      JOIN connector_sdk.connector_installations i
                        ON i.installation_id=c.installation_id
                     WHERE w.tenant_id=:tenant_id
                       AND w.connection_id=:connection_id
                       AND (:after IS NULL OR w.webhook_id::text > :after)
                     ORDER BY w.webhook_id
                     LIMIT :limit
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "connection_id": connection_id,
                    "after": after,
                    "limit": limit,
                },
            ).mappings().all()
        return [dict(row) for row in rows]

    def create_webhook(
        self,
        *,
        tenant_id: UUID,
        connection_id: UUID,
        endpoint_key: str,
        secret_reference_current: str,
        idempotency_key: str,
        actor_subject: str,
        correlation_id: UUID,
        request_id: str | None,
    ) -> IdempotentReplay | tuple[int, dict[str, Any]]:
        request_hash = _canonical_sha256(
            {
                "connection_id": str(connection_id),
                "endpoint_key": endpoint_key,
                "secret_reference_current": secret_reference_current,
            }
        )
        operation_id = uuid4()
        webhook_id = uuid4()
        with self.database.session(tenant_id) as session:
            replay = self._claim_idempotency(
                session,
                tenant_id=tenant_id,
                scope="webhook.create",
                key=idempotency_key,
                request_sha256=request_hash,
            )
            if replay is not None:
                return replay
            row = session.execute(
                text(
                    """
                    SELECT i.connector_id, m.manifest
                      FROM connector_sdk.connector_connections c
                      JOIN connector_sdk.connector_installations i
                        ON i.installation_id=c.installation_id
                      JOIN connector_sdk.connector_manifests m
                        ON m.connector_id=i.connector_id
                       AND m.version=i.current_version
                       AND m.manifest_digest=i.current_manifest_digest
                     WHERE c.tenant_id=:tenant_id
                       AND c.connection_id=:connection_id
                    """
                ),
                {"tenant_id": tenant_id, "connection_id": connection_id},
            ).mappings().one_or_none()
            if row is None:
                raise ProblemError(
                    status=404,
                    code="CONNECTION_NOT_FOUND",
                    title="Connection not found",
                    detail="The connector connection was not found in this tenant.",
                )
            manifest = parse_manifest(dict(row["manifest"]))
            policy = manifest.webhook_policy_for(endpoint_key)
            if policy is None:
                raise ProblemError(
                    status=422,
                    code="WEBHOOK_ENDPOINT_NOT_DECLARED",
                    title="Webhook endpoint not declared",
                    detail="The connector manifest does not declare this endpoint.",
                )
            public_path = f"/v1/webhooks/{manifest.connector_id}/{endpoint_key}/{webhook_id}"
            session.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_webhook_endpoints
                      (webhook_id, tenant_id, connection_id, endpoint_key,
                       route_template, public_path, secret_reference_current,
                       state)
                    VALUES (:webhook_id, :tenant_id, :connection_id,
                            :endpoint_key, :route_template, :public_path,
                            :secret_reference_current, 'DISABLED')
                    """
                ),
                {
                    "webhook_id": webhook_id,
                    "tenant_id": tenant_id,
                    "connection_id": connection_id,
                    "endpoint_key": endpoint_key,
                    "route_template": policy.route_path,
                    "public_path": public_path,
                    "secret_reference_current": secret_reference_current,
                },
            )
            self._audit(
                session,
                tenant_id=tenant_id,
                actor_subject=actor_subject,
                actor_type="service",
                action="webhook.create_disabled",
                resource_type="connector_webhook",
                resource_id=str(webhook_id),
                correlation_id=correlation_id,
                request_id=request_id,
                safe_metadata={
                    "connector_id": manifest.connector_id,
                    "endpoint_key": endpoint_key,
                },
            )
            body = {
                "data": {
                    "operation_id": str(operation_id),
                    "status": "accepted",
                    "resource_version": 1,
                },
                "meta": {
                    "correlation_id": str(correlation_id),
                    "api_version": "v1",
                },
            }
            self._complete_idempotency(
                session,
                tenant_id=tenant_id,
                scope="webhook.create",
                key=idempotency_key,
                operation_id=operation_id,
                status=202,
                body=body,
            )
        return 202, body

    def get_webhook(self, *, tenant_id: UUID, webhook_id: UUID) -> dict[str, Any]:
        with self.database.session(tenant_id) as session:
            row = session.execute(
                text(
                    """
                    SELECT w.webhook_id, w.connection_id, w.tenant_id,
                           i.connector_id, w.endpoint_key, w.public_path,
                           w.state, w.resource_version,
                           w.previous_secret_valid_until
                      FROM connector_sdk.connector_webhook_endpoints w
                      JOIN connector_sdk.connector_connections c
                        ON c.tenant_id=w.tenant_id
                       AND c.connection_id=w.connection_id
                      JOIN connector_sdk.connector_installations i
                        ON i.installation_id=c.installation_id
                     WHERE w.tenant_id=:tenant_id AND w.webhook_id=:webhook_id
                    """
                ),
                {"tenant_id": tenant_id, "webhook_id": webhook_id},
            ).mappings().one_or_none()
        if row is None:
            raise ProblemError(
                status=404,
                code="WEBHOOK_NOT_FOUND",
                title="Webhook not found",
                detail="The webhook endpoint was not found in this tenant.",
            )
        return dict(row)

    def rotate_webhook_secret(
        self,
        *,
        tenant_id: UUID,
        webhook_id: UUID,
        expected_version: int,
        new_secret_reference: str,
        overlap_seconds: int,
        idempotency_key: str,
        actor_subject: str,
        correlation_id: UUID,
        request_id: str | None,
    ) -> IdempotentReplay | tuple[int, dict[str, Any]]:
        request_hash = _canonical_sha256(
            {
                "webhook_id": str(webhook_id),
                "expected_version": expected_version,
                "new_secret_reference": new_secret_reference,
                "overlap_seconds": overlap_seconds,
            }
        )
        operation_id = uuid4()
        with self.database.session(tenant_id) as session:
            replay = self._claim_idempotency(
                session,
                tenant_id=tenant_id,
                scope="webhook.rotate",
                key=idempotency_key,
                request_sha256=request_hash,
            )
            if replay is not None:
                return replay
            row = session.execute(
                text(
                    """
                    UPDATE connector_sdk.connector_webhook_endpoints
                       SET secret_reference_previous=secret_reference_current,
                           previous_secret_valid_until=now() + (:overlap_seconds || ' seconds')::interval,
                           secret_reference_current=:new_secret,
                           state='DISABLED'
                     WHERE tenant_id=:tenant_id AND webhook_id=:webhook_id
                       AND resource_version=:expected_version
                    RETURNING resource_version
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "webhook_id": webhook_id,
                    "expected_version": expected_version,
                    "overlap_seconds": overlap_seconds,
                    "new_secret": new_secret_reference,
                },
            ).mappings().one_or_none()
            if row is None:
                raise ProblemError(
                    status=412,
                    code="RESOURCE_VERSION_CONFLICT",
                    title="Resource version conflict",
                    detail="The webhook state changed before this request was applied.",
                )
            self._audit(
                session,
                tenant_id=tenant_id,
                actor_subject=actor_subject,
                actor_type="service",
                action="webhook.rotate_secret_reference",
                resource_type="connector_webhook",
                resource_id=str(webhook_id),
                correlation_id=correlation_id,
                request_id=request_id,
                safe_metadata={"overlap_seconds": overlap_seconds},
            )
            body = {
                "data": {
                    "operation_id": str(operation_id),
                    "status": "accepted",
                    "resource_version": int(row["resource_version"]),
                },
                "meta": {
                    "correlation_id": str(correlation_id),
                    "api_version": "v1",
                },
            }
            self._complete_idempotency(
                session,
                tenant_id=tenant_id,
                scope="webhook.rotate",
                key=idempotency_key,
                operation_id=operation_id,
                status=202,
                body=body,
            )
        return 202, body

    def list_deliveries(
        self,
        *,
        tenant_id: UUID,
        webhook_id: UUID,
        limit: int,
        after: str | None,
    ) -> list[dict[str, Any]]:
        with self.database.session(tenant_id) as session:
            rows = session.execute(
                text(
                    """
                    SELECT inbox_id, webhook_id, event_id, body_sha256,
                           verification_state, processing_state, correlation_id,
                           received_at, processed_at, error_code
                      FROM connector_sdk.connector_webhook_inbox
                     WHERE tenant_id=:tenant_id AND webhook_id=:webhook_id
                       AND (:after IS NULL OR inbox_id::text > :after)
                     ORDER BY inbox_id
                     LIMIT :limit
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "webhook_id": webhook_id,
                    "after": after,
                    "limit": limit,
                },
            ).mappings().all()
        return [dict(row) for row in rows]

    def resolve_ingress_webhook(
        self,
        *,
        connector_id: str,
        endpoint_key: str,
        webhook_id: UUID,
    ) -> dict[str, Any]:
        with self.database.engine.connect() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT *
                      FROM connector_sdk.resolve_webhook_ingress(:webhook_id)
                    """
                ),
                {"webhook_id": webhook_id},
            ).mappings().one_or_none()
        if (
            row is None
            or row["connector_id"] != connector_id
            or row["endpoint_key"] != endpoint_key
        ):
            raise ProblemError(
                status=404,
                code="WEBHOOK_NOT_FOUND",
                title="Webhook not found",
                detail="The webhook route is not registered.",
            )
        return dict(row)

    def webhook_body_reference_state(
        self,
        *,
        tenant_id: UUID,
        webhook_id: UUID,
        event_id: str,
        body_sha256: str,
        encrypted_body_reference: str,
    ) -> str:
        """Classify a journaled body after an uncertain transaction outcome."""
        with self.database.session(tenant_id) as session:
            row = session.execute(
                text(
                    """
                    SELECT body_sha256, encrypted_body_reference
                      FROM connector_sdk.connector_webhook_inbox
                     WHERE tenant_id=:tenant_id
                       AND webhook_id=:webhook_id
                       AND event_id=:event_id
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "webhook_id": webhook_id,
                    "event_id": event_id,
                },
            ).mappings().one_or_none()
        if row is None:
            return "unreferenced"
        if (
            str(row["body_sha256"]) == body_sha256
            and str(row["encrypted_body_reference"])
            == encrypted_body_reference
        ):
            return "accepted"
        return "rejected"

    def persist_verified_webhook(
        self,
        *,
        ingress: dict[str, Any],
        event_id: str,
        body_sha256: str,
        encrypted_body_reference: str,
        signature_version: str,
        correlation_id: UUID,
        traceparent: str | None,
    ) -> tuple[bool, UUID]:
        tenant_id = UUID(str(ingress["tenant_id"]))
        webhook_id = UUID(str(ingress["webhook_id"]))
        inbox_id = uuid4()
        with self.database.session(tenant_id) as session:
            inserted = session.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_webhook_event_keys
                      (tenant_id, webhook_id, event_id, body_sha256, expires_at)
                    VALUES (:tenant_id, :webhook_id, :event_id,
                            :body_sha256, now() + interval '7 days')
                    ON CONFLICT (webhook_id, event_id) DO NOTHING
                    RETURNING body_sha256
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "webhook_id": webhook_id,
                    "event_id": event_id,
                    "body_sha256": body_sha256,
                },
            ).scalar_one_or_none()
            duplicate = inserted is None
            accepted_digest = inserted
            if accepted_digest is None:
                accepted_digest = session.execute(
                    text(
                        """
                        SELECT body_sha256
                          FROM connector_sdk.connector_webhook_event_keys
                         WHERE tenant_id=:tenant_id AND webhook_id=:webhook_id
                           AND event_id=:event_id
                        """
                    ),
                    {
                        "tenant_id": tenant_id,
                        "webhook_id": webhook_id,
                        "event_id": event_id,
                    },
                ).scalar_one()
            if accepted_digest != body_sha256:
                raise ProblemError(
                    status=409,
                    code="WEBHOOK_SEMANTIC_CONFLICT",
                    title="Webhook semantic conflict",
                    detail="The provider event ID was reused with a different body.",
                )
            existing_inbox = session.execute(
                text(
                    """
                    SELECT inbox_id
                      FROM connector_sdk.connector_webhook_inbox
                     WHERE tenant_id=:tenant_id AND webhook_id=:webhook_id
                       AND event_id=:event_id
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "webhook_id": webhook_id,
                    "event_id": event_id,
                },
            ).scalar_one_or_none()
            if existing_inbox is not None:
                return True, UUID(str(existing_inbox))
            session.execute(
                text(
                    """
                    INSERT INTO connector_sdk.connector_webhook_inbox
                      (inbox_id, tenant_id, webhook_id, connector_id,
                       endpoint_key, event_id, body_sha256,
                       encrypted_body_reference, signature_version,
                       verification_state, processing_state, correlation_id,
                       traceparent, verified_at)
                    VALUES (:inbox_id, :tenant_id, :webhook_id,
                            :connector_id, :endpoint_key, :event_id,
                            :body_sha256, :encrypted_body_reference,
                            :signature_version, 'VERIFIED', 'PENDING',
                            :correlation_id, :traceparent, now())
                    """
                ),
                {
                    "inbox_id": inbox_id,
                    "tenant_id": tenant_id,
                    "webhook_id": webhook_id,
                    "connector_id": ingress["connector_id"],
                    "endpoint_key": ingress["endpoint_key"],
                    "event_id": event_id,
                    "body_sha256": body_sha256,
                    "encrypted_body_reference": encrypted_body_reference,
                    "signature_version": signature_version,
                    "correlation_id": correlation_id,
                    "traceparent": traceparent,
                },
            )
            self._outbox(
                session,
                tenant_id=tenant_id,
                aggregate_type="connector_webhook_inbox",
                aggregate_id=inbox_id,
                event_type="connector.webhook.accepted.v1",
                payload={
                    "inbox_id": str(inbox_id),
                    "connector_id": ingress["connector_id"],
                    "endpoint_key": ingress["endpoint_key"],
                    "event_id": event_id,
                    "body_sha256": body_sha256,
                },
                correlation_id=correlation_id,
                causation_id=event_id,
                traceparent=traceparent,
            )
        return duplicate, inbox_id


__all__ = [
    "ConnectorRepository",
    "IdempotentReplay",
    "_etag_version",
]
