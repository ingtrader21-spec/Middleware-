"""Framework-neutral connector catalog service used by API handlers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .errors import (
    ConnectorNotFoundError,
    ConnectorVersionConflictError,
)
from .manifest import manifest_digest, parse_manifest
from .models import ConnectorManifest, ConnectorState
from .registry import ConnectorRegistry
from .standards import SemanticVersion


class ConnectorCatalogService:
    """Pure application service for connector-management API adapters.

    Persistent installations should wrap this service with a transactional
    repository. Secret values are never accepted or returned here.
    """

    def __init__(self, registry: ConnectorRegistry) -> None:
        self._registry = registry

    def list_connectors(self) -> list[dict[str, Any]]:
        return [self._projection(record) for record in self._registry.list()]

    def get_connector(self, connector_id: str) -> dict[str, Any]:
        return self._projection(self._registry.get(connector_id))

    def _assert_candidate_invariants(self, candidate: ConnectorManifest) -> None:
        """Validate a candidate against the complete current registry.

        Validation occurs before any mutation, so a prefix or webhook conflict
        cannot partially install a connector and corrupt the catalog.
        """
        errors: list[str] = []
        for record in self._registry.list():
            existing = record.manifest
            if existing.connector_id == candidate.connector_id:
                continue
            for incoming in candidate.command_policies:
                for current in existing.command_policies:
                    if (
                        incoming.prefix.startswith(current.prefix)
                        or current.prefix.startswith(incoming.prefix)
                    ):
                        errors.append(
                            "command prefix conflict: "
                            f"{incoming.prefix} ({candidate.connector_id}) and "
                            f"{current.prefix} ({existing.connector_id})"
                        )
            existing_routes = {
                webhook.route_path for webhook in existing.webhook_policies
            }
            for webhook in candidate.webhook_policies:
                if webhook.route_path in existing_routes:
                    errors.append(
                        "webhook route conflict: "
                        f"{webhook.route_path} belongs to "
                        f"{existing.connector_id} and {candidate.connector_id}"
                    )
        if errors:
            raise ConnectorVersionConflictError("; ".join(sorted(set(errors))))

    def validate_candidate(
        self,
        raw_manifest: Mapping[str, Any],
    ) -> dict[str, Any]:
        manifest = parse_manifest(raw_manifest)
        self._assert_candidate_invariants(manifest)
        warnings: list[str] = []
        if manifest.runtime_binding.status == "UNVERIFIED_TEMPLATE_ONLY":
            warnings.append("runtime binding is not verified")
        return {
            "valid": True,
            "connector_id": manifest.connector_id,
            "version": manifest.version,
            "manifest_digest": manifest_digest(raw_manifest),
            "warnings": warnings,
        }

    def install_disabled(
        self,
        raw_manifest: Mapping[str, Any],
        *,
        expected_digest: str,
    ) -> dict[str, Any]:
        actual = manifest_digest(raw_manifest)
        if actual != expected_digest:
            raise ValueError("manifest digest does not match expected digest")
        manifest = parse_manifest(raw_manifest)
        self._assert_candidate_invariants(manifest)
        try:
            existing = self._registry.get(manifest.connector_id)
        except ConnectorNotFoundError:
            existing = None

        if existing is None:
            record = self._registry.register_manifest(
                raw_manifest,
                state=ConnectorState.INSTALLED_DISABLED,
            )
            return self._projection(record)

        incoming_version = SemanticVersion.parse(manifest.version)
        existing_version = SemanticVersion.parse(existing.manifest.version)
        if incoming_version < existing_version:
            raise ConnectorVersionConflictError(
                "connector version cannot move backwards"
            )
        if incoming_version == existing_version:
            if actual != existing.manifest_digest:
                raise ConnectorVersionConflictError(
                    "the same semantic version cannot carry a new digest"
                )
            if existing.state is ConnectorState.DECLARED:
                self._registry.set_state(
                    manifest.connector_id,
                    expected_state=ConnectorState.DECLARED,
                    new_state=ConnectorState.VALIDATED,
                )
                existing = self._registry.set_state(
                    manifest.connector_id,
                    expected_state=ConnectorState.VALIDATED,
                    new_state=ConnectorState.INSTALLED_DISABLED,
                )
            elif existing.state is ConnectorState.VALIDATED:
                existing = self._registry.set_state(
                    manifest.connector_id,
                    expected_state=ConnectorState.VALIDATED,
                    new_state=ConnectorState.INSTALLED_DISABLED,
                )
            elif existing.state is not ConnectorState.INSTALLED_DISABLED:
                raise ValueError(
                    f"connector cannot be installed over {existing.state.value}"
                )
            return self._projection(existing)

        record = self._registry.register_manifest(
            raw_manifest,
            state=ConnectorState.INSTALLED_DISABLED,
            replace=True,
        )
        return self._projection(record)

    def disable(
        self,
        connector_id: str,
        *,
        expected_state: ConnectorState,
    ) -> dict[str, Any]:
        record = self._registry.set_state(
            connector_id,
            expected_state=expected_state,
            new_state=ConnectorState.SUSPENDED,
        )
        return self._projection(record)

    @staticmethod
    def read_manifest(path: Path) -> Mapping[str, Any]:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError("manifest must be an object")
        return raw

    @staticmethod
    def _projection(record: Any) -> dict[str, Any]:
        manifest = record.manifest
        return {
            "connector_id": manifest.connector_id,
            "display_name": manifest.display_name,
            "version": manifest.version,
            "cell": manifest.cell.value,
            "repository": manifest.repository,
            "state": record.state.value,
            "manifest_digest": record.manifest_digest,
            "runtime_binding_status": manifest.runtime_binding.status,
            "workflow_families": list(manifest.workflow_families),
            "commands": [
                {
                    "prefix": item.prefix,
                    "required_capability": item.required_capability,
                    "readback_required": item.readback_required,
                }
                for item in manifest.command_policies
            ],
            "webhooks": [
                {
                    "endpoint_key": item.endpoint_key,
                    "route_path": item.route_path,
                }
                for item in manifest.webhook_policies
            ],
        }
