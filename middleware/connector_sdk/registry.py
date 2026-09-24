"""Trusted connector manifest and adapter-factory registry."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import (
    CommandNotAllowedError,
    ConnectorNotFoundError,
    ConnectorStateError,
    ConnectorVersionConflictError,
)
from .interfaces import AdapterFactory
from .manifest import load_manifest, manifest_digest, parse_manifest
from .models import ConnectorManifest, ConnectorState
from .standards import SemanticVersion

_ALLOWED_TRANSITIONS: dict[ConnectorState, frozenset[ConnectorState]] = {
    ConnectorState.DECLARED: frozenset(
        {ConnectorState.VALIDATED, ConnectorState.FAILED}
    ),
    ConnectorState.VALIDATED: frozenset(
        {ConnectorState.INSTALLED_DISABLED, ConnectorState.FAILED}
    ),
    ConnectorState.INSTALLED_DISABLED: frozenset(
        {
            ConnectorState.ACTIVE,
            ConnectorState.SUSPENDED,
            ConnectorState.FAILED,
        }
    ),
    ConnectorState.ACTIVE: frozenset(
        {ConnectorState.SUSPENDED, ConnectorState.FAILED}
    ),
    ConnectorState.SUSPENDED: frozenset(
        {ConnectorState.INSTALLED_DISABLED, ConnectorState.FAILED}
    ),
    ConnectorState.FAILED: frozenset({ConnectorState.DECLARED}),
}


@dataclass(frozen=True, slots=True)
class RegisteredConnector:
    manifest: ConnectorManifest
    manifest_digest: str
    state: ConnectorState


class ConnectorRegistry:
    """In-process registry with explicit trusted adapter registration."""

    def __init__(self) -> None:
        self._connectors: dict[str, RegisteredConnector] = {}
        self._factories: dict[str, AdapterFactory] = {}
        self._lock = threading.RLock()

    def register_manifest(
        self,
        raw_manifest: Mapping[str, Any],
        *,
        state: ConnectorState = ConnectorState.DECLARED,
        replace: bool = False,
    ) -> RegisteredConnector:
        if state not in {
            ConnectorState.DECLARED,
            ConnectorState.VALIDATED,
            ConnectorState.INSTALLED_DISABLED,
        }:
            raise ConnectorStateError(
                "manifest registration cannot create an active, suspended, "
                "or failed connector"
            )
        manifest = parse_manifest(raw_manifest)
        digest = manifest_digest(raw_manifest)
        new_version = SemanticVersion.parse(manifest.version)

        with self._lock:
            existing = self._connectors.get(manifest.connector_id)
            if existing is None:
                record = RegisteredConnector(
                    manifest=manifest,
                    manifest_digest=digest,
                    state=state,
                )
                self._connectors[manifest.connector_id] = record
                return record

            if not replace:
                raise ConnectorVersionConflictError(
                    f"connector already registered: {manifest.connector_id}"
                )

            existing_version = SemanticVersion.parse(
                existing.manifest.version
            )
            if new_version < existing_version:
                raise ConnectorVersionConflictError(
                    "connector version cannot move backwards"
                )
            if new_version == existing_version:
                if digest != existing.manifest_digest:
                    raise ConnectorVersionConflictError(
                        "an existing semantic version is immutable and "
                        "cannot be replaced with a different manifest digest"
                    )
                return existing

            record = RegisteredConnector(
                manifest=manifest,
                manifest_digest=digest,
                state=state,
            )
            self._connectors[manifest.connector_id] = record
            return record

    def register_adapter_factory(
        self,
        connector_id: str,
        factory: AdapterFactory,
    ) -> None:
        if not callable(factory):
            raise TypeError("adapter factory must be callable")
        with self._lock:
            if connector_id not in self._connectors:
                raise ConnectorNotFoundError(connector_id)
            self._factories[connector_id] = factory

    def adapter_factory(self, connector_id: str) -> AdapterFactory:
        with self._lock:
            try:
                return self._factories[connector_id]
            except KeyError as error:
                raise ConnectorNotFoundError(
                    f"no trusted adapter factory for {connector_id}"
                ) from error

    def get(self, connector_id: str) -> RegisteredConnector:
        with self._lock:
            try:
                return self._connectors[connector_id]
            except KeyError as error:
                raise ConnectorNotFoundError(connector_id) from error

    def list(self) -> tuple[RegisteredConnector, ...]:
        with self._lock:
            return tuple(
                self._connectors[key] for key in sorted(self._connectors)
            )

    def set_state(
        self,
        connector_id: str,
        *,
        expected_state: ConnectorState,
        new_state: ConnectorState,
    ) -> RegisteredConnector:
        with self._lock:
            existing = self.get(connector_id)
            if existing.state is not expected_state:
                raise ConnectorVersionConflictError(
                    f"state changed: expected {expected_state.value}, "
                    f"found {existing.state.value}"
                )
            if new_state is expected_state:
                return existing
            if new_state not in _ALLOWED_TRANSITIONS[expected_state]:
                raise ConnectorStateError(
                    f"invalid connector state transition: "
                    f"{expected_state.value} -> {new_state.value}"
                )
            updated = RegisteredConnector(
                manifest=existing.manifest,
                manifest_digest=existing.manifest_digest,
                state=new_state,
            )
            self._connectors[connector_id] = updated
            return updated

    def resolve_command(
        self,
        command_type: str,
    ) -> tuple[RegisteredConnector, Any]:
        matches: list[tuple[int, RegisteredConnector, Any]] = []
        with self._lock:
            for record in self._connectors.values():
                if any(
                    command_type.startswith(prefix)
                    for prefix in record.manifest.forbidden_command_prefixes
                ):
                    continue
                policy = record.manifest.command_policy_for(command_type)
                if policy is not None:
                    matches.append((len(policy.prefix), record, policy))
        if not matches:
            raise CommandNotAllowedError(command_type)
        matches.sort(key=lambda item: item[0], reverse=True)
        best_length = matches[0][0]
        best = [item for item in matches if item[0] == best_length]
        if len(best) != 1:
            connector_ids = ", ".join(
                sorted(item[1].manifest.connector_id for item in best)
            )
            raise CommandNotAllowedError(
                f"ambiguous command prefix for {command_type}: "
                f"{connector_ids}"
            )
        _, record, policy = best[0]
        return record, policy

    def load_directory(
        self,
        directory: Path,
        *,
        state: ConnectorState = ConnectorState.DECLARED,
    ) -> tuple[RegisteredConnector, ...]:
        candidates: list[tuple[Mapping[str, Any], ConnectorManifest]] = []
        route_owners: dict[str, str] = {}
        for path in sorted(directory.glob("*.connector.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping):
                raise ConnectorVersionConflictError(
                    f"manifest is not an object: {path}"
                )
            manifest = load_manifest(path)
            for webhook in manifest.webhook_policies:
                owner = route_owners.get(webhook.route_path)
                if owner is not None:
                    raise ConnectorVersionConflictError(
                        f"webhook route {webhook.route_path} is shared by "
                        f"{owner} and {manifest.connector_id}"
                    )
                route_owners[webhook.route_path] = manifest.connector_id
            candidates.append((raw, manifest))

        connector_ids = [manifest.connector_id for _, manifest in candidates]
        if len(connector_ids) != len(set(connector_ids)):
            raise ConnectorVersionConflictError(
                "connector directory contains duplicate connector IDs"
            )

        staged = ConnectorRegistry()
        loaded: list[RegisteredConnector] = []
        for raw, _ in candidates:
            loaded.append(staged.register_manifest(raw, state=state))
        invariant_errors = staged.validate_global_invariants()
        if invariant_errors:
            raise ConnectorVersionConflictError("; ".join(invariant_errors))

        with self._lock:
            for record in loaded:
                if record.manifest.connector_id in self._connectors:
                    raise ConnectorVersionConflictError(
                        f"connector already registered: "
                        f"{record.manifest.connector_id}"
                    )
            for record in loaded:
                self._connectors[record.manifest.connector_id] = record
        return tuple(loaded)

    def validate_global_invariants(self) -> tuple[str, ...]:
        errors: list[str] = []
        command_owners: list[tuple[str, str]] = []
        webhook_routes: dict[str, str] = {}
        for record in self.list():
            manifest = record.manifest
            for command in manifest.command_policies:
                for prior_prefix, prior_owner in command_owners:
                    overlaps = (
                        command.prefix.startswith(prior_prefix)
                        or prior_prefix.startswith(command.prefix)
                    )
                    if overlaps and prior_owner != manifest.connector_id:
                        errors.append(
                            "command prefixes overlap across connectors: "
                            f"{prior_prefix} ({prior_owner}) and "
                            f"{command.prefix} ({manifest.connector_id})"
                        )
                command_owners.append(
                    (command.prefix, manifest.connector_id)
                )
            for webhook in manifest.webhook_policies:
                prior = webhook_routes.get(webhook.route_path)
                if prior:
                    errors.append(
                        f"webhook route {webhook.route_path} belongs to "
                        f"{prior} and {manifest.connector_id}"
                    )
                webhook_routes[webhook.route_path] = manifest.connector_id
        return tuple(errors)
