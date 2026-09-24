"""Deterministic desired-state artifacts derived from connector manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .manifest import load_manifest


def build_generated_artifacts(
    manifest_directory: Path,
) -> dict[str, dict[str, Any]]:
    manifests = [
        load_manifest(path)
        for path in sorted(manifest_directory.glob("*.connector.json"))
    ]

    routes: list[dict[str, Any]] = []
    clients: list[dict[str, Any]] = []
    packs: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []

    for manifest in manifests:
        for webhook in manifest.webhook_policies:
            routes.append(
                {
                    "id": (
                        f"connector-{manifest.connector_id}-"
                        f"{webhook.endpoint_key}"
                    ),
                    "connector_id": manifest.connector_id,
                    "endpoint_key": webhook.endpoint_key,
                    "cell": manifest.cell.value,
                    "path": webhook.route_path,
                    "methods": ["POST"],
                    "policy_chain": "webhook",
                    "upstream": "middleware-connector-webhook-inbox",
                    "active": False,
                    "source": "connector-manifest-v1",
                }
            )

        clients.append(
            {
                "connector_id": manifest.connector_id,
                "client_id": f"connector-{manifest.connector_id}",
                "audience": manifest.authentication.audience,
                "grant_type": "client_credentials",
                "authentication_type": manifest.authentication.type,
                "scopes": sorted(manifest.authentication.scopes),
                "secret_references": sorted(
                    manifest.authentication.secret_references
                ),
                "state": "declared-not-created",
                "human_login": False,
                "refresh_tokens": False,
            }
        )

        packs.append(
            {
                "connector_id": manifest.connector_id,
                "cell": manifest.cell.value,
                "workflow_families": sorted(manifest.workflow_families),
                "direct_n8n_access": False,
                "command_path": "n8n -> Middleware -> trusted adapter",
                "active": False,
            }
        )

        for policy in manifest.command_policies:
            commands.append(
                {
                    "connector_id": manifest.connector_id,
                    "prefix": policy.prefix,
                    "required_capability": policy.required_capability,
                    "timeout_seconds": policy.timeout_seconds,
                    "readback_required": policy.readback_required,
                    "unknown_outcome_requires_readback": (
                        policy.retry_policy.unknown_outcome_requires_readback
                    ),
                }
            )

    return {
        "kong-routes.v1.json": {
            "schema_version": "1.0",
            "state": "DESIRED_ONLY",
            "routes": sorted(routes, key=lambda item: item["id"]),
        },
        "keycloak-clients.v1.json": {
            "schema_version": "1.0",
            "state": "DESIRED_ONLY",
            "clients": sorted(
                clients, key=lambda item: item["connector_id"]
            ),
        },
        "n8n-workflow-packs.v1.json": {
            "schema_version": "1.0",
            "state": "SOURCE_ONLY",
            "packs": sorted(packs, key=lambda item: item["connector_id"]),
        },
        "command-registry.v1.json": {
            "schema_version": "1.0",
            "default_policy": "DENY",
            "commands": sorted(commands, key=lambda item: item["prefix"]),
        },
    }


def render_generated_artifact(data: dict[str, Any]) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n"
