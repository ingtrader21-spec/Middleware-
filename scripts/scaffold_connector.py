#!/usr/bin/env python3
"""Scaffold one disabled-first Codestra connector manifest."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from middleware.connector_sdk import parse_manifest  # noqa: E402

CONNECTOR_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def secret_prefix(connector_id: str) -> str:
    return connector_id.upper().replace("-", "_")


def build_manifest(args: argparse.Namespace) -> dict[str, object]:
    connector_id = args.connector_id
    prefix = secret_prefix(connector_id)
    header_prefix = "-".join(
        part.capitalize() for part in connector_id.split("-")
    )
    webhook_list: list[dict[str, object]] = []
    if args.webhook_endpoint_key:
        webhook_list.append(
            {
                "endpoint_key": args.webhook_endpoint_key,
                "route_path": (
                    f"/v1/webhooks/{connector_id}/"
                    f"{args.webhook_endpoint_key}"
                ),
                "signature_algorithm": "hmac-sha256",
                "signature_header": f"X-{header_prefix}-Signature",
                "timestamp_header": f"X-{header_prefix}-Timestamp",
                "event_id_header": f"X-{header_prefix}-Event-Id",
                "maximum_clock_skew_seconds": 300,
                "maximum_body_bytes": 1048576,
                "acknowledgement_deadline_seconds": 5,
                "secret_reference": f"WEBHOOK_{prefix}_HMAC_SECRET",
            }
        )
    return {
        "$schema": (
            "https://contracts.codestra.co/connectors/"
            "connector-manifest.v1.schema.json"
        ),
        "manifest_version": "1.0",
        "connector_id": connector_id,
        "display_name": args.display_name,
        "version": "1.0.0",
        "cell": args.cell,
        "repository": args.repository,
        "enabled_by_default": False,
        "direct_n8n_access": False,
        "runtime_binding": {
            "status": "UNVERIFIED_TEMPLATE_ONLY",
            "base_url": f"https://{connector_id}.internal.invalid",
            "health_path": "/health",
            "operation_path_template": (
                "/v1/operations/{operation_id}/status"
            ),
        },
        "authentication": {
            "type": "oauth2-plus-mtls",
            "audience": "codestra-middleware-api",
            "scopes": [
                f"connector.{connector_id}.command",
                f"connector.{connector_id}.read",
            ],
            "secret_references": [
                f"CONNECTOR_{prefix}_CLIENT_SECRET",
                f"CONNECTOR_{prefix}_MTLS_CERT",
            ],
        },
        "commands": [
            {
                "prefix": args.command_prefix,
                "required_capability": args.capability,
                "timeout_seconds": 30,
                "readback_required": True,
                "retry_policy": {
                    "maximum_attempts": 5,
                    "initial_backoff_seconds": 2,
                    "maximum_backoff_seconds": 120,
                    "jitter_ratio": 0.2,
                    "unknown_outcome_requires_readback": True,
                },
            }
        ],
        "events": [
            {"event_type": args.event_type, "direction": "inbound"}
        ],
        "webhooks": webhook_list,
        "forbidden_command_prefixes": [],
        "forbidden_payload_keys": [
            "access_token",
            "client_secret",
            "password",
            "private_key",
            "provider_token",
            "refresh_token",
        ],
        "workflow_families": [args.workflow_family],
        "metadata": {
            "source_only": True,
            "runtime_activation_authorized": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-id", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--cell",
        choices=(
            "core-communications",
            "beyvra-financial",
            "telephony-private",
        ),
        default="core-communications",
    )
    parser.add_argument("--command-prefix", required=True)
    parser.add_argument("--capability", required=True)
    parser.add_argument("--workflow-family", required=True)
    parser.add_argument("--event-type", required=True)
    parser.add_argument("--webhook-endpoint-key")
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=ROOT / "connectors" / "manifests",
    )
    args = parser.parse_args()

    if not CONNECTOR_ID.fullmatch(args.connector_id):
        parser.error("--connector-id must be lowercase kebab-case")

    manifest = build_manifest(args)
    parse_manifest(manifest)

    output = args.output_directory / f"{args.connector_id}.connector.json"
    if output.exists():
        print(f"ERROR=refusing to overwrite {output}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"CONNECTOR_SCAFFOLD=PASS PATH={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
