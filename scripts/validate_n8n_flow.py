#!/usr/bin/env python3
"""Enforce middleware-to-n8n commands and n8n-to-middleware results only."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCESS_MAP = ROOT / "config" / "identity-access-map.json"


def fail(message: str) -> None:
    print(f"N8N_FLOW_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    try:
        document = json.loads(ACCESS_MAP.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable_to_load_access_map:{exc}")

    grants: dict[tuple[str, str], set[str]] = {}
    for raw in document.get("grants", []):
        if not isinstance(raw, dict) or not isinstance(raw.get("scopes"), list):
            fail("invalid_grant_shape")
        key = (raw.get("callerClientId"), raw.get("targetClientId"))
        if key in grants:
            fail(f"duplicate_grant:{key[0]}->{key[1]}")
        grants[key] = set(raw["scopes"])

    expected = {
        ("middleware-api", "n8n-automation"): {
            "workflow.status.read",
            "workflow.trigger",
        },
        ("n8n-automation", "middleware-api"): {
            "middleware.request.forward",
            "middleware.status.read",
            "workflow.result.publish",
        },
    }
    for key, scopes in expected.items():
        if grants.get(key) != scopes:
            fail(f"incorrect_grant:{key[0]}->{key[1]}:{sorted(grants.get(key, set()))}")

    direct_targets = {
        "odoo-integration",
        "vicidial-adapter",
        "telnexa-gateway",
        "klyrow-gateway",
        "kyqra-gateway",
        "postly-adapter",
        "ai-provider-adapter",
        "marketing-provider-adapter",
    }
    configured = set(document.get("prohibitedDirectTargets", {}).get("n8n-automation", []))
    if configured != direct_targets:
        fail("direct_provider_prohibition_changed")
    for target in direct_targets:
        if ("n8n-automation", target) in grants:
            fail(f"direct_provider_grant_present:{target}")

    print("N8N_COMMAND_DIRECTION=PASS")
    print("N8N_RESULT_DIRECTION=PASS")
    print("N8N_DIRECT_PROVIDER_GRANTS=DISALLOWED")


if __name__ == "__main__":
    main()
