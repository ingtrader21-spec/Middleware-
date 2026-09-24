#!/usr/bin/env python3
"""Validate the automation v2 authorization model and its nine invariants."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.automation_policy import (  # noqa: E402
    AutomationAuthorizationError,
    AutomationPolicy,
    AutomationPolicyError,
)


def claims(client_id: str, scopes: str) -> dict[str, object]:
    return {
        "iss": "https://auth.codestra.co/realms/codestra",
        "aud": "middleware-api",
        "azp": client_id,
        "scope": scopes,
    }


def require_denied(label: str, operation) -> None:
    try:
        operation()
    except AutomationAuthorizationError:
        return
    raise AutomationPolicyError(f"negative authorization probe unexpectedly passed: {label}")


def main() -> int:
    try:
        policy = AutomationPolicy.from_path()
        run_ci = (ROOT / "scripts" / "run_ci.sh").read_text(encoding="utf-8")
        if "python3 scripts/validate_automation_operation_policy.py" not in run_ci:
            raise AutomationPolicyError("run_ci.sh does not enforce the operation policy")

        require_denied(
            "messaging client issuing crawler command",
            lambda: policy.authorize_command(
                claims(
                    "n8n-messaging-automation",
                    "automation.command.messaging",
                ),
                command_type="crawler.fetch.v1",
                workflow_family="crawler.kyqra",
            ),
        )
        require_denied(
            "identity client claiming CRM family",
            lambda: policy.authorize_job_family(
                claims("n8n-identity-automation", "automation.job.claim"),
                required_scope="automation.job.claim",
                workflow_family="crm",
            ),
        )
        require_denied(
            "implicit scope union",
            lambda: policy.authorize_token(
                claims(
                    "n8n-crm-automation",
                    "automation.command.crm automation.command.messaging",
                ),
                required_scope="automation.command.crm",
            ),
        )
        require_denied(
            "generic command scope",
            lambda: policy.authorize_token(
                claims(
                    "n8n-crm-automation",
                    "automation.command.crm automation.command",
                ),
                required_scope="automation.command.crm",
            ),
        )
        require_denied(
            "wrong issuer",
            lambda: policy.authorize_token(
                {
                    **claims("n8n-crm-automation", "automation.command.crm"),
                    "iss": "https://gateway.example.invalid/claims",
                },
                required_scope="automation.command.crm",
            ),
        )
        require_denied(
            "wrong audience",
            lambda: policy.authorize_token(
                {
                    **claims("n8n-crm-automation", "automation.command.crm"),
                    "aud": "kong-only",
                },
                required_scope="automation.command.crm",
            ),
        )
    except (AutomationPolicyError, AutomationAuthorizationError) as exc:
        print(f"AUTOMATION_OPERATION_POLICY=FAIL reason={exc}", file=sys.stderr)
        return 1

    print(f"AUTOMATION_POLICY_CLIENTS={len(policy.clients)}")
    print(f"AUTOMATION_POLICY_OPERATIONS={len(policy.operations)}")
    print(f"AUTOMATION_POLICY_COMMAND_FAMILIES={len(policy.command_families)}")
    print(f"AUTOMATION_POLICY_INVARIANTS={len(policy.invariants)}")
    print("AUTOMATION_NEGATIVE_AUTHORIZATION_PROBES=6")
    print("AUTOMATION_OPERATION_POLICY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
