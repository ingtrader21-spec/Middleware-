#!/usr/bin/env python3
"""Certify route registration and fail-closed unauthenticated behavior."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request


COMMAND_PATH = "/v1/commands"
OPERATION_TEMPLATE = "/v1/operations/{command_id}"
OPERATION_PROBE = "/v1/operations/00000000-0000-0000-0000-000000000000"
LEGACY_COMMAND_PATH = "/v1/integrations/n8n/commands"
LEGACY_OPERATION_TEMPLATE = "/v1/integrations/n8n/operations/{command_id}"
LEGACY_OPERATION_PROBE = "/v1/integrations/n8n/operations/00000000-0000-0000-0000-000000000000"
VICIDIAL_PATH = "/api/v1/vicidial/events"
OPERATIONS_DASHBOARD_PATHS = (
    "/v1/operations-dashboard/overview",
    "/v1/operations-dashboard/auth-gateway",
    "/v1/operations-dashboard/routes",
    "/v1/operations-dashboard/providers",
    "/v1/operations-dashboard/messages/lifecycle",
    "/v1/operations-dashboard/webhooks",
    "/v1/operations-dashboard/tenants/{tenant_id}",
    "/v1/operations-dashboard/queues",
    "/v1/operations-dashboard/release-gates",
    "/v1/operations-dashboard/canaries",
)


def request(
    base: str,
    method: str,
    path: str,
    body: dict | None = None,
    headers: dict | None = None,
) -> tuple[int, dict]:
    encoded = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=encoded,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def assert_fail_closed(status_code: int, response_body: dict) -> None:
    assert status_code in {401, 403}
    assert response_body.get("error", {}).get("code") in {
        "authentication_failed",
        "authorization_denied",
    }
    assert response_body != {"detail": "Not Found"}


def certify(base: str, *, expect_operations_dashboard: bool = False) -> None:
    command_path = COMMAND_PATH if expect_operations_dashboard else LEGACY_COMMAND_PATH
    operation_template = OPERATION_TEMPLATE if expect_operations_dashboard else LEGACY_OPERATION_TEMPLATE
    operation_probe = OPERATION_PROBE if expect_operations_dashboard else LEGACY_OPERATION_PROBE
    status, openapi = request(base, "GET", "/openapi.json")
    assert status == 200
    paths = openapi["paths"]
    assert "post" in paths[command_path]
    assert "get" in paths[operation_template]
    assert "post" in paths[VICIDIAL_PATH]
    assert "/v1/operations" not in paths
    assert "/v1/integrations/n8n/operations" not in paths
    if expect_operations_dashboard:
        for path in OPERATIONS_DASHBOARD_PATHS:
            assert "get" in paths[path]

    command = {
        "command_id": "00000000-0000-4000-8000-000000000001",
        "command_type": "crm.lead.upsert",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "tenant-certification",
        "requested_by": "n8n-service-subject",
        "correlation_id": "route-certification-request",
        "idempotency_key": "route-certification-idempotency",
        "capability": "ODOO_WRITE",
        "payload": {
            "lead_source": "synthetic-certification",
            "source_record_id": "route-certification-source",
            "initial_stage": "review_pending",
            "review_required": True,
            "allow_external_contact": False,
            "provenance": {
                "method": "submitted_by_person",
                "captured_by": "route-certification",
                "source_reference": "synthetic://route-certification",
                "legal_basis": "unknown_review_required",
                "content_digest": "a" * 64,
            },
            "consent": {
                "status": "unknown",
                "captured_at": "2026-08-30T16:00:00+00:00",
                "policy_version": "test-v1",
                "channels": {"email": False, "sms": False, "phone": False},
            },
            "lead": {
                "name": "route certification",
                "description": "Synthetic route test only.",
                "contact": {
                    "name": "Synthetic Contact",
                    "email": "synthetic@example.invalid",
                    "phone": "+18095550199",
                    "preferred_language": "en",
                },
                "company": {
                    "name": "Synthetic Company",
                    "domain": "example.invalid",
                    "industry": "Testing",
                },
                "campaign_code": None,
                "tags": [],
            },
        },
    }
    command_headers = {
        "X-Tenant-ID": command["tenant_id"],
        "X-Correlation-ID": command["correlation_id"],
        "Idempotency-Key": command["idempotency_key"],
    }
    submit_status, submit_body = request(
        base,
        "POST",
        command_path,
        command,
        command_headers,
    )
    read_status, read_body = request(
        base,
        "GET",
        operation_probe,
        headers={"X-Tenant-ID": command["tenant_id"]},
    )
    responses = [
        (submit_status, submit_body),
        (read_status, read_body),
    ]
    if expect_operations_dashboard:
        responses.append(
            request(
                base,
                "GET",
                "/v1/operations-dashboard/overview",
                headers={
                    "X-Tenant-ID": command["tenant_id"],
                    "X-Correlation-ID": command["correlation_id"],
                },
            )
        )
    for status_code, response_body in responses:
        assert_fail_closed(status_code, response_body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expect-operations-dashboard", action="store_true")
    args = parser.parse_args()
    certify(
        args.base_url,
        expect_operations_dashboard=args.expect_operations_dashboard,
    )
    print("PRODUCTION_ROUTE_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
