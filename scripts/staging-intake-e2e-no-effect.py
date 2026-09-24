#!/usr/bin/env python3
"""Fail-closed no-effect certification for the isolated staging intake path.

The command performs synthetic durable intake writes only after the remote runtime
proves that it is the exact protected-main source, uses an immutable image, runs
with staging-safe persistence/dispatch settings, and has every external effect
disabled. The same read-back is repeated after the synthetic requests.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
PLATFORM_CONTRACT = ROOT / "contracts" / "platform-control-plane.v1.json"

LOCAL_DISABLED_FLAGS = (
    "LIVE_WRITES",
    "ODOO_WRITE",
    "N8N_DELIVERY_ENABLED",
    "LIVE_SMS_DELIVERY",
    "LIVE_EMAIL_DELIVERY",
    "LIVE_PSTN_DIALING",
)
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(
    r"^(?:[a-z0-9][a-z0-9._:/-]*@)?sha256:[0-9a-f]{64}$"
)
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class FailClosedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so protected credentials never cross authorities."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(FailClosedRedirectHandler())


def fail(message: str) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, str]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=headers or {},
    )
    try:
        with NO_REDIRECT_OPENER.open(req, timeout=15) as response:
            return response.status, response.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(8192).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        fail(f"request failed for {url}: {exc}")
    raise AssertionError("fail() always exits")


def require_disabled(name: str) -> None:
    value = os.environ.get(name, "").strip().lower()
    if value not in {"false", "0", "disabled", "off"}:
        fail(f"{name} must be explicitly disabled, got {value!r}")


def _json_object(body: str, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except json.JSONDecodeError as exc:
        fail(f"{label} did not return valid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must return a JSON object")
    return value


def canonical_production_hosts() -> set[str]:
    """Load public production hosts from committed source authority."""

    try:
        contract = json.loads(PLATFORM_CONTRACT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot load production gateway authority: {exc}")
    if not isinstance(contract, dict):
        fail("production gateway authority must contain a JSON object")

    hosts: set[str] = set()
    n8n_boundary = contract.get("n8n_to_middleware")
    if isinstance(n8n_boundary, dict):
        gateway_host = n8n_boundary.get("gateway_host")
        if isinstance(gateway_host, str) and gateway_host.strip():
            hosts.add(gateway_host.strip().lower())

    if not hosts:
        fail("production gateway authority does not declare a gateway host")
    return hosts


def validate_dns_hostname(value: str, *, label: str) -> str:
    """Return one canonical DNS hostname, rejecting IP literals and ambiguity."""

    if not isinstance(value, str) or value != value.strip():
        fail(f"{label} must be a canonical DNS hostname")
    hostname = value.lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        # Protected tokens must never be sent to caller-selected IPv4 or IPv6
        # literals; the approved staging endpoint is a reviewed DNS identity.
        fail(f"{label} must not be an IPv4 or IPv6 address")
    try:
        numeric_answers = socket.getaddrinfo(
            hostname,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            flags=socket.AI_NUMERICHOST,
        )
    except socket.gaierror:
        numeric_answers = []
    if numeric_answers:
        # libc accepts legacy IPv4 text such as hexadecimal, octal, and
        # abbreviated components even though ipaddress intentionally does not.
        # AI_NUMERICHOST performs no DNS lookup and closes that parser gap.
        fail(f"{label} must not use a legacy numeric address spelling")
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or all(item.isdigit() for item in labels)
        or any(DNS_LABEL.fullmatch(item) is None for item in labels)
    ):
        fail(f"{label} must be a canonical DNS hostname")
    return hostname


def validate_base_url(
    value: str,
    *,
    approved_host: str,
    denied_hosts: set[str] | None = None,
) -> str:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        fail("base_url is malformed")
    if parsed.scheme != "https" or not parsed.netloc or hostname is None:
        fail("base_url must be an HTTPS staging Caddy endpoint")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail("base_url must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        fail("base_url must not contain a path")
    if port not in {None, 443}:
        fail("base_url must use the standard HTTPS port")
    normalized_host = validate_dns_hostname(hostname, label="base_url host")
    normalized_approved_host = validate_dns_hostname(
        approved_host,
        label="approved staging host",
    )
    if normalized_host != normalized_approved_host:
        fail("base_url host does not match the protected staging authority")
    production_hosts = {
        validate_dns_hostname(item, label="production gateway host")
        for item in (denied_hosts or canonical_production_hosts())
    }
    if normalized_host in production_hosts:
        fail("base_url resolves to a committed production gateway host")
    return f"https://{normalized_host}"


def _immutable_digest(value: Any) -> bool:
    return isinstance(value, str) and IMAGE_DIGEST.fullmatch(value) is not None


def validate_runtime_evidence(
    version: dict[str, Any],
    safety: dict[str, Any],
    *,
    expected_source_sha: str,
) -> dict[str, Any]:
    if GIT_SHA.fullmatch(expected_source_sha) is None:
        fail("expected source SHA must be canonical lowercase 40-hex")
    if version.get("service") != "middleware-api":
        fail("version read-back is not Middleware")
    if version.get("environment") != "staging":
        fail("version read-back is not an isolated staging runtime")
    if version.get("source_sha") != expected_source_sha:
        fail(
            "version source mismatch: "
            f"expected {expected_source_sha}, got {version.get('source_sha')!r}"
        )
    if version.get("git_sha") != expected_source_sha:
        fail("version git_sha differs from the dispatched protected-main SHA")
    image_digest = version.get("image_digest")
    if not _immutable_digest(image_digest):
        fail("version read-back does not expose an immutable image digest")
    if not isinstance(version.get("schema_head"), str) or not version["schema_head"]:
        fail("version read-back does not expose a schema head")
    if version.get("schema_version") != version["schema_head"]:
        fail("version schema identity fields are inconsistent")
    if (
        not isinstance(version.get("build_time"), str)
        or not version["build_time"]
        or version.get("build_timestamp") != version["build_time"]
    ):
        fail("version build identity fields are inconsistent")
    configuration_checksum = version.get("configuration_checksum")
    if (
        not isinstance(configuration_checksum, str)
        or SHA256.fullmatch(configuration_checksum) is None
    ):
        fail("version read-back does not expose a canonical configuration checksum")
    release_id = version.get("release_id")
    if (
        not isinstance(release_id, str)
        or RELEASE_ID.fullmatch(release_id) is None
        or release_id.lower() == "unknown"
    ):
        fail("version read-back does not expose a canonical release ID")
    runtime_profile_id = version.get("runtime_profile_id")
    if not isinstance(runtime_profile_id, str) or runtime_profile_id in {
        "",
        "local-unlocked",
    }:
        fail("version read-back does not expose a locked staging runtime profile")

    if safety.get("schema_version") != "1.1":
        fail("runtime safety schema must be exactly 1.1")
    if safety.get("service") != "middleware-api":
        fail("runtime safety read-back is not Middleware")
    if safety.get("environment") != "staging":
        fail("runtime safety read-back is not staging")
    if safety.get("runtime_profile_id") != runtime_profile_id:
        fail("runtime profile differs between version and safety read-back")

    release = safety.get("release")
    if not isinstance(release, dict):
        fail("runtime safety release evidence is missing")
    for key in ("source_sha", "image_digest", "schema_head", "build_time"):
        if release.get(key) != version.get(key):
            fail(f"runtime safety release {key} differs from version read-back")
    if release.get("source_sha") != expected_source_sha:
        fail("runtime safety source does not match the dispatched protected-main SHA")

    persistence = safety.get("persistence")
    if not isinstance(persistence, dict) or persistence.get("in_memory") is not False:
        fail("staging runtime must use durable, non-memory persistence")

    dispatch = safety.get("dispatch")
    if not isinstance(dispatch, dict):
        fail("runtime dispatch evidence is missing")
    expected_dispatch = {
        "outbox_enabled": False,
        "nats_mode": "disabled",
        "temporal_worker_mode": "disabled",
    }
    for key, expected in expected_dispatch.items():
        if dispatch.get(key) != expected:
            fail(f"runtime dispatch control {key} must be {expected!r}")

    effects = safety.get("external_effects")
    if not isinstance(effects, dict) or not effects:
        fail("runtime external-effect evidence is missing")
    enabled_effects = sorted(
        name for name, enabled in effects.items() if enabled is not False
    )
    if enabled_effects:
        fail("runtime external effects are not all disabled: " + ", ".join(enabled_effects))

    umbrella = safety.get("umbrella_controls")
    if not isinstance(umbrella, dict) or not umbrella:
        fail("runtime umbrella-control evidence is missing")
    enabled_umbrella = sorted(
        name for name, enabled in umbrella.items() if enabled is not False
    )
    if enabled_umbrella:
        fail(
            "runtime umbrella controls are not all disabled: "
            + ", ".join(enabled_umbrella)
        )

    required_values = {
        "production_dialing": "DISABLED",
        "production_activation_configured": False,
        "provider_effects_disabled": True,
        "all_external_effects_disabled": True,
        "staging_safe": True,
    }
    for key, expected in required_values.items():
        if safety.get(key) != expected:
            fail(f"runtime safety field {key} must be {expected!r}")

    return {
        "source_sha": expected_source_sha,
        "image_digest": image_digest,
        "schema_head": version["schema_head"],
        "release_id": release_id,
        "configuration_checksum": configuration_checksum,
        "runtime_profile_id": runtime_profile_id,
        "safety": safety,
    }


def read_runtime_evidence(
    base: str,
    *,
    safety_token: str,
    expected_source_sha: str,
) -> dict[str, Any]:
    status, body = request(f"{base}/version")
    if status != 200:
        fail(f"version read-back failed: HTTP {status}: {body[:500]}")
    version = _json_object(body, label="version read-back")

    status, body = request(
        f"{base}/v1/runtime/safety",
        headers={"Authorization": f"Bearer {safety_token}"},
    )
    if status != 200:
        fail(f"runtime safety read-back failed: HTTP {status}: {body[:500]}")
    safety = _json_object(body, label="runtime safety read-back")
    return validate_runtime_evidence(
        version,
        safety,
        expected_source_sha=expected_source_sha,
    )


def require_stable_runtime(
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    for key in (
        "source_sha",
        "image_digest",
        "schema_head",
        "release_id",
        "configuration_checksum",
        "runtime_profile_id",
    ):
        if after.get(key) != before.get(key):
            fail(f"runtime {key} changed during certification")
    if after.get("safety") != before.get("safety"):
        fail("runtime safety controls changed during certification")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-url",
        required=True,
        help="Isolated staging Caddy public API base",
    )
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--token-env", default="STAGING_SDK_INTAKE_TOKEN")
    parser.add_argument(
        "--safety-token-env",
        default="STAGING_RUNTIME_SAFETY_TOKEN",
    )
    args = parser.parse_args()

    expected_source_sha = args.expected_source_sha
    if GIT_SHA.fullmatch(expected_source_sha) is None:
        fail("--expected-source-sha must be a full 40-character Git SHA")
    if TENANT_ID.fullmatch(args.tenant) is None:
        fail("--tenant must be a bounded API-safe identifier")
    if args.token_env != "STAGING_SDK_INTAKE_TOKEN":
        fail("--token-env must name the dedicated staging intake token")
    if args.safety_token_env != "STAGING_RUNTIME_SAFETY_TOKEN":
        fail("--safety-token-env must name the dedicated staging safety token")

    for flag in LOCAL_DISABLED_FLAGS:
        require_disabled(flag)

    approved_host = os.environ.get("STAGING_INTAKE_APPROVED_HOST", "")
    base = validate_base_url(args.base_url, approved_host=approved_host)

    token = os.environ.get(args.token_env, "").strip()
    if not token:
        fail(f"missing staging bearer token in {args.token_env}")
    safety_token = os.environ.get(args.safety_token_env, "").strip()
    if not safety_token:
        fail(f"missing staging safety token in {args.safety_token_env}")

    before = read_runtime_evidence(
        base,
        safety_token=safety_token,
        expected_source_sha=expected_source_sha,
    )

    correlation = f"stg-cert-{uuid.uuid4()}"
    idem = f"stg-lead-{uuid.uuid4()}"
    submitted_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    lead_url = f"{base}/v1/intake/leads"
    survey_url = f"{base}/v1/intake/surveys/responses"

    # Negative control: no token must be rejected by gateway/auth, never accepted.
    status, _ = request(
        lead_url,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Tenant-ID": args.tenant,
            "X-Correlation-ID": correlation,
            "Idempotency-Key": idem,
        },
        body={
            "tenantId": args.tenant,
            "siteId": "staging-cert",
            "source": "api",
            "submittedAt": submitted_at,
        },
    )
    if status < 400:
        fail(f"unauthenticated lead request unexpectedly accepted with HTTP {status}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Tenant-ID": args.tenant,
        "X-Correlation-ID": correlation,
        "Idempotency-Key": idem,
    }
    lead = {
        "tenantId": args.tenant,
        "siteId": "staging-cert",
        "source": "api",
        "submittedAt": submitted_at,
        "formId": "staging-cert-v1",
        "name": "Synthetic Staging Certification",
        "email": "staging-cert@example.invalid",
        "metadata": {"certification": "no-effect"},
    }

    status, first_body = request(
        lead_url,
        method="POST",
        headers=headers,
        body=lead,
    )
    if status not in {200, 202}:
        fail(
            "authenticated lead intake failed: "
            f"HTTP {status}: {first_body[:500]}"
        )

    status, retry_body = request(
        lead_url,
        method="POST",
        headers=headers,
        body=lead,
    )
    if status != 200:
        fail(
            "exact retry did not return duplicate semantics: "
            f"HTTP {status}: {retry_body[:500]}"
        )

    changed = dict(lead)
    changed["name"] = "Synthetic Staging Certification Changed"
    status, conflict_body = request(
        lead_url,
        method="POST",
        headers=headers,
        body=changed,
    )
    if status != 409:
        fail(
            "changed-payload idempotency reuse did not conflict: "
            f"HTTP {status}: {conflict_body[:500]}"
        )

    survey_headers = dict(headers)
    survey_headers["Idempotency-Key"] = f"stg-survey-{uuid.uuid4()}"
    survey_headers["X-Correlation-ID"] = f"stg-survey-{uuid.uuid4()}"
    survey = {
        "tenantId": args.tenant,
        "siteId": "staging-cert",
        "source": "api",
        "submittedAt": submitted_at,
        "surveyId": "staging-cert",
        "surveyVersion": "1.0.0",
        "surveyCategory": "custom",
        "anonymous": True,
        "answers": {"certification": "pass"},
        "metadata": {"certification": "no-effect"},
    }
    status, survey_body = request(
        survey_url,
        method="POST",
        headers=survey_headers,
        body=survey,
    )
    if status not in {200, 202}:
        fail(
            "anonymous survey intake failed: "
            f"HTTP {status}: {survey_body[:500]}"
        )

    after = read_runtime_evidence(
        base,
        safety_token=safety_token,
        expected_source_sha=expected_source_sha,
    )
    require_stable_runtime(before, after)

    print("STAGING_INTAKE_NO_EFFECT=PASS")
    print(f"source_sha={before['source_sha']}")
    print(f"image_digest={before['image_digest']}")
    print(f"schema_head={before['schema_head']}")
    print(f"runtime_profile_id={before['runtime_profile_id']}")
    print(f"correlation_id={correlation}")
    print("external_effects_verified=DISABLED_BEFORE_AND_AFTER")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
