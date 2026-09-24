#!/usr/bin/env python3
"""Run the protected staging machine-identity matrix without business mutation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx


ROOT = Path(__file__).resolve().parents[1]
CALLER_POLICY_PATH = ROOT / "config" / "control-plane-callers.v1.json"
PROVIDER_POLICY_PATH = ROOT / "config" / "provider-operation-policy.json"
CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
CANONICAL_AUDIENCE = "middleware-api"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CLIENT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
NEGATIVE_FIXTURE_CASES = {
    "wrong_issuer": 401,
    "wrong_audience": 401,
    "wrong_azp": 401,
    "expired": 401,
    "not_yet_valid": 401,
    "missing_scope": 401,
    "cross_client_scope_confusion": 401,
}


class MatrixError(RuntimeError):
    pass


@dataclass(frozen=True)
class MatrixClient:
    client_id: str
    status_scope: str
    secret_environment: str
    provider_control: bool


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot load {path.name}") from exc
    if not isinstance(value, dict):
        raise MatrixError(f"{path.name} root must be an object")
    return value


def _secret_environment(client_id: str) -> str:
    return "AUTH_MATRIX_SECRET_" + client_id.upper().replace("-", "_")


def _load_policy() -> dict[str, MatrixClient]:
    policy = _load_json(CALLER_POLICY_PATH)
    provider_policy = _load_json(PROVIDER_POLICY_PATH)
    if policy.get("schema_version") != "1.0":
        raise MatrixError("caller policy schema is unsupported")
    if policy.get("issuer") != CANONICAL_ISSUER:
        raise MatrixError("caller policy issuer is not canonical")
    if policy.get("audience") != CANONICAL_AUDIENCE:
        raise MatrixError("caller policy audience is not canonical")
    if policy.get("maximum_token_lifetime_seconds") != 300:
        raise MatrixError("machine token lifetime policy must be 300 seconds")
    if provider_policy.get("schemaVersion") != 1:
        raise MatrixError("provider-operation policy schema is unsupported")
    authority = provider_policy.get("authority", {})
    if authority.get("issuer") != CANONICAL_ISSUER:
        raise MatrixError("provider policy issuer is not canonical")
    if authority.get("audience") != CANONICAL_AUDIENCE:
        raise MatrixError("provider policy audience is not canonical")

    provider_scopes: dict[str, set[str]] = {}
    for operation in provider_policy.get("operations", []):
        if not isinstance(operation, dict) or operation.get("externalEffect") is not True:
            continue
        caller = operation.get("caller")
        scope = operation.get("scope")
        if isinstance(caller, str) and isinstance(scope, str):
            provider_scopes.setdefault(caller, set()).add(scope)

    raw_callers = policy.get("callers")
    if not isinstance(raw_callers, dict):
        raise MatrixError("caller registry is missing")
    clients: dict[str, MatrixClient] = {}
    for client_id, raw in raw_callers.items():
        if not isinstance(client_id, str) or not isinstance(raw, dict):
            raise MatrixError("caller registry entry is malformed")
        if raw.get("staging_auth_matrix") is not True:
            continue
        if raw.get("compatibility_only") is True:
            raise MatrixError(f"{client_id}: compatibility identity cannot be certified")
        if not CLIENT_ID.fullmatch(client_id):
            raise MatrixError(f"{client_id}: client ID is malformed")
        status_scope = raw.get("status_scope")
        if not isinstance(status_scope, str) or not status_scope:
            raise MatrixError(f"{client_id}: status scope is missing")
        is_provider = client_id in provider_scopes
        if is_provider:
            if status_scope != "provider-control.operations.read.denied":
                raise MatrixError(
                    f"{client_id}: generic operation read scope must remain denied"
                )
            status_scope = sorted(provider_scopes[client_id])[0]
            if raw.get("connector_commands_allowed") is not False:
                raise MatrixError(
                    f"{client_id}: provider caller has generic connector authority"
                )
            command_scope = raw.get("command_scope")
            if (
                not isinstance(command_scope, str)
                or not command_scope.endswith(".denied")
            ):
                raise MatrixError(
                    f"{client_id}: generic mutation scope is not fail-closed"
                )
            if raw.get("allowed_command_prefixes") or raw.get("allowed_targets"):
                raise MatrixError(
                    f"{client_id}: provider caller has generic command bindings"
                )
        clients[client_id] = MatrixClient(
            client_id=client_id,
            status_scope=status_scope,
            secret_environment=_secret_environment(client_id),
            provider_control=is_provider,
        )
    if not clients:
        raise MatrixError("staging identity matrix is empty")
    if set(provider_scopes) - set(clients):
        raise MatrixError("provider-control caller coverage is incomplete")
    return dict(sorted(clients.items()))


def _audiences(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def _scopes(value: object) -> set[str]:
    if isinstance(value, str):
        return {item for item in value.split() if item}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def validate_claim_shape(
    claims: dict[str, Any],
    *,
    client_id: str,
    required_scope: str,
    now: int | None = None,
) -> str:
    timestamp = int(time.time()) if now is None else now
    if claims.get("iss") != CANONICAL_ISSUER:
        raise MatrixError("token issuer is not canonical")
    if _audiences(claims.get("aud")) != {CANONICAL_AUDIENCE}:
        raise MatrixError("token audience is not exact")
    if claims.get("azp") != client_id:
        raise MatrixError("token azp does not match the selected client")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise MatrixError("token subject is missing")
    issued = claims.get("iat")
    expires = claims.get("exp")
    if not isinstance(issued, int) or not isinstance(expires, int):
        raise MatrixError("token timestamps are missing")
    if expires <= issued or expires - issued > 300:
        raise MatrixError("token lifetime exceeds the machine-token policy")
    if issued > timestamp + 30:
        raise MatrixError("token issued-at is in the future")
    if expires <= timestamp:
        raise MatrixError("token is expired")
    not_before = claims.get("nbf")
    if isinstance(not_before, int) and not_before > timestamp:
        raise MatrixError("token is not yet valid")
    if required_scope not in _scopes(claims.get("scope")):
        raise MatrixError("token lacks the required status scope")
    tenant_id = claims.get("tenant_id")
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or tenant_id == "*"
        or len(tenant_id) > 128
    ):
        raise MatrixError("token tenant_id is invalid")
    return tenant_id


def decode_unverified_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise MatrixError("token is not a compact JWT")
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        value = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError("token claims cannot be decoded") from exc
    if not isinstance(value, dict):
        raise MatrixError("token claims must be an object")
    return value


def tamper_signature(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise MatrixError("token signature cannot be tampered")
    replacement = "A" if parts[2][-1] != "A" else "B"
    return ".".join((parts[0], parts[1], parts[2][:-1] + replacement))


def _https_url(value: str, label: str, *, allow_path: bool) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (not allow_path and parsed.path not in {"", "/"})
    ):
        raise MatrixError(
            f"{label} must be an HTTPS URL without embedded credentials, "
            "query, or fragment"
        )
    return value.rstrip("/")


def _tenant_digest(tenant_id: str) -> str:
    return hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()


def _error_code(response: httpx.Response) -> str | None:
    try:
        value = response.json()
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    error = value.get("error")
    if isinstance(error, dict) and isinstance(error.get("code"), str):
        return error["code"]
    if isinstance(value.get("code"), str):
        return value["code"]
    return None


def _record(
    *,
    client_id: str,
    probe: str,
    expected_status: int,
    response: httpx.Response,
) -> dict[str, Any]:
    return {
        "client_id": client_id,
        "probe": probe,
        "expected_status": expected_status,
        "actual_status": response.status_code,
        "error_code": _error_code(response),
        "passed": response.status_code == expected_status,
    }


def _obtain_token(
    client: httpx.Client,
    *,
    token_endpoint: str,
    matrix_client: MatrixClient,
    secret: str,
) -> str:
    response = client.request(
        method="POST",
        url=token_endpoint,
        data={
            "grant_type": "client_credentials",
            "client_id": matrix_client.client_id,
            "client_secret": secret,
            "audience": CANONICAL_AUDIENCE,
            "scope": matrix_client.status_scope,
        },
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    value = response.json()
    token = value.get("access_token") if isinstance(value, dict) else None
    if not isinstance(token, str) or not token:
        raise MatrixError(
            f"{matrix_client.client_id}: token endpoint returned no access token"
        )
    return token


def _operation_get(
    client: httpx.Client,
    *,
    gateway_base_url: str,
    operation_id: uuid.UUID,
    authorization: str | None,
    tenant_id: str,
    provider_control: bool = False,
    forwarded_authorization: str | None = None,
) -> httpx.Response:
    headers = {
        "Accept": "application/json",
        "X-Tenant-ID": tenant_id,
        "X-Correlation-ID": f"staging-auth-matrix-{uuid.uuid4()}",
    }
    if authorization is not None:
        headers["Authorization"] = authorization
    if forwarded_authorization is not None:
        headers["X-Forwarded-Authorization"] = forwarded_authorization
    return client.request(
        method="GET",
        url=(
            f"{gateway_base_url}/api/v1/control/identity-probes/{operation_id}"
            if provider_control
            else f"{gateway_base_url}/v1/operations/{operation_id}"
        ),
        headers=headers,
    )


def _load_negative_fixtures(path_value: str | None) -> dict[str, dict[str, str]]:
    if not path_value:
        return {}
    path = Path(path_value)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError("negative token fixture file cannot be loaded") from exc
    if not isinstance(value, dict):
        raise MatrixError("negative token fixture root must be an object")
    result: dict[str, dict[str, str]] = {}
    for case, expected_status in NEGATIVE_FIXTURE_CASES.items():
        raw = value.get(case)
        if raw is None:
            continue
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("token"), str)
            or not raw["token"]
            or not isinstance(raw.get("tenant_id"), str)
            or not raw["tenant_id"]
        ):
            raise MatrixError(f"negative token fixture {case} is malformed")
        result[case] = {
            "token": raw["token"],
            "tenant_id": raw["tenant_id"],
            "expected_status": str(expected_status),
        }
    return result


def _selected_clients(
    clients: dict[str, MatrixClient],
    value: str | None,
) -> list[MatrixClient]:
    if not value:
        return list(clients.values())
    requested = [item.strip() for item in value.split(",") if item.strip()]
    if not requested or len(requested) != len(set(requested)):
        raise MatrixError("AUTH_MATRIX_CLIENTS is empty or duplicated")
    unknown = sorted(set(requested) - set(clients))
    if unknown:
        raise MatrixError(f"unknown matrix clients: {unknown}")
    return [clients[item] for item in requested]


def run() -> tuple[dict[str, Any], Path]:
    if os.environ.get("AUTH_MATRIX_ENVIRONMENT") != "staging":
        raise MatrixError("AUTH_MATRIX_ENVIRONMENT must equal staging")
    gateway_base_url = _https_url(
        os.environ.get("AUTH_MATRIX_GATEWAY_BASE_URL", ""),
        "AUTH_MATRIX_GATEWAY_BASE_URL",
        allow_path=False,
    )
    token_endpoint = _https_url(
        os.environ.get("AUTH_MATRIX_TOKEN_ENDPOINT", ""),
        "AUTH_MATRIX_TOKEN_ENDPOINT",
        allow_path=True,
    )
    source_sha = os.environ.get("AUTH_MATRIX_SOURCE_SHA", "")
    image_digest = os.environ.get("AUTH_MATRIX_IMAGE_DIGEST", "")
    if not SHA40.fullmatch(source_sha):
        raise MatrixError("AUTH_MATRIX_SOURCE_SHA must be an exact commit SHA")
    if not IMAGE_DIGEST.fullmatch(image_digest):
        raise MatrixError("AUTH_MATRIX_IMAGE_DIGEST must be an exact sha256 digest")

    policy_clients = _load_policy()
    selected = _selected_clients(
        policy_clients,
        os.environ.get("AUTH_MATRIX_CLIENTS"),
    )
    complete_client_coverage = {item.client_id for item in selected} == set(
        policy_clients
    )
    fixtures = _load_negative_fixtures(
        os.environ.get("AUTH_MATRIX_NEGATIVE_TOKEN_FILE")
    )
    extended_negative_coverage = set(fixtures) == set(NEGATIVE_FIXTURE_CASES)
    require_extended = os.environ.get(
        "AUTH_MATRIX_REQUIRE_EXTENDED_NEGATIVES", "true"
    ).strip().lower() in {"1", "true", "yes", "on"}
    if require_extended and not extended_negative_coverage:
        missing = sorted(set(NEGATIVE_FIXTURE_CASES) - set(fixtures))
        raise MatrixError(f"extended negative token fixtures are incomplete: {missing}")

    evidence_dir = Path(
        os.environ.get(
            "AUTH_MATRIX_EVIDENCE_DIR",
            "/tmp/codestra-staging-auth-matrix-"
            + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        )
    )
    if ROOT in evidence_dir.resolve().parents or evidence_dir.resolve() == ROOT:
        raise MatrixError("evidence directory must be outside the repository")
    evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence_path = evidence_dir / "auth-matrix-evidence.json"

    policy_digest = hashlib.sha256(
        CALLER_POLICY_PATH.read_bytes() + PROVIDER_POLICY_PATH.read_bytes()
    ).hexdigest()
    records: list[dict[str, Any]] = []
    clients_evidence: list[dict[str, Any]] = []

    with httpx.Client(
        timeout=httpx.Timeout(15.0, connect=5.0),
        follow_redirects=False,
    ) as client:
        random_operation = uuid.uuid4()
        records.append(
            _record(
                client_id="<none>",
                probe="missing_authorization",
                expected_status=401,
                response=_operation_get(
                    client,
                    gateway_base_url=gateway_base_url,
                    operation_id=random_operation,
                    authorization=None,
                    tenant_id="matrix-no-bearer",
                ),
            )
        )
        records.append(
            _record(
                client_id="<none>",
                probe="malformed_bearer",
                expected_status=401,
                response=_operation_get(
                    client,
                    gateway_base_url=gateway_base_url,
                    operation_id=random_operation,
                    authorization="Bearer not-a-jwt",
                    tenant_id="matrix-malformed",
                ),
            )
        )
        records.append(
            _record(
                client_id="<none>",
                probe="unsupported_forwarding_header_only",
                expected_status=401,
                response=_operation_get(
                    client,
                    gateway_base_url=gateway_base_url,
                    operation_id=random_operation,
                    authorization=None,
                    forwarded_authorization="Bearer ignored-forwarded-token",
                    tenant_id="matrix-forwarded-only",
                ),
            )
        )

        for matrix_client in selected:
            secret = os.environ.get(matrix_client.secret_environment, "")
            if not secret:
                raise MatrixError(
                    f"{matrix_client.secret_environment} is required"
                )
            token = _obtain_token(
                client,
                token_endpoint=token_endpoint,
                matrix_client=matrix_client,
                secret=secret,
            )
            claims = decode_unverified_claims(token)
            tenant_id = validate_claim_shape(
                claims,
                client_id=matrix_client.client_id,
                required_scope=matrix_client.status_scope,
            )
            operation_id = uuid.uuid4()
            clients_evidence.append(
                {
                    "client_id": matrix_client.client_id,
                    "status_scope": matrix_client.status_scope,
                    "provider_control": matrix_client.provider_control,
                    "issuer": claims.get("iss"),
                    "audience": sorted(_audiences(claims.get("aud"))),
                    "azp": claims.get("azp"),
                    "lifetime_seconds": claims["exp"] - claims["iat"],
                    "tenant_sha256": _tenant_digest(tenant_id),
                }
            )
            records.append(
                _record(
                    client_id=matrix_client.client_id,
                    probe="valid_original_bearer_nonexistent_operation",
                    expected_status=404,
                    response=_operation_get(
                        client,
                        gateway_base_url=gateway_base_url,
                        operation_id=operation_id,
                        authorization=f"Bearer {token}",
                        tenant_id=tenant_id,
                        provider_control=matrix_client.provider_control,
                    ),
                )
            )
            records.append(
                _record(
                    client_id=matrix_client.client_id,
                    probe="tampered_signature",
                    expected_status=401,
                    response=_operation_get(
                        client,
                        gateway_base_url=gateway_base_url,
                        operation_id=operation_id,
                        authorization=f"Bearer {tamper_signature(token)}",
                        tenant_id=tenant_id,
                        provider_control=matrix_client.provider_control,
                    ),
                )
            )
            records.append(
                _record(
                    client_id=matrix_client.client_id,
                    probe="tenant_mismatch",
                    expected_status=403,
                    response=_operation_get(
                        client,
                        gateway_base_url=gateway_base_url,
                        operation_id=operation_id,
                        authorization=f"Bearer {token}",
                        tenant_id="matrix-mismatch-" + uuid.uuid4().hex,
                        provider_control=matrix_client.provider_control,
                    ),
                )
            )

        for case, fixture in sorted(fixtures.items()):
            records.append(
                _record(
                    client_id="<negative-fixture>",
                    probe=case,
                    expected_status=int(fixture["expected_status"]),
                    response=_operation_get(
                        client,
                        gateway_base_url=gateway_base_url,
                        operation_id=uuid.uuid4(),
                        authorization=f"Bearer {fixture['token']}",
                        tenant_id=fixture["tenant_id"],
                    ),
                )
            )

    passed = all(record["passed"] for record in records)
    certification_eligible = (
        passed and complete_client_coverage and extended_negative_coverage
    )
    evidence = {
        "schema_version": "1.0",
        "environment": "staging",
        "source_sha": source_sha,
        "image_digest": image_digest,
        "routes": {
            "standard": "/v1/operations/{command_id}",
            "provider_control": "/api/v1/control/identity-probes/{probe_id}",
        },
        "route_matrix_sha256": policy_digest,
        "generated_at": datetime.now(UTC).isoformat(),
        "clients": clients_evidence,
        "records": records,
        "summary": {
            "result": "PASS" if passed else "FAIL",
            "client_count": len(selected),
            "probe_count": len(records),
            "complete_client_coverage": complete_client_coverage,
            "extended_negative_coverage": extended_negative_coverage,
            "certification_eligible": certification_eligible,
            "command_posts": 0,
            "provider_calls": 0,
            "business_mutations": 0,
            "tokens_recorded": False,
            "secrets_recorded": False,
            "external_effects_enabled": "NONE",
        },
    }
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    evidence_path.chmod(0o600)
    return evidence, evidence_path


def main() -> int:
    try:
        evidence, evidence_path = run()
    except (MatrixError, httpx.HTTPError) as exc:
        print(f"AUTH_MATRIX=FAIL reason={exc}", file=sys.stderr)
        return 1
    summary = evidence["summary"]
    print(f"AUTH_MATRIX={summary['result']}")
    print(f"AUTH_MATRIX_CLIENTS={summary['client_count']}")
    print(f"AUTH_MATRIX_PROBES={summary['probe_count']}")
    print("AUTH_MATRIX_COMMAND_POSTS=0")
    print("AUTH_MATRIX_PROVIDER_CALLS=0")
    print("AUTH_MATRIX_EXTERNAL_EFFECTS=NONE")
    print(
        "AUTH_MATRIX_CERTIFICATION_ELIGIBLE="
        + ("YES" if summary["certification_eligible"] else "NO")
    )
    print(f"AUTH_MATRIX_EVIDENCE={evidence_path}")
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
