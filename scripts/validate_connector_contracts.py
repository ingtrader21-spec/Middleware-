#!/usr/bin/env python3
"""Validate isolated, fail-closed middleware connector contracts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
CONNECTORS = ROOT / "config" / "connectors"
SCHEMA_PATH = ROOT / "contracts" / "connector.schema.json"
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
WORKSTREAM_RE = re.compile(r"^(integration|platform|site)/[a-z0-9][a-z0-9-]*$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
ROOT_KEYS = {"version", "id", "workstream", "repository", "role", "transport", "authentication", "runtime", "deployment_evidence"}
TRANSPORT_KEYS = {"protocol", "base_url_env", "health_path"}
AUTH_KEYS = {"method", "keycloak_client_id", "secret_env"}
RUNTIME_KEYS = {"enabled_by_default", "external_effects_enabled", "status"}
EVIDENCE_KEYS = {"deployed", "verified_commit", "verified_at", "notes"}
ROLES = {"frontend", "backend", "identity", "gateway", "erp", "social-site", "social-adapter"}


def main() -> int:
    errors: list[str] = []
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError, Exception) as exc:
        print(f"Connector schema validation failed: {exc}", file=sys.stderr)
        return 1
    schema_validator = Draft202012Validator(schema, format_checker=FormatChecker())
    ids: set[str] = set()
    clients: set[str] = set()
    files = sorted(CONNECTORS.glob("*.json")) if CONNECTORS.exists() else []
    for path in files:
        try:
            item = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        for violation in sorted(schema_validator.iter_errors(item), key=lambda e: list(e.path)):
            location = ".".join(str(part) for part in violation.path) or "<root>"
            errors.append(f"{path.name}: schema {location}: {violation.message}")
        if set(item) != ROOT_KEYS:
            errors.append(f"{path.name}: root fields must exactly match the schema")
        if item.get("role") not in ROLES:
            errors.append(f"{path.name}: invalid role")
        connector_id = item.get("id")
        client_id = item.get("authentication", {}).get("keycloak_client_id")
        if item.get("version") != 1:
            errors.append(f"{path.name}: version must be 1")
        if not isinstance(connector_id, str) or not ID_RE.fullmatch(connector_id):
            errors.append(f"{path.name}: invalid id")
        elif connector_id in ids:
            errors.append(f"{path.name}: duplicate connector id {connector_id}")
        else:
            ids.add(connector_id)
        if path.stem != connector_id:
            errors.append(f"{path.name}: filename must match connector id")
        if not WORKSTREAM_RE.fullmatch(str(item.get("workstream", ""))):
            errors.append(f"{path.name}: invalid workstream")
        repository = item.get("repository")
        if not isinstance(repository, str) or not repository.startswith("appolon1908-hue/"):
            errors.append(f"{path.name}: explicit appolon1908-hue repository required")
        transport = item.get("transport", {})
        if not isinstance(transport, dict) or set(transport) != TRANSPORT_KEYS:
            errors.append(f"{path.name}: transport fields must exactly match the schema")
            transport = {} if not isinstance(transport, dict) else transport
        if transport.get("protocol") not in {"https", "oidc", "internal_https"}:
            errors.append(f"{path.name}: invalid transport protocol")
        base_url_env = transport.get("base_url_env")
        if not isinstance(base_url_env, str) or not ENV_RE.fullmatch(base_url_env) or not base_url_env.endswith("_BASE_URL"):
            errors.append(f"{path.name}: base URL must be an environment-variable reference")
        if not str(transport.get("health_path", "")).startswith("/"):
            errors.append(f"{path.name}: health_path must be absolute")
        auth = item.get("authentication", {})
        if not isinstance(auth, dict) or set(auth) != AUTH_KEYS:
            errors.append(f"{path.name}: authentication fields must exactly match the schema")
            auth = {} if not isinstance(auth, dict) else auth
        if auth.get("method") not in {"oidc_client_credentials", "oidc_authorization_code", "oidc_jwks"}:
            errors.append(f"{path.name}: invalid authentication method")
        if not isinstance(client_id, str) or not client_id.startswith("middleware-"):
            errors.append(f"{path.name}: dedicated middleware Keycloak client required")
        elif client_id in clients:
            errors.append(f"{path.name}: Keycloak client is shared: {client_id}")
        else:
            clients.add(client_id)
        secret_env = auth.get("secret_env")
        if secret_env is not None and (not isinstance(secret_env, str) or not ENV_RE.fullmatch(secret_env) or not secret_env.endswith("_CLIENT_SECRET")):
            errors.append(f"{path.name}: secret must be an environment-variable reference")
        runtime = item.get("runtime", {})
        if not isinstance(runtime, dict) or set(runtime) != RUNTIME_KEYS:
            errors.append(f"{path.name}: runtime fields must exactly match the schema")
            runtime = {} if not isinstance(runtime, dict) else runtime
        if runtime != {"enabled_by_default": False, "external_effects_enabled": False, "status": "runtime_unconfirmed"}:
            errors.append(f"{path.name}: runtime must remain fail closed and unconfirmed")
        evidence = item.get("deployment_evidence", {})
        if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_KEYS:
            errors.append(f"{path.name}: deployment evidence fields must exactly match the schema")
            evidence = {} if not isinstance(evidence, dict) else evidence
        if evidence.get("deployed") is not False or evidence.get("verified_commit") is not None or evidence.get("verified_at") is not None:
            errors.append(f"{path.name}: deployment evidence must not claim an unperformed deployment")
        if evidence.get("notes") != "Configuration contract only; no live deployment performed.":
            errors.append(f"{path.name}: deployment evidence notes must match the schema")
    if errors:
        print("Connector contract validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"Connector contract validation passed: {len(files)} isolated connector(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
