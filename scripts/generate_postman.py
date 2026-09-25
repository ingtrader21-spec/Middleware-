#!/usr/bin/env python3
"""Generate a deterministic Postman collection from canonical Middleware OpenAPI."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "contracts/platform/middleware-openapi.generated.json"
OUTPUT = ROOT / "postman/generated/Middleware-OpenAPI.postman_collection.json"
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _example(schema: dict[str, Any] | None) -> Any:
    if not isinstance(schema, dict):
        return {}
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    kind = schema.get("type")
    if kind == "object":
        return {
            key: _example(value)
            for key, value in sorted((schema.get("properties") or {}).items())
        }
    if kind == "array":
        return []
    if kind == "integer":
        return 0
    if kind == "number":
        return 0
    if kind == "boolean":
        return False
    return ""


def _resolve_ref(doc: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    ref = value.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return value
    node: Any = doc
    for part in ref[2:].split("/"):
        node = node[part]
    return node if isinstance(node, dict) else value


def _request(doc: dict[str, Any], path: str, method: str, op: dict[str, Any]) -> dict[str, Any]:
    raw = "{{base_url}}" + path
    headers = []
    query = []
    for param in op.get("parameters", []):
        if not isinstance(param, dict):
            continue
        param = _resolve_ref(doc, param)
        name = str(param.get("name", ""))
        if not name:
            continue
        loc = param.get("in")
        value = "{{" + name.lower().replace("-", "_") + "}}"
        if loc == "header":
            headers.append({"key": name, "value": value, "type": "text"})
        elif loc == "query":
            query.append({
                "key": name,
                "value": value,
                "disabled": not bool(param.get("required")),
            })
    if path.startswith("/internal/v1/database"):
        headers.append({
            "key": "Authorization",
            "value": "Bearer {{db_read_token}}",
            "type": "text",
        })
    elif path not in {
        "/health", "/health/live", "/health/ready", "/healthz", "/readyz"
    }:
        headers.append({
            "key": "Authorization",
            "value": "Bearer {{bearer_token}}",
            "type": "text",
        })
    request: dict[str, Any] = {
        "method": method.upper(),
        "header": headers,
        "url": {
            "raw": raw,
            "host": ["{{base_url}}"],
            "path": [p for p in path.split("/") if p],
            "query": query,
        },
    }
    body = op.get("requestBody")
    if isinstance(body, dict):
        body = _resolve_ref(doc, body)
        content = body.get("content") or {}
        media = content.get("application/json")
        if isinstance(media, dict):
            schema = _resolve_ref(doc, media.get("schema") or {})
            request["body"] = {
                "mode": "raw",
                "raw": json.dumps(
                    _example(schema), indent=2, ensure_ascii=False
                ),
                "options": {"raw": {"language": "json"}},
            }
            request["header"].append({
                "key": "Content-Type",
                "value": "application/json",
                "type": "text",
            })
    item = {
        "name": op.get("summary")
        or op.get("operationId")
        or f"{method.upper()} {path}",
        "request": request,
    }
    events = []
    if method.lower() not in {"get", "head", "options"}:
        events.append({
            "listen": "prerequest",
            "script": {
                "type": "text/javascript",
                "exec": [
                    "if (pm.collectionVariables.get('allow_mutating_requests') !== 'true') {",
                    "  pm.execution.skipRequest();",
                    "}",
                ],
            },
        })
    exact_200 = path in {
        "/health", "/health/live", "/health/ready", "/healthz", "/readyz"
    }
    test_exec = [
        "pm.test('response received', () => pm.expect(pm.response).to.exist);",
    ]
    if exact_200:
        test_exec.append("pm.test('health endpoint 200', () => pm.response.to.have.status(200));")
    else:
        test_exec.append("pm.test('no server error', () => pm.expect(pm.response.code).to.be.below(500));")
    events.append({
        "listen": "test",
        "script": {"type": "text/javascript", "exec": test_exec},
    })
    item["event"] = events
    return item


def build() -> tuple[dict[str, Any], str]:
    doc = json.loads(OPENAPI.read_text(encoding="utf-8"))
    digest = hashlib.sha256(OPENAPI.read_bytes()).hexdigest()
    groups: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(doc.get("paths", {})):
        item = doc["paths"][path]
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            tags = op.get("tags") or ["untagged"]
            tag = str(tags[0])
            groups.setdefault(tag, []).append(
                _request(doc, path, method, op)
            )
    collection = {
        "info": {
            "_postman_id": "middleware-openapi-generated",
            "name": "Middleware OpenAPI - Generated",
            "description": (
                "Generated from contracts/platform/middleware-openapi.generated.json. "
                "Do not edit by hand; use scripts/generate_postman.py."
            ),
            "schema": (
                "https://schema.getpostman.com/json/collection/"
                "v2.1.0/collection.json"
            ),
        },
        "variable": [
            {"key": "base_url", "value": "http://127.0.0.1:8095"},
            {"key": "bearer_token", "value": ""},
            {"key": "db_read_token", "value": ""},
            {"key": "db_verify_token", "value": ""},
            {"key": "allow_mutating_requests", "value": "false"},
        ],
        "item": [
            {"name": tag, "item": groups[tag]}
            for tag in sorted(groups)
        ],
    }
    return collection, digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    collection, digest = build()
    rendered = _json(collection)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit("generated Postman collection drift")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"POSTMAN_OPENAPI_DIGEST={digest}")
    print(f"POSTMAN_COLLECTION={OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
