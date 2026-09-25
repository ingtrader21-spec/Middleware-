#!/usr/bin/env python3
"""Generate a deterministic Postman collection from canonical Middleware OpenAPI."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "contracts" / "platform" / "middleware-openapi.generated.json"
OUTPUT = ROOT / "postman" / "generated" / "Middleware-OpenAPI.postman_collection.json"
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
HEALTH_PATHS = {"/health", "/health/live", "/health/ready", "/healthz", "/readyz"}


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _resolve_ref(doc: dict[str, Any], value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    ref = value.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return value
    node: Any = doc
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _example(
    doc: dict[str, Any],
    schema: Any,
    *,
    seen_refs: frozenset[str] = frozenset(),
) -> Any:
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen_refs:
            return {}
        resolved = _resolve_ref(doc, schema)
        if resolved is schema:
            return {}
        return _example(doc, resolved, seen_refs=seen_refs | {ref})
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    for keyword in ("oneOf", "anyOf", "allOf"):
        variants = schema.get(keyword)
        if isinstance(variants, list) and variants:
            if keyword == "allOf":
                merged: dict[str, Any] = {}
                for variant in variants:
                    value = _example(doc, variant, seen_refs=seen_refs)
                    if isinstance(value, dict):
                        merged.update(value)
                return merged
            return _example(doc, variants[0], seen_refs=seen_refs)
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        return {
            key: _example(doc, value, seen_refs=seen_refs)
            for key, value in sorted((schema.get("properties") or {}).items())
        }
    if kind == "array":
        items = schema.get("items")
        return [_example(doc, items, seen_refs=seen_refs)] if isinstance(items, dict) else []
    if kind == "integer":
        return 0
    if kind == "number":
        return 0
    if kind == "boolean":
        return False
    return ""


def _variable_name(name: str) -> str:
    return name.lower().replace("-", "_")


def _parameters(
    doc: dict[str, Any],
    path_item: dict[str, Any],
    op: dict[str, Any],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source in (path_item.get("parameters", []), op.get("parameters", [])):
        for raw in source or []:
            if not isinstance(raw, dict):
                continue
            param = _resolve_ref(doc, raw)
            if not isinstance(param, dict):
                continue
            name = str(param.get("name", ""))
            loc = str(param.get("in", ""))
            if not name or not loc:
                continue
            merged[(loc, name)] = param
    return list(merged.values())


def _expected_statuses(op: dict[str, Any], path: str) -> list[int]:
    if path in HEALTH_PATHS:
        return [200]
    declared: list[int] = []
    responses = op.get("responses") or {}
    if isinstance(responses, dict):
        for code in responses:
            try:
                declared.append(int(str(code)))
            except ValueError:
                continue
    successes = sorted({value for value in declared if 200 <= value < 400})
    if successes:
        return successes
    # Some read-only probe routes are intentionally negative-only (for example,
    # a nonexistent identity probe used to prove tenant/auth isolation). For
    # those routes, honor the explicit OpenAPI statuses instead of inventing 200.
    return sorted(set(declared))


def _request(
    doc: dict[str, Any],
    path: str,
    method: str,
    path_item: dict[str, Any],
    op: dict[str, Any],
) -> dict[str, Any]:
    rendered_path = path
    headers: list[dict[str, Any]] = []
    query: list[dict[str, Any]] = []
    for param in _parameters(doc, path_item, op):
        name = str(param.get("name", ""))
        loc = param.get("in")
        variable = _variable_name(name)
        value = "{{" + variable + "}}"
        if loc == "path":
            rendered_path = rendered_path.replace("{" + name + "}", value)
        elif loc == "header":
            headers.append({"key": name, "value": value, "type": "text"})
        elif loc == "query":
            query.append(
                {
                    "key": name,
                    "value": value,
                    "disabled": not bool(param.get("required")),
                }
            )

    raw = "{{base_url}}" + rendered_path
    if path.startswith("/internal/v1/database"):
        headers.append(
            {
                "key": "Authorization",
                "value": "Bearer {{db_read_token}}",
                "type": "text",
            }
        )
    elif path not in HEALTH_PATHS:
        headers.append(
            {
                "key": "Authorization",
                "value": "Bearer {{bearer_token}}",
                "type": "text",
            }
        )

    request: dict[str, Any] = {
        "method": method.upper(),
        "header": headers,
        "url": {
            "raw": raw,
            "host": ["{{base_url}}"],
            "path": [p for p in rendered_path.split("/") if p],
            "query": query,
        },
    }
    body = op.get("requestBody")
    if isinstance(body, dict):
        body = _resolve_ref(doc, body)
        content = body.get("content") or {} if isinstance(body, dict) else {}
        media = content.get("application/json") if isinstance(content, dict) else None
        if isinstance(media, dict):
            schema = media.get("schema") or {}
            request["body"] = {
                "mode": "raw",
                "raw": json.dumps(_example(doc, schema), indent=2, ensure_ascii=False),
                "options": {"raw": {"language": "json"}},
            }
            request["header"].append(
                {"key": "Content-Type", "value": "application/json", "type": "text"}
            )

    statuses = _expected_statuses(op, path)
    tests = [
        f"const allowedSuccessStatuses = {json.dumps(statuses)};",
        "pm.test('response matches OpenAPI success contract', () => "
        "pm.expect(allowedSuccessStatuses).to.include(pm.response.code));",
    ]
    return {
        "name": op.get("summary")
        or op.get("operationId")
        or f"{method.upper()} {path}",
        "request": request,
        "event": [
            {
                "listen": "test",
                "script": {"type": "text/javascript", "exec": tests},
            }
        ],
    }


def _collection_events() -> list[dict[str, Any]]:
    return [
        {
            "listen": "prerequest",
            "script": {
                "type": "text/javascript",
                "exec": [
                    "const safeMethods = ['GET','HEAD','OPTIONS'];",
                    "const method = String(pm.request.method || '').toUpperCase();",
                    "const environment = String(pm.variables.replaceIn('{{environment}}') || '').trim().toLowerCase();",
                    "const allowEffectful = String(pm.variables.replaceIn('{{RUN_EFFECTFUL}}') || '').toLowerCase() === 'true';",
                    "const production = ['production','prod'].includes(environment);",
                    "if (!safeMethods.includes(method) && (production || !allowEffectful)) {",
                    "  pm.execution.skipRequest();",
                    "}",
                ],
            },
        },
        {
            "listen": "test",
            "script": {
                "type": "text/javascript",
                "exec": [
                    "const requestId = pm.response.headers.get('X-Request-ID') || pm.response.headers.get('X-Correlation-ID');",
                    "if (requestId) { pm.test('response correlation identifier is non-empty', () => pm.expect(String(requestId).trim()).not.to.eql('')); }",
                ],
            },
        },
    ]


def build() -> tuple[dict[str, Any], str]:
    doc = json.loads(OPENAPI.read_text(encoding="utf-8"))
    digest = hashlib.sha256(OPENAPI.read_bytes()).hexdigest()
    groups: dict[str, list[dict[str, Any]]] = {}
    variable_names = {"base_url", "environment", "RUN_EFFECTFUL", "bearer_token", "db_read_token", "db_verify_token"}

    for path in sorted(doc.get("paths", {})):
        path_item = doc["paths"][path]
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            for param in _parameters(doc, path_item, op):
                if param.get("in") in {"path", "query", "header"}:
                    variable_names.add(_variable_name(str(param.get("name", ""))))
            tags = op.get("tags") or ["untagged"]
            tag = str(tags[0])
            groups.setdefault(tag, []).append(_request(doc, path, method, path_item, op))

    defaults = {
        "base_url": "http://127.0.0.1:8095",
        "environment": "local",
        "RUN_EFFECTFUL": "false",
        "bearer_token": "",
        "db_read_token": "",
        "db_verify_token": "",
    }
    collection = {
        "info": {
            "_postman_id": "middleware-openapi-generated",
            "name": "Middleware OpenAPI - Generated",
            "description": (
                "Generated from contracts/platform/middleware-openapi.generated.json. "
                "Do not edit by hand; use scripts/generate_postman.py. "
                "Effectful methods are skipped by default and always denied in production; "
                "executed requests assert an OpenAPI-declared success status."
            ),
            "schema": (
                "https://schema.getpostman.com/json/collection/"
                "v2.1.0/collection.json"
            ),
        },
        "event": _collection_events(),
        "variable": [
            {"key": key, "value": defaults.get(key, "")}
            for key in sorted(variable_names)
            if key
        ],
        "item": [{"name": tag, "item": groups[tag]} for tag in sorted(groups)],
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
