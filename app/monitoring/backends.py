"""Typed, bounded access to registered monitoring backends and release artifacts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
from urllib.parse import quote, urlsplit

from fastapi import HTTPException
import httpx

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SENSITIVE = re.compile(
    r"authorization|password|secret|token|cookie|private.?key|dsn|message.?body|email.?body",
    re.I,
)
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*")


def redact(value, depth=0):
    if depth > 20:
        return "[depth limited]"
    if isinstance(value, dict):
        return {
            str(k): redact(v, depth + 1)
            for k, v in value.items()
            if not SENSITIVE.search(str(k))
        }
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value[:10000]]
    if isinstance(value, str):
        return EMAIL.sub("[redacted]", BEARER.sub("Bearer [redacted]", value))[:16384]
    return value


def load_config():
    path = os.getenv("MONITORING_CONFIG_FILE", "")
    if not path:
        raise HTTPException(503, "monitoring release configuration is not mounted")
    try:
        raw = Path(path).read_bytes()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("size")
        value = json.loads(raw)
        if value.get("schema_version") != 1 or not isinstance(
            value.get("services"), dict
        ):
            raise ValueError("schema")
        if not isinstance(value.get("revision"), str):
            raise ValueError("revision")
        return value
    except (OSError, ValueError, TypeError, AttributeError):
        raise HTTPException(
            503, "monitoring release configuration is invalid"
        ) from None


def service_for(config, principal, service_id, environment=None):
    service = config["services"].get(service_id)
    if not service or service.get("tenant") != principal.tenant:
        raise HTTPException(404, "registered service not found")
    if environment and environment not in service.get("environments", []):
        raise HTTPException(404, "service environment not registered")
    return service


def load_github_secret():
    """Load webhook identity from mounted release configuration, not HTTP input."""
    config = load_config()
    try:
        path = config["github"]["secret_file"]
        with Path(path).open("rb") as stream:
            raw = stream.read(8193)
        secret = raw.strip()
        if len(raw) > 8192 or len(secret) < 32:
            raise ValueError("secret length")
        return secret
    except (KeyError, OSError, ValueError, TypeError):
        raise HTTPException(503, "GitHub webhook identity unavailable") from None


class Backends:
    def __init__(self, config, transport=None):
        self.config = config
        self.transport = transport

    async def get(
        self, backend, path, params=None, *, tenant=None, text_response=False
    ):
        binding = self.config.get("backends", {}).get(backend)
        if not binding:
            raise HTTPException(503, "monitoring backend is not configured")
        base = binding.get("base_url", "")
        parsed = urlsplit(base)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise HTTPException(503, "invalid monitoring backend binding")
        if parsed.scheme == "http" and not binding.get("private_network_http", False):
            raise HTTPException(503, "monitoring backend requires TLS")
        if not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
            raise HTTPException(503, "invalid backend operation")
        headers = {"Accept": "application/json"}
        if binding.get("token_file"):
            try:
                token = Path(binding["token_file"]).read_text().strip()
                if not token or len(token) > 8192 or "\n" in token:
                    raise ValueError("token")
                headers["Authorization"] = "Bearer " + token
            except (OSError, ValueError):
                raise HTTPException(503, "backend identity unavailable") from None
        if backend in {"loki", "tempo"}:
            mapping = binding.get("tenant_map", {})
            if tenant not in mapping:
                raise HTTPException(403, "backend tenant not bound")
            headers["X-Scope-OrgID"] = mapping[tenant]
        verify = binding.get("ca_file", True)
        if verify is False:
            raise HTTPException(503, "TLS verification may not be disabled")
        try:
            async with httpx.AsyncClient(
                timeout=5.0,
                follow_redirects=False,
                trust_env=False,
                verify=verify,
                transport=self.transport,
                limits=httpx.Limits(max_connections=10),
            ) as client:
                async with client.stream(
                    "GET", base.rstrip("/") + path, params=params, headers=headers
                ) as response:
                    accepted = {200}
                    if backend == "openbao" and path == "/v1/sys/health":
                        accepted.update({429, 472, 473, 501, 503})
                    if response.status_code not in accepted:
                        raise HTTPException(503, "monitoring backend request failed")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise HTTPException(
                                502, "monitoring backend response exceeds budget"
                            )
                    if text_response:
                        return body.decode("utf-8")
                    value = json.loads(body)
                    if backend == "sentry":
                        if not isinstance(value, list) or not all(
                            isinstance(row, dict) for row in value
                        ):
                            raise ValueError("invalid issue response")
                    elif not isinstance(value, dict):
                        raise ValueError("invalid object response")
                    if isinstance(value, dict) and value.get("error"):
                        raise ValueError("backend reported an error")
                    return redact(value)
        except (httpx.HTTPError, ValueError, UnicodeError):
            raise HTTPException(
                503, "monitoring backend unavailable or invalid response"
            ) from None

    async def query(self, family, body, principal):
        service_for(self.config, principal, body.service_id, body.environment)
        template = self.config.get("queries", {}).get(body.query_id)
        if not template or template.get("family") != family:
            raise HTTPException(422, "registered query template required")
        if body.service_id not in template.get("services", []):
            raise HTTPException(403, "query not bound to service")
        query = template.get("query", "")
        # Only reviewed named templates are accepted. Tenant/service values are
        # quoted literals, and never user-supplied query expressions.
        if not all(x in query for x in ["${tenant}", "${service}", "${environment}"]):
            raise HTTPException(503, "query template lacks mandatory scope bindings")
        for key, value in {
            "tenant": principal.tenant,
            "service": body.service_id,
            "environment": body.environment,
        }.items():
            query = query.replace("${" + key + "}", json.dumps(value))
        end = body.end or datetime.now(UTC)
        start = body.start or end - timedelta(hours=24)
        if (end - start).total_seconds() / body.step_seconds > 10000:
            raise HTTPException(422, "query exceeds point budget")
        if family in {"metrics", "metrics-range"}:
            params = {"query": query, "timeout": "5s"}
            path = "/api/v1/query"
            if family == "metrics-range":
                path = "/api/v1/query_range"
                params.update(
                    start=start.timestamp(), end=end.timestamp(), step=body.step_seconds
                )
            else:
                params["time"] = end.timestamp()
            value = await self.get("prometheus", path, params, tenant=principal.tenant)
            if value.get("status") != "success":
                raise HTTPException(503, "metric query did not succeed")
            result = value.get("data", {})
            if not isinstance(result, dict) or not isinstance(
                result.get("result", []), list
            ):
                raise HTTPException(503, "invalid metric result")
            series = result.get("result", [])
            if (
                len(series) > 1000
                or sum(
                    len(x.get("values", [])) or 1 for x in series if isinstance(x, dict)
                )
                > 10000
            ):
                raise HTTPException(502, "metric result exceeds point budget")
            return result
        if family == "logs":
            result = await self.get(
                "loki",
                "/loki/api/v1/query_range",
                {
                    "query": query,
                    "start": int(start.timestamp() * 1e9),
                    "end": int(end.timestamp() * 1e9),
                    "limit": body.limit,
                },
                tenant=principal.tenant,
            )
            if result.get("status") != "success":
                raise HTTPException(503, "log query did not succeed")
            return result
        return await self.get(
            "tempo",
            "/api/search",
            {
                "q": query,
                "start": int(start.timestamp()),
                "end": int(end.timestamp()),
                "limit": min(body.limit, 100),
            },
            tenant=principal.tenant,
        )

    async def integration(self, name, binding, principal):
        backend = binding["backend"]
        if backend == "backstage":
            raw = await self.get(
                backend,
                "/api/catalog/entities/by-query",
                {"limit": 100, "fields": "kind,metadata.name,metadata.namespace"},
            )
            return {
                "backend": "backstage",
                "catalog_entities": len(raw.get("items", [])),
                "page_limited": True,
            }
        if backend == "sentry":
            organization = quote(binding["organization"], safe="")
            project = quote(binding["project"], safe="")
            raw = await self.get(
                backend,
                f"/api/0/projects/{organization}/{project}/issues/",
                {"query": "is:unresolved", "per_page": 100},
            )
            return {
                "backend": "sentry",
                "unresolved_issues_in_page": len(raw),
                "page_limited": True,
                "issues": [
                    {
                        k: v
                        for k, v in row.items()
                        if k in {"id", "shortId", "status", "count", "lastSeen"}
                    }
                    for row in raw[:100]
                ],
            }
        if backend == "wazuh":
            raw = await self.get(
                backend, "/agents", {"limit": 100, "select": "id,status"}
            )
            data = raw.get("data", {})
            return {
                "backend": "wazuh",
                "agents": [
                    {k: v for k, v in row.items() if k in {"id", "status"}}
                    for row in data.get("affected_items", [])[:100]
                ],
                "total_agents": data.get("total_affected_items"),
                "page_limited": True,
            }
        raise HTTPException(422, "integration has no supported live read adapter")
