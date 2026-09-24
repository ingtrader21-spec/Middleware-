"""Read-only monitoring collector: actual configuration and freshness -> Middleware observations.

The collector is the runtime half of the reconciler. It reads what each
component is *actually* running — Prometheus' active configuration, targets and
rules, Alertmanager's loaded configuration, Grafana's provisioned datasources
and dashboards, Loki/Tempo/Alloy configuration and readiness, the OpenTelemetry
gateway health, OpenBao ``/v1/sys/health`` and every exporter's ``/metrics`` —
computes bounded digests, and posts ``config``/``deployment`` observations to
Middleware. Middleware derives ``pending | applying | synced | drifted | failed |
unknown`` from those observations; the collector never decides ``synced`` and
never mutates a component.

Safety: GET only; TLS verified; no redirects; bearer tokens are read from
files and never written to reports or logs; report fields are bounded and
enumerated; a component that cannot be read is reported ``failed`` rather than
omitted; if Middleware itself is unavailable the run fails closed without
touching local sequence state.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SECRET_SHAPED = re.compile(
    r"(hvs\.[A-Za-z0-9_-]{20,}|hvb\.[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._~+/-]{16,})"
)
COMPONENT_KINDS = (
    "prometheus",
    "alertmanager",
    "grafana",
    "loki",
    "tempo",
    "alloy",
    "otel-gateway",
    "openbao",
    "node-exporter",
    "cadvisor",
    "redis-exporter",
    "postgres-exporter",
    "blackbox",
)
EXPORTER_SENTINELS = {
    "node-exporter": "node_exporter_build_info",
    "cadvisor": "cadvisor_version_info",
    "redis-exporter": "redis_up",
    "postgres-exporter": "pg_up",
    "blackbox": "blackbox_exporter_build_info",
}
STALE_AFTER = timedelta(seconds=90)


class CollectorError(RuntimeError):
    """A fail-closed collector condition (never a partial or fabricated result)."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        raise CollectorError(f"redirect refused ({code})")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def read_token(path: str | None) -> str | None:
    if not path:
        return None
    file = Path(path)
    if not file.is_absolute() or file.is_symlink() or not file.is_file():
        raise CollectorError("token file is unavailable or unsafe")
    value = file.read_text(encoding="utf-8").strip()
    if not value or any(character in value for character in " \t\r\n"):
        raise CollectorError("token file is empty or malformed")
    return value


def scrub(text: str) -> str:
    return SECRET_SHAPED.sub("[REDACTED]", text)


@dataclass
class Http:
    """Bounded GET client: verified TLS, optional CA, optional bearer, no redirects."""

    timeout: float = 5.0
    ca_file: str | None = None
    token: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    max_bytes: int = 4 * 1024 * 1024
    opener_factory: Callable[..., Any] | None = None

    def get(
        self, url: str, accept: str = "application/json"
    ) -> tuple[int, bytes, dict[str, str]]:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise CollectorError("url is not an approved plain endpoint")
        headers = {"Accept": accept, "User-Agent": "codestra-monitoring-collector/1"}
        headers.update(self.extra_headers)
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(url, headers=headers, method="GET")
        context = (
            ssl.create_default_context(cafile=self.ca_file)
            if parsed.scheme == "https"
            else None
        )
        factory = self.opener_factory or urllib.request.build_opener
        opener = (
            factory(NoRedirect(), urllib.request.HTTPSHandler(context=context))
            if context
            else factory(NoRedirect())
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise CollectorError("response exceeds the collector budget")
                return (
                    response.status,
                    body,
                    {k.lower(): v for k, v in response.headers.items()},
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(self.max_bytes) if exc.fp else b""
            return (
                exc.code,
                body,
                {k.lower(): v for k, v in (exc.headers or {}).items()},
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CollectorError(
                scrub(f"unreachable: {exc.reason if hasattr(exc, 'reason') else exc}")
            ) from None

    def json(self, url: str) -> tuple[int, Any]:
        status, body, _ = self.get(url)
        try:
            return status, (json.loads(body) if body else None)
        except json.JSONDecodeError as exc:
            raise CollectorError(
                f"non-JSON response from {urllib.parse.urlsplit(url).path}"
            ) from exc

    def post_json(
        self, url: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, Any]:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        all_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "codestra-monitoring-collector/1",
        }
        all_headers.update(headers)
        if self.token:
            all_headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(
            url, data=data, headers=all_headers, method="POST"
        )
        parsed = urllib.parse.urlsplit(url)
        context = (
            ssl.create_default_context(cafile=self.ca_file)
            if parsed.scheme == "https"
            else None
        )
        factory = self.opener_factory or urllib.request.build_opener
        opener = (
            factory(NoRedirect(), urllib.request.HTTPSHandler(context=context))
            if context
            else factory(NoRedirect())
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_bytes)
                return response.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as exc:
            body = exc.read(self.max_bytes) if exc.fp else b""
            try:
                return exc.code, (json.loads(body) if body else None)
            except json.JSONDecodeError:
                return exc.code, None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CollectorError(
                scrub(
                    f"middleware unreachable: {exc.reason if hasattr(exc, 'reason') else exc}"
                )
            ) from None


@dataclass
class Reading:
    component: str
    status: str  # observed | failed
    reachable: bool
    config_digest: str | None
    details: dict[str, Any]
    freshness_seconds: float | None
    error: str | None
    observed_at: str

    def public(self) -> dict[str, Any]:
        value = asdict(self)
        value["details"] = {
            k: v
            for k, v in self.details.items()
            if isinstance(v, (int, float, str, bool)) or v is None
        }
        if value["error"]:
            value["error"] = scrub(value["error"])[:256]
        return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _reading(
    component: str,
    *,
    digest: str | None = None,
    details: dict[str, Any] | None = None,
    freshness: float | None = None,
) -> Reading:
    return Reading(
        component,
        "observed",
        True,
        digest,
        details or {},
        freshness,
        None,
        _now().isoformat(),
    )


def _failed(component: str, error: str) -> Reading:
    return Reading(
        component,
        "failed",
        False,
        None,
        {},
        None,
        scrub(error)[:256],
        _now().isoformat(),
    )


# --- component readers ------------------------------------------------------------------


def read_prometheus(http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/-/ready", accept="text/plain")
    if status != 200:
        return _failed("prometheus", f"readiness {status}")
    status, config = http.json(base + "/api/v1/status/config")
    if (
        status != 200
        or not isinstance(config, dict)
        or "yaml" not in config.get("data", {})
    ):
        return _failed("prometheus", f"active configuration unavailable ({status})")
    digest = digest_bytes(config["data"]["yaml"].encode("utf-8"))
    status, targets = http.json(base + "/api/v1/targets?state=active")
    active = (
        targets.get("data", {}).get("activeTargets", [])
        if status == 200 and isinstance(targets, dict)
        else []
    )
    now = _now()
    health = {"up": 0, "down": 0, "unknown": 0}
    freshest: float | None = None
    per_target: list[dict[str, Any]] = []
    for target in active:
        state = target.get("health", "unknown")
        health[state if state in health else "unknown"] += 1
        last = target.get("lastScrape")
        age = None
        if isinstance(last, str):
            try:
                age = (
                    now - datetime.fromisoformat(last.replace("Z", "+00:00"))
                ).total_seconds()
                freshest = age if freshest is None else min(freshest, age)
            except ValueError:
                age = None
        labels = target.get("labels", {})
        per_target.append(
            {
                "job": labels.get("job"),
                "service": labels.get("service"),
                "environment": labels.get("environment"),
                "scrape_url_host": urllib.parse.urlsplit(
                    target.get("scrapeUrl", "")
                ).netloc,
                "health": state,
                "last_scrape_age_seconds": None if age is None else round(age, 1),
                "scrape_error": scrub(str(target.get("lastError", "")))[:120] or None,
            }
        )
    status, rules = http.json(base + "/api/v1/rules")
    groups = (
        rules.get("data", {}).get("groups", [])
        if status == 200 and isinstance(rules, dict)
        else []
    )
    rule_digest = digest_json(
        [
            [g.get("name"), g.get("file"), [r.get("name") for r in g.get("rules", [])]]
            for g in groups
        ]
    )
    reading = _reading(
        "prometheus",
        digest=digest,
        details={
            "targets_up": health["up"],
            "targets_down": health["down"],
            "targets_unknown": health["unknown"],
            "rule_groups": len(groups),
            "rules_digest": rule_digest,
        },
        freshness=freshest,
    )
    reading.details["targets"] = per_target
    return reading


def read_alertmanager(http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/-/ready", accept="text/plain")
    if status != 200:
        return _failed("alertmanager", f"readiness {status}")
    status, info = http.json(base + "/api/v2/status")
    if (
        status != 200
        or not isinstance(info, dict)
        or "original" not in info.get("config", {})
    ):
        return _failed("alertmanager", f"active configuration unavailable ({status})")
    digest = digest_bytes(info["config"]["original"].encode("utf-8"))
    status, alerts = http.json(base + "/api/v2/alerts")
    count = len(alerts) if status == 200 and isinstance(alerts, list) else None
    cluster = info.get("cluster", {}).get("status")
    return _reading(
        "alertmanager",
        digest=digest,
        details={
            "active_alerts": count,
            "cluster_status": cluster,
            "version": info.get("versionInfo", {}).get("version"),
        },
    )


def read_grafana(http: Http, base: str) -> Reading:
    status, health = http.json(base + "/api/health")
    if status != 200 or not isinstance(health, dict) or health.get("database") != "ok":
        return _failed("grafana", f"health {status}")
    status, sources = http.json(base + "/api/datasources")
    if status != 200 or not isinstance(sources, list):
        return _failed(
            "grafana",
            f"datasources unavailable ({status}); a read-only service account token is required",
        )
    binding = sorted(
        [
            [s.get("uid"), s.get("type"), s.get("url"), bool(s.get("readOnly"))]
            for s in sources
        ]
    )
    healths: dict[str, str] = {}
    for source in sources:
        uid = source.get("uid")
        if not isinstance(uid, str):
            continue
        code, result = http.json(
            base + f"/api/datasources/uid/{urllib.parse.quote(uid)}/health"
        )
        healths[uid] = (
            (result or {}).get("status", f"http-{code}")
            if isinstance(result, dict)
            else f"http-{code}"
        )
    status, dashboards = http.json(base + "/api/search?type=dash-db&limit=5000")
    uids = (
        sorted(str(d["uid"]) for d in dashboards if isinstance(d, dict) and d.get("uid"))
        if status == 200 and isinstance(dashboards, list)
        else []
    )
    digest = digest_json({"datasources": binding, "dashboards": uids})
    unhealthy = sorted(
        uid for uid, state in healths.items() if state not in {"OK", "ok"}
    )
    reading = _reading(
        "grafana",
        digest=digest,
        details={
            "datasources": len(binding),
            "dashboards": len(uids),
            "unhealthy_datasources": len(unhealthy),
            "version": health.get("version"),
        },
    )
    reading.details["datasource_health"] = healths
    return reading


def read_loki(http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/ready", accept="text/plain")
    if status != 200:
        return _failed(
            "loki", f"readiness {status}: {body[:80].decode('utf-8', 'replace')}"
        )
    status, config, _ = http.get(base + "/config", accept="application/yaml")
    if status != 200 or not config:
        return _failed("loki", f"active configuration unavailable ({status})")
    status, labels = http.json(base + "/loki/api/v1/labels")
    names = (
        labels.get("data", []) if status == 200 and isinstance(labels, dict) else None
    )
    return _reading(
        "loki",
        digest=digest_bytes(config),
        details={
            "label_names": None if names is None else len(names),
            "label_names_bounded": None if names is None else len(names) <= 15,
        },
    )


def read_tempo(http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/ready", accept="text/plain")
    if status != 200:
        return _failed("tempo", f"readiness {status}")
    status, config, _ = http.get(base + "/status/config", accept="application/yaml")
    if status != 200 or not config:
        return _failed("tempo", f"active configuration unavailable ({status})")
    status, echo, _ = http.get(base + "/api/echo", accept="text/plain")
    return _reading(
        "tempo", digest=digest_bytes(config), details={"echo": status == 200}
    )


def read_alloy(http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/-/ready", accept="text/plain")
    if status != 200:
        return _failed("alloy", f"readiness {status}")
    status, components = http.json(base + "/api/v0/web/components")
    if status != 200 or not isinstance(components, list):
        return _failed("alloy", f"component list unavailable ({status})")
    summary = sorted(
        [
            [
                c.get("name"),
                c.get("localID") or c.get("id"),
                c.get("health", {}).get("state"),
            ]
            for c in components
            if isinstance(c, dict)
        ]
    )
    unhealthy = sum(1 for item in summary if item[2] not in {"healthy", None})
    return _reading(
        "alloy",
        digest=digest_json(summary),
        details={"components": len(summary), "unhealthy_components": unhealthy},
    )


def read_otel_gateway(http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/", accept="application/json")
    if status != 200:
        return _failed("otel-gateway", f"health {status}")
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {}
    return _reading(
        "otel-gateway", digest=None, details={"status": payload.get("status", "up")}
    )


def read_openbao(http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/v1/sys/health", accept="application/json")
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {}
    if status not in {200, 429, 472, 473, 501, 503} or not isinstance(payload, dict):
        return _failed("openbao", f"health {status}")
    details = {
        "http_status": status,
        "initialized": payload.get("initialized"),
        "sealed": payload.get("sealed"),
        "standby": payload.get("standby"),
        "performance_standby": payload.get("performance_standby"),
        "version": payload.get("version"),
        "cluster_name": payload.get("cluster_name"),
    }
    healthy = (
        status in {200, 429}
        and payload.get("initialized") is True
        and payload.get("sealed") is False
    )
    reading = _reading("openbao", digest=None, details=details)
    if not healthy:
        reading.status = "failed"
        reading.error = f"openbao health {status}: initialized={payload.get('initialized')} sealed={payload.get('sealed')} (operator action; the collector never unseals)"
    return reading


def read_exporter(component: str, http: Http, base: str) -> Reading:
    status, body, _ = http.get(base + "/metrics", accept="text/plain")
    if status != 200:
        return _failed(component, f"metrics {status}")
    sentinel = EXPORTER_SENTINELS.get(component)
    text = body.decode("utf-8", "replace")
    present = sentinel is None or (sentinel in text)
    families = sum(1 for line in text.splitlines() if line.startswith("# TYPE "))
    reading = _reading(
        component,
        digest=None,
        details={"metric_families": families, "sentinel_present": present},
    )
    if not present:
        reading.status = "failed"
        reading.error = f"sentinel metric {sentinel} missing"
    return reading


READERS: dict[str, Callable[[Http, str], Reading]] = {
    "prometheus": read_prometheus,
    "alertmanager": read_alertmanager,
    "grafana": read_grafana,
    "loki": read_loki,
    "tempo": read_tempo,
    "alloy": read_alloy,
    "otel-gateway": read_otel_gateway,
    "openbao": read_openbao,
}
for _exporter in EXPORTER_SENTINELS:
    READERS[_exporter] = (
        lambda name: (lambda http, base: read_exporter(name, http, base))
    )(_exporter)


# --- configuration --------------------------------------------------------------------------


@dataclass
class ComponentTarget:
    component: str
    service_id: str
    base_url: str
    ca_file: str | None = None
    token_file: str | None = None
    tenant_header: str | None = None
    expected_endpoint: str | None = None
    authentication: str = "none"
    contract_sha: str | None = None


@dataclass
class CollectorConfig:
    environment: str
    source_deployment: str
    tenant: str
    middleware_base_url: str
    middleware_token_file: str
    middleware_ca_file: str | None
    components: list[ComponentTarget]
    service_components: dict[str, list[str]]
    version_endpoints: dict[str, str]
    state_dir: str
    timeout_seconds: float = 5.0

    @classmethod
    def load(cls, path: Path) -> "CollectorConfig":
        raw = json.loads(path.read_text(encoding="utf-8"))
        for key in (
            "environment",
            "source_deployment",
            "tenant",
            "middleware",
            "components",
            "service_components",
            "state_dir",
        ):
            if key not in raw:
                raise CollectorError(f"collector config missing {key}")
        if raw["environment"] not in {"development", "test", "staging", "production"}:
            raise CollectorError("collector environment is not governed")
        if not IDENTIFIER.fullmatch(
            raw["source_deployment"]
        ) or not IDENTIFIER.fullmatch(raw["tenant"]):
            raise CollectorError("source_deployment/tenant must be bounded identifiers")
        middleware = raw["middleware"]
        if not str(middleware.get("base_url", "")).startswith(
            ("http://", "https://")
        ) or not middleware.get("token_file"):
            raise CollectorError("middleware base_url and token_file are required")
        components = []
        for item in raw["components"]:
            if item.get("component") not in READERS:
                raise CollectorError(
                    f"unknown component reader {item.get('component')!r}"
                )
            if not IDENTIFIER.fullmatch(str(item.get("service_id", ""))):
                raise CollectorError(
                    "component service_id must be a bounded identifier"
                )
            components.append(
                ComponentTarget(
                    **{
                        k: item.get(k)
                        for k in ComponentTarget.__dataclass_fields__
                        if k in item
                    }
                )
            )
        state_dir = Path(raw["state_dir"])
        if not state_dir.is_absolute():
            raise CollectorError("state_dir must be absolute")
        return cls(
            environment=raw["environment"],
            source_deployment=raw["source_deployment"],
            tenant=raw["tenant"],
            middleware_base_url=middleware["base_url"].rstrip("/"),
            middleware_token_file=middleware["token_file"],
            middleware_ca_file=middleware.get("ca_file"),
            components=components,
            service_components={
                k: list(v) for k, v in raw["service_components"].items()
            },
            version_endpoints={
                k: v for k, v in raw.get("version_endpoints", {}).items()
            },
            state_dir=str(state_dir),
            timeout_seconds=float(raw.get("timeout_seconds", 5.0)),
        )


# --- sequence state ------------------------------------------------------------------------


class SequenceState:
    """Monotonic per-resource sequence numbers so delayed posts can never overwrite newer state."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "sequence.json"
        self.values: dict[str, int] = {}

    def load(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass
        if self.path.is_file():
            self.values = {
                k: int(v)
                for k, v in json.loads(self.path.read_text(encoding="utf-8")).items()
            }

    def next(self, key: str) -> int:
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.values, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)


# --- run ------------------------------------------------------------------------------------


def collect(
    config: CollectorConfig, opener_factory: Callable[..., Any] | None = None
) -> dict[str, Reading]:
    readings: dict[str, Reading] = {}
    for target in config.components:
        try:
            headers = {}
            if target.tenant_header:
                headers["X-Scope-OrgID"] = target.tenant_header
            http = Http(
                timeout=config.timeout_seconds,
                ca_file=target.ca_file,
                token=read_token(target.token_file),
                extra_headers=headers,
                opener_factory=opener_factory,
            )
            reading = READERS[target.component](http, target.base_url.rstrip("/"))
        except CollectorError as exc:
            reading = _failed(target.component, str(exc))
        readings[target.component] = reading
    return readings


def read_versions(
    config: CollectorConfig, opener_factory: Callable[..., Any] | None = None
) -> dict[str, dict[str, Any]]:
    versions: dict[str, dict[str, Any]] = {}
    for service_id, url in config.version_endpoints.items():
        try:
            status, payload = Http(
                timeout=config.timeout_seconds, opener_factory=opener_factory
            ).json(url)
        except CollectorError as exc:
            versions[service_id] = {"status": "failed", "error": scrub(str(exc))[:200]}
            continue
        if status != 200 or not isinstance(payload, dict):
            versions[service_id] = {
                "status": "failed",
                "error": f"version endpoint {status}",
            }
            continue
        git_sha = payload.get("git_sha") or payload.get("source_sha")
        image = payload.get("image_digest")
        migration = payload.get("schema_version") or payload.get("schema_head")
        versions[service_id] = {
            "status": "observed",
            "observed_git_sha": git_sha
            if isinstance(git_sha, str) and re.fullmatch(r"[0-9a-f]{40}", git_sha)
            else None,
            "observed_image_digest": image
            if isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image)
            else None,
            "observed_migration_head": migration
            if isinstance(migration, str)
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", migration)
            else None,
        }
    return versions


def post_observations(
    config: CollectorConfig,
    readings: dict[str, Reading],
    versions: dict[str, dict[str, Any]],
    state: SequenceState,
    correlation: str,
    opener_factory: Callable[..., Any] | None = None,
) -> list[dict[str, Any]]:
    """Post one config observation per (service, component) and one observed-state per versioned service."""
    token = read_token(config.middleware_token_file)
    http = Http(
        timeout=config.timeout_seconds,
        ca_file=config.middleware_ca_file,
        token=token,
        opener_factory=opener_factory,
    )
    results: list[dict[str, Any]] = []
    observed_at = _now().isoformat()
    for service_id, components in config.service_components.items():
        for component in components:
            reading = readings.get(component)
            if reading is None:
                continue
            key = f"{config.environment}:{service_id}:{component}"
            body = {
                "kind": "config",
                "resource_id": component,
                "service_id": service_id,
                "environment": config.environment,
                "source_deployment": config.source_deployment,
                "sequence": state.next(key),
                "observed_at": observed_at,
                "data": {
                    "component": component,
                    "config_digest": reading.config_digest or "",
                    "status": "failed" if reading.status == "failed" else "observed",
                },
            }
            idem = (
                "collector-"
                + hashlib.sha256(f"{key}:{body['sequence']}".encode()).hexdigest()[:40]
            )
            status, payload = http.post_json(
                config.middleware_base_url + "/platform/v1/runtime/observations",
                body,
                {"Idempotency-Key": idem, "X-Correlation-ID": correlation},
            )
            results.append(
                {
                    "operation": "runtime.observation",
                    "service_id": service_id,
                    "component": component,
                    "http_status": status,
                    "sequence": body["sequence"],
                }
            )
            if status >= 500:
                raise CollectorError(f"middleware rejected observation with {status}")
    for service_id, version in versions.items():
        if version.get("status") != "observed":
            results.append(
                {
                    "operation": "service.observed_state",
                    "service_id": service_id,
                    "http_status": None,
                    "skipped": version.get("error"),
                }
            )
            continue
        body = {k: v for k, v in version.items() if k.startswith("observed_") and v}
        body.update(
            {
                "observed_at": observed_at,
                "source": config.source_deployment,
                "status": "observed",
            }
        )
        status, payload = http.post_json(
            config.middleware_base_url
            + f"/platform/v1/services/{urllib.parse.quote(service_id)}/monitoring-state/observations",
            body,
            {"X-Correlation-ID": correlation},
        )
        results.append(
            {
                "operation": "service.observed_state",
                "service_id": service_id,
                "http_status": status,
                "monitoring_state": (payload or {}).get("monitoring_state")
                if isinstance(payload, dict)
                else None,
            }
        )
        if status >= 500:
            raise CollectorError(f"middleware rejected observed state with {status}")
    return results


def target_records(
    config: CollectorConfig, readings: dict[str, Reading]
) -> list[dict[str, Any]]:
    """Section 10 record per Prometheus target: expected/actual endpoint, auth, scrape status, freshness, contract."""
    prometheus = readings.get("prometheus")
    expectations = {t.service_id: t for t in config.components}
    records: list[dict[str, Any]] = []
    for target in prometheus.details.get("targets", []) if prometheus else []:
        service = target.get("service")
        expected = expectations.get(service)
        age = target.get("last_scrape_age_seconds")
        records.append(
            {
                "service_id": service,
                "environment": target.get("environment"),
                "job": target.get("job"),
                "expected_endpoint": expected.expected_endpoint if expected else None,
                "actual_endpoint": target.get("scrape_url_host"),
                "endpoint_matches": (
                    expected.expected_endpoint == target.get("scrape_url_host")
                )
                if expected and expected.expected_endpoint
                else None,
                "authentication": expected.authentication if expected else "unknown",
                "scrape_status": target.get("health"),
                "last_scrape_age_seconds": age,
                "metric_freshness": "unknown"
                if age is None
                else ("fresh" if age <= STALE_AFTER.total_seconds() else "stale"),
                "contract_sha": expected.contract_sha if expected else None,
                "scrape_error": target.get("scrape_error"),
            }
        )
    return sorted(records, key=lambda r: (str(r["service_id"]), str(r["job"])))


def render_markdown(records: list[dict[str, Any]]) -> str:
    lines = [
        "| service | env | job | expected endpoint | actual endpoint | auth | scrape | age s | freshness | contract |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in records:
        lines.append(
            f"| {r['service_id']} | {r['environment']} | {r['job']} | {r['expected_endpoint'] or '-'} | {r['actual_endpoint'] or '-'} | {r['authentication']} | {r['scrape_status']} | {r['last_scrape_age_seconds'] if r['last_scrape_age_seconds'] is not None else '-'} | {r['metric_freshness']} | {(r['contract_sha'] or '-')[:12]} |"
        )
    return "\n".join(lines) + "\n"


def run(
    config: CollectorConfig,
    output_dir: Path,
    opener_factory: Callable[..., Any] | None = None,
    post: bool = True,
) -> dict[str, Any]:
    correlation = f"collector-{config.source_deployment}-{uuid.uuid4().hex[:16]}"
    started = time.monotonic()
    readings = collect(config, opener_factory)
    versions = read_versions(config, opener_factory)
    state = SequenceState(Path(config.state_dir))
    state.load()
    posted: list[dict[str, Any]] = []
    if post:
        posted = post_observations(
            config, readings, versions, state, correlation, opener_factory
        )
        state.save()
    records = target_records(config, readings)
    report = {
        "schema_version": 1,
        "environment": config.environment,
        "source_deployment": config.source_deployment,
        "correlation_id": correlation,
        "started_at": _now().isoformat(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "components": {name: reading.public() for name, reading in readings.items()},
        "versions": versions,
        "posted": posted,
        "targets": records,
        "middleware_mutated_runtime": False,
        "secret_values_recorded": False,
    }
    serialized = json.dumps(report, indent=2, sort_keys=True)
    if SECRET_SHAPED.search(serialized):
        raise CollectorError(
            "report would contain secret-shaped material; refusing to write it"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "collector-report.json").write_text(
        serialized + "\n", encoding="utf-8"
    )
    (output_dir / "target-records.md").write_text(
        render_markdown(records), encoding="utf-8"
    )
    return report
