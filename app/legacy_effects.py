"""Permanent denial authority for legacy effect paths.

``config/legacy-effect-registry.v1.json`` is the single machine-readable
registry of obsolete command, provider and business-mutation paths. Every
entry has one of two dispositions:

``DENIED``
    The path may never execute its former effect. A ``route`` entry is
    enforced by :func:`denial_dependency`, which runs before request-body
    validation, authentication and any ledger, database or provider call; a
    ``payload_shape`` entry shares its path with a live contract and is
    enforced by the handler through :func:`deny`.
``READ_ONLY_COMPAT``
    A justified read-only compatibility path. Only read methods qualify.

There is no runtime override: the registry is loaded from the repository,
validated fail-closed, and :func:`enforce_legacy_effect_registry` refuses to
build an application that mounts a ``DENIED`` route without its denial
dependency. :func:`readback` exposes the registry, its digest, the per-entry
mount/enforcement state and the denials this process observed.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, NoReturn

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from app.observability import safe_correlation_id

REGISTRY_PATH = Path(__file__).resolve().parents[1] / "config" / "legacy-effect-registry.v1.json"
REGISTRY_SCHEMA = "codestra.middleware.legacy-effect-registry.v1"
READBACK_SCHEMA = "codestra.middleware.legacy-effect-readback.v1"

DENIED = "DENIED"
READ_ONLY_COMPAT = "READ_ONLY_COMPAT"
DISPOSITIONS = frozenset({DENIED, READ_ONLY_COMPAT})
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
EFFECT_CLASSES = frozenset(
    {
        "command_submission",
        "business_mutation",
        "provider_dispatch",
        "synthetic_event_ingest",
        "false_acknowledgement",
        "callback_payload_shape",
        "read",
    }
)
DENIAL_STATUS = 410
DENIAL_CODE = "legacy_effect_denied"
# OpenAPI ``responses`` for a denied route: it has no success response.
DENIED_RESPONSES: dict[int | str, dict[str, Any]] = {
    DENIAL_STATUS: {"description": "Permanently denied legacy effect path"}
}
_ENTRY_FIELDS = frozenset(
    {"id", "method", "path", "match", "disposition", "effect_class", "owner", "successor", "reason"}
)
_POLICY_INVARIANTS = {
    "denied_disposition": DENIED,
    "read_only_disposition": READ_ONLY_COMPAT,
    "denial_status": DENIAL_STATUS,
    "denial_code": DENIAL_CODE,
    "reactivation_allowed": False,
    "runtime_override_allowed": False,
    "provider_effects_enabled": False,
}


class LegacyEffectRegistryError(RuntimeError):
    """The registry is malformed, or an application violates it."""


@dataclass(frozen=True)
class LegacyEffect:
    id: str
    method: str
    path: str
    match: str
    disposition: str
    effect_class: str
    owner: str
    successor: str | None
    reason: str

    @property
    def denied(self) -> bool:
        return self.disposition == DENIED

    @property
    def route_scoped(self) -> bool:
        return self.match == "route"

    @property
    def successor_path(self) -> str | None:
        if not self.successor:
            return None
        return self.successor.split(" ", 1)[-1]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "match": self.match,
            "disposition": self.disposition,
            "effect_class": self.effect_class,
            "owner": self.owner,
            "successor": self.successor,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class LegacyEffectRegistry:
    registry_id: str
    authority: str
    sha256: str
    policy: dict[str, Any]
    entries: tuple[LegacyEffect, ...]

    def get(self, effect_id: str) -> LegacyEffect | None:
        return next((entry for entry in self.entries if entry.id == effect_id), None)

    def require(self, effect_id: str) -> LegacyEffect:
        entry = self.get(effect_id)
        if entry is None:
            raise LegacyEffectRegistryError(f"unknown legacy effect {effect_id}")
        return entry

    def route_entry(self, method: str, path: str) -> LegacyEffect | None:
        return next(
            (
                entry
                for entry in self.entries
                if entry.route_scoped and entry.method == method and entry.path == path
            ),
            None,
        )


def _fail(message: str) -> NoReturn:
    raise LegacyEffectRegistryError(f"legacy effect registry: {message}")


def _entry(raw: Any, index: int) -> LegacyEffect:
    if not isinstance(raw, dict) or set(raw) != _ENTRY_FIELDS:
        _fail(f"entry {index} must declare exactly {sorted(_ENTRY_FIELDS)}")
    for field in _ENTRY_FIELDS - {"successor"}:
        if not isinstance(raw[field], str) or not raw[field]:
            _fail(f"entry {index} field {field} must be a non-empty string")
    if raw["successor"] is not None and (not isinstance(raw["successor"], str) or " /" not in raw["successor"]):
        _fail(f"entry {raw['id']} successor must be null or 'METHOD /path'")
    entry = LegacyEffect(**raw)
    if not entry.id.startswith("LE-"):
        _fail(f"entry {entry.id} id must start with LE-")
    if not entry.path.startswith("/"):
        _fail(f"entry {entry.id} path must be absolute")
    if entry.disposition not in DISPOSITIONS:
        _fail(f"entry {entry.id} disposition {entry.disposition} is not one of {sorted(DISPOSITIONS)}")
    if entry.effect_class not in EFFECT_CLASSES:
        _fail(f"entry {entry.id} effect_class {entry.effect_class} is unknown")
    if entry.match != "route" and not entry.match.startswith("payload_shape:"):
        _fail(f"entry {entry.id} match must be 'route' or 'payload_shape:<name>'")
    if entry.disposition == READ_ONLY_COMPAT:
        if entry.method not in READ_METHODS or entry.effect_class != "read" or not entry.route_scoped:
            _fail(f"entry {entry.id} READ_ONLY_COMPAT must be a route-scoped read method")
    else:
        if entry.method not in MUTATION_METHODS or entry.effect_class == "read":
            _fail(f"entry {entry.id} DENIED must name a mutation method and an effect class")
    return entry


def load_registry(path: Path = REGISTRY_PATH) -> LegacyEffectRegistry:
    """Load and validate the registry; any defect raises (fail closed)."""
    raw_bytes = path.read_bytes()
    try:
        document = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        _fail(f"not valid JSON: {exc}")
    if not isinstance(document, dict) or document.get("schema") != REGISTRY_SCHEMA:
        _fail(f"schema must be {REGISTRY_SCHEMA}")
    policy = document.get("policy")
    if not isinstance(policy, dict):
        _fail("policy must be an object")
    for key, expected in _POLICY_INVARIANTS.items():
        if policy.get(key) != expected:
            _fail(f"policy.{key} must be {expected!r}")
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        _fail("entries must be a non-empty list")
    entries = tuple(_entry(raw, index) for index, raw in enumerate(raw_entries))
    ids = Counter(entry.id for entry in entries)
    duplicates = sorted(effect_id for effect_id, count in ids.items() if count > 1)
    if duplicates:
        _fail(f"duplicate ids {duplicates}")
    keys = Counter((entry.method, entry.path, entry.match) for entry in entries)
    clashes = sorted(f"{m} {p} ({x})" for (m, p, x), count in keys.items() if count > 1)
    if clashes:
        _fail(f"duplicate operations {clashes}")
    return LegacyEffectRegistry(
        registry_id=str(document.get("registry_id", "")),
        authority=str(document.get("authority", "")),
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        policy=policy,
        entries=entries,
    )


@lru_cache(maxsize=1)
def registry() -> LegacyEffectRegistry:
    """The process-wide registry, loaded once from the repository."""
    return load_registry()


# --- denial -----------------------------------------------------------------------

_denials: Counter[str] = Counter()
_denials_lock = threading.Lock()


def denials_observed() -> dict[str, int]:
    with _denials_lock:
        return dict(_denials)


class LegacyEffectDenied(HTTPException):
    """A registered legacy effect path was invoked. Never retryable.

    Subclasses ``HTTPException`` so that even an application without the
    dedicated handler answers 410 instead of executing anything.
    """

    code = DENIAL_CODE
    retryable = False

    def __init__(self, effect: LegacyEffect) -> None:
        self.effect = effect
        super().__init__(DENIAL_STATUS, f"legacy effect path is permanently denied: {effect.id}")


def deny(effect_id: str) -> NoReturn:
    """Record and raise the denial of a ``DENIED`` registry entry."""
    entry = registry().require(effect_id)
    if not entry.denied:
        raise LegacyEffectRegistryError(f"{effect_id} is not a DENIED legacy effect")
    with _denials_lock:
        _denials[effect_id] += 1
    raise LegacyEffectDenied(entry)


def denial_dependency(effect_id: str) -> Callable[[], Any]:
    """A route dependency that denies ``effect_id`` before the handler runs.

    Resolved when the router is declared, so an unknown or non-``DENIED`` id
    fails at import time rather than at request time.
    """
    entry = registry().require(effect_id)
    if not (entry.denied and entry.route_scoped):
        raise LegacyEffectRegistryError(f"{effect_id} is not a route-scoped DENIED legacy effect")

    async def deny_legacy_effect() -> NoReturn:
        deny(effect_id)

    deny_legacy_effect.__legacy_effect_id__ = effect_id  # type: ignore[attr-defined]
    return deny_legacy_effect


def install_legacy_effect_handler(app: FastAPI) -> None:
    """Render a denial in the canonical error envelope with successor metadata."""

    async def legacy_effect_denied(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, LegacyEffectDenied)
        effect = exc.effect
        correlation_id = (
            getattr(request.state, "correlation_id", None)
            or safe_correlation_id(request.headers.get("X-Correlation-ID"))
            or "unassigned"
        )
        headers = {"X-Correlation-ID": correlation_id, "Deprecation": "true"}
        if effect.successor_path:
            headers["Link"] = f'<{effect.successor_path}>; rel="successor-version"'
        return JSONResponse(
            status_code=DENIAL_STATUS,
            content={
                "error": {
                    "code": DENIAL_CODE,
                    "message": str(exc.detail),
                    "correlation_id": correlation_id,
                    "retryable": False,
                    "details": {
                        "legacy_effect_id": effect.id,
                        "effect_class": effect.effect_class,
                        "disposition": effect.disposition,
                        "successor": effect.successor,
                    },
                }
            },
            headers=headers,
        )

    app.add_exception_handler(LegacyEffectDenied, legacy_effect_denied)


# --- enforcement ------------------------------------------------------------------


def _api_routes(app: FastAPI) -> Iterator[tuple[str, APIRoute]]:
    def walk(routes, prefix: str = "") -> Iterator[tuple[str, APIRoute]]:
        for route in routes:
            original = getattr(route, "original_router", None)
            if original is not None:
                context = getattr(route, "include_context", None)
                yield from walk(original.routes, prefix + (getattr(context, "prefix", "") or ""))
                continue
            if isinstance(route, APIRoute):
                yield prefix + route.path_format, route

    yield from walk(app.routes)


def _denial_ids(route: APIRoute) -> set[str]:
    calls = [dependency.dependency for dependency in route.dependencies]
    calls.extend(sub.call for sub in route.dependant.dependencies)
    return {
        effect_id
        for call in calls
        if (effect_id := getattr(call, "__legacy_effect_id__", None)) is not None
    }


def _handler_enforces(route: APIRoute, effect_id: str) -> bool:
    try:
        source = inspect.getsource(route.endpoint)
    except (OSError, TypeError):
        return False
    return f'deny("{effect_id}")' in source


def enforce_legacy_effect_registry(app: FastAPI) -> dict[str, dict[str, bool]]:
    """Refuse an application that mounts a ``DENIED`` path it does not deny.

    Returns ``{effect_id: {"mounted": bool, "enforced": bool}}`` for readback.
    """
    active = registry()
    state = {entry.id: {"mounted": False, "enforced": False} for entry in active.entries}
    violations: list[str] = []
    for path, route in _api_routes(app):
        for method in sorted(route.methods or ()):
            for entry in active.entries:
                if entry.method != method or entry.path != path:
                    continue
                state[entry.id]["mounted"] = True
                if not entry.denied:
                    state[entry.id]["enforced"] = True
                    continue
                if entry.route_scoped:
                    enforced = entry.id in _denial_ids(route)
                else:
                    enforced = _handler_enforces(route, entry.id)
                state[entry.id]["enforced"] = enforced
                if not enforced:
                    violations.append(f"{entry.id} {method} {path}")
            # A denial dependency must match the operation it is mounted on.
            for effect_id in _denial_ids(route):
                entry = active.get(effect_id)
                if entry is None or entry.method not in route.methods or entry.path != path:
                    violations.append(f"{effect_id} mounted on {method} {path}")
    if violations:
        raise LegacyEffectRegistryError(
            "legacy effect paths mounted without denial: " + ", ".join(sorted(set(violations)))
        )
    app.state.legacy_effects = state
    return state


def readback(app: FastAPI) -> dict[str, Any]:
    """The registry, its digest, and this application's enforcement state."""
    active = registry()
    state: dict[str, dict[str, bool]] = getattr(app.state, "legacy_effects", None) or {}
    observed = denials_observed()
    profile = getattr(app.state, "profile", None)
    entries = [
        {
            **entry.as_dict(),
            "mounted": state.get(entry.id, {}).get("mounted", False),
            "enforced": state.get(entry.id, {}).get("enforced", False),
            "denials_observed": observed.get(entry.id, 0),
        }
        for entry in active.entries
    ]
    return {
        "schema": READBACK_SCHEMA,
        "registry": {
            "schema": REGISTRY_SCHEMA,
            "registry_id": active.registry_id,
            "authority": active.authority,
            "sha256": active.sha256,
            "entries": len(active.entries),
            "denied": sum(1 for entry in active.entries if entry.denied),
            "read_only_compat": sum(1 for entry in active.entries if not entry.denied),
        },
        "policy": {key: active.policy[key] for key in _POLICY_INVARIANTS},
        "profile": getattr(profile, "value", profile),
        "enforcement_verified": bool(state)
        and all(item["enforced"] for item in state.values() if item["mounted"]),
        "provider_effects_enabled": False,
        "entries": entries,
    }
