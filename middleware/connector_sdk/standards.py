"""Standards helpers used by the Connector SDK.

Profiles:
- Semantic Versioning 2.0.0 precedence.
- W3C Trace Context ``traceparent`` version 00.
- RFC 3339 timestamps for CloudEvents.
- CloudEvents 1.0 structured event projection helpers.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from functools import total_ordering
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from .errors import StandardsValidationError

_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_TRACEPARENT_RE = re.compile(
    r"^00-"
    r"((?!0{32})[0-9a-f]{32})-"
    r"((?!0{16})[0-9a-f]{16})-"
    r"([0-9a-f]{2})$"
)
_RFC3339_RE = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<hour>[01][0-9]|2[0-3]):"
    r"(?P<minute>[0-5][0-9]):"
    r"(?P<second>[0-5][0-9])"
    r"(?P<fraction>\.[0-9]+)?"
    r"(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
_TRACESTATE_KEY = re.compile(
    r"^(?:[a-z0-9][a-z0-9_*/-]{0,255}|"
    r"[a-z0-9][a-z0-9_*/-]{0,240}@[a-z0-9][a-z0-9_*/-]{0,13})$"
)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def deep_freeze(value: Any) -> Any:
    """Recursively freeze JSON-like values to prevent post-validation mutation."""
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): deep_freeze(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze(child) for child in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(deep_freeze(child) for child in value)
    return value


def deep_thaw(value: Any) -> Any:
    """Convert recursively frozen JSON-like values to serializable values."""
    if isinstance(value, Mapping):
        return {str(key): deep_thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [deep_thaw(child) for child in value]
    if isinstance(value, frozenset):
        return sorted(deep_thaw(child) for child in value)
    return value


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


SECRET_KEY_NAMES = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "providertoken",
        "refreshtoken",
        "secret",
        "secretvalue",
        "session",
        "sessionid",
        "token",
    }
)


def is_secret_key_name(value: str) -> bool:
    normalized = normalized_key(value)
    if normalized.endswith("reference") or normalized.endswith("references"):
        return False
    return normalized in SECRET_KEY_NAMES


def forbidden_paths(
    value: Any,
    forbidden_names: set[str] | frozenset[str],
    path: str = "$",
) -> tuple[str, ...]:
    normalized_forbidden = {normalized_key(name) for name in forbidden_names}
    matches: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            normalized = normalized_key(str(key))
            if normalized in normalized_forbidden or is_secret_key_name(str(key)):
                matches.append(child_path)
            matches.extend(forbidden_paths(child, normalized_forbidden, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            matches.extend(
                forbidden_paths(child, normalized_forbidden, f"{path}[{index}]")
            )
    return tuple(matches)


@total_ordering
@dataclass(frozen=True, slots=True)
class SemanticVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> "SemanticVersion":
        match = _SEMVER_RE.fullmatch(value)
        if match is None:
            raise StandardsValidationError(f"invalid Semantic Version: {value!r}")
        prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
        build = tuple(match.group(5).split(".")) if match.group(5) else ()
        return cls(
            major=int(match.group(1)),
            minor=int(match.group(2)),
            patch=int(match.group(3)),
            prerelease=prerelease,
            build=build,
        )

    def _compare_prerelease(self, other: "SemanticVersion") -> int:
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return -1 if int(left) < int(right) else 1
            if left_numeric != right_numeric:
                return -1 if left_numeric else 1
            return -1 if left < right else 1
        if len(self.prerelease) == len(other.prerelease):
            return 0
        return -1 if len(self.prerelease) < len(other.prerelease) else 1

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        core_left = (self.major, self.minor, self.patch)
        core_right = (other.major, other.minor, other.patch)
        if core_left != core_right:
            return core_left < core_right
        return self._compare_prerelease(other) < 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return False
        return (
            self.major,
            self.minor,
            self.patch,
            self.prerelease,
        ) == (
            other.major,
            other.minor,
            other.patch,
            other.prerelease,
        )


def validate_traceparent(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _TRACEPARENT_RE.fullmatch(value) is None:
        raise StandardsValidationError("traceparent is not valid W3C version 00")
    return value


def validate_tracestate(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 512 or _CONTROL_CHARS.search(value):
        raise StandardsValidationError("tracestate is invalid")
    members = [member.strip() for member in value.split(",")]
    if not 1 <= len(members) <= 32:
        raise StandardsValidationError("tracestate must contain 1 to 32 members")
    seen: set[str] = set()
    for member in members:
        if "=" not in member:
            raise StandardsValidationError("tracestate member is missing '='")
        key, member_value = member.split("=", 1)
        if _TRACESTATE_KEY.fullmatch(key) is None:
            raise StandardsValidationError("tracestate key is invalid")
        if key in seen:
            raise StandardsValidationError("tracestate contains a duplicate key")
        if (
            not member_value
            or len(member_value) > 256
            or member_value.startswith(" ")
            or member_value.endswith(" ")
            or "," in member_value
            or "=" in member_value
            or _CONTROL_CHARS.search(member_value)
        ):
            raise StandardsValidationError("tracestate value is invalid")
        seen.add(key)
    return value


def validate_rfc3339(value: str) -> str:
    if not isinstance(value, str) or _RFC3339_RE.fullmatch(value) is None:
        raise StandardsValidationError("timestamp is not RFC 3339")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise StandardsValidationError("timestamp is not RFC 3339") from error
    if parsed.tzinfo is None:
        raise StandardsValidationError("timestamp must include a UTC offset")
    return value


def validate_uri_reference(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or _CONTROL_CHARS.search(value):
        raise StandardsValidationError(f"{label} must be a non-empty URI reference")
    parsed = urlsplit(value)
    if not parsed.scheme:
        raise StandardsValidationError(f"{label} must include a URI scheme")
    return value
