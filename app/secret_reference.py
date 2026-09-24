"""Secret references: pointers to OpenBao secrets that never carry a value.

The contract is owned by ``appolon1908-hue/Codestra-OpenBao``
(``contracts/secret-reference.v1.schema.json``) and vendored byte-for-byte under
``contracts/secrets/`` with a canonical sha256 pin. Middleware may store and
return a reference together with rotation, lease and reconciliation metadata;
it must never store, resolve or return the secret value.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "secrets" / "secret-reference.v1.schema.json"
PIN_PATH = ROOT / "contracts" / "secrets" / "secret-reference.v1.schema.sha256"

Environment = Literal["development", "test", "staging", "production"]
SECRET_REF = re.compile(
    r"^codestra/(development|test|staging|production)/[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)+$"
)
SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
IDENTITY = re.compile(r"^[a-z][a-z0-9-]+$")
LEASE_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_SHAPED = re.compile(
    r"(hvs\.[A-Za-z0-9_-]{20,}|hvb\.[A-Za-z0-9_-]{20,}|\bs\.[A-Za-z0-9]{24,}\b|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,})"
)
URI_PREFIX = "openbao://"


class SecretReferenceError(ValueError):
    """A value-bearing, cross-environment or malformed secret reference."""


def canonical_digest(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@lru_cache(maxsize=1)
def schema() -> dict[str, Any]:
    document = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    pinned = PIN_PATH.read_text(encoding="utf-8").strip()
    if canonical_digest(document) != pinned:
        raise SecretReferenceError(
            "vendored secret-reference schema does not match its pin"
        )
    return document


def forbidden_keys() -> frozenset[str]:
    return frozenset(schema()["x-codestra-forbidden-keys"])


def secret_classes() -> tuple[str, ...]:
    return tuple(schema()["properties"]["secret_class"]["enum"])


def reject_secret_material(value: Any, trail: str = "secret_reference") -> None:
    """Fail closed on any forbidden key or secret-shaped string at any depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in forbidden_keys() or lowered.endswith(
                ("_password", "_token", "_secret")
            ):
                raise SecretReferenceError(
                    f"{trail}.{key}: secret material is never stored"
                )
            reject_secret_material(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_secret_material(item, f"{trail}[{index}]")
    elif isinstance(value, str) and SECRET_SHAPED.search(value):
        raise SecretReferenceError(f"{trail}: secret-shaped value is never stored")


class LeaseMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_id_hash: str | None = Field(default=None, pattern=LEASE_HASH.pattern)
    ttl_seconds: int | None = Field(default=None, ge=1)
    renewable: bool | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None


class SecretReference(BaseModel):
    """The shared v1 secret-reference object plus Middleware-held metadata."""

    model_config = ConfigDict(extra="forbid")

    provider: Literal["openbao"] = "openbao"
    environment: Environment
    service_id: str = Field(pattern=SERVICE_ID.pattern)
    secret_ref: str
    secret_class: str
    version: int | None = Field(default=None, ge=1)
    reference_uri: str | None = None
    workload_identity: str | None = Field(default=None, pattern=IDENTITY.pattern)
    secret_owner: str | None = Field(default=None, pattern=IDENTITY.pattern)
    consumer_repository: str | None = Field(
        default=None, pattern=r"^appolon1908-hue/[A-Za-z0-9._-]+$"
    )
    rotation_status: Literal[
        "unknown", "current", "rotation_due", "rotating", "revoked"
    ] = "unknown"
    lease_metadata: LeaseMetadata | None = None
    last_reconciled_at: datetime | None = None
    last_reconciliation_status: Literal[
        "unknown", "readable", "denied", "missing", "openbao_unavailable"
    ] = "unknown"

    @field_validator("secret_class")
    @classmethod
    def class_is_governed(cls, value: str) -> str:
        if value not in secret_classes():
            raise ValueError(f"secret_class must be one of {secret_classes()}")
        return value

    @field_validator("secret_ref")
    @classmethod
    def ref_is_safe(cls, value: str) -> str:
        if (
            not SECRET_REF.fullmatch(value)
            or "*" in value
            or ".." in value
            or "//" in value
        ):
            raise ValueError(
                "secret_ref must be codestra/<environment>/<workload>/<name> without wildcards or traversal"
            )
        return value

    @model_validator(mode="after")
    def environment_and_uri_agree(self) -> "SecretReference":
        if not self.secret_ref.startswith(f"codestra/{self.environment}/"):
            raise ValueError("secret_ref must lie inside its own environment")
        expected = URI_PREFIX + self.secret_ref
        if self.reference_uri is None:
            self.reference_uri = expected
        elif self.reference_uri != expected:
            raise ValueError("reference_uri must equal openbao:// + secret_ref")
        return self

    @model_validator(mode="before")
    @classmethod
    def never_a_value(cls, data: Any) -> Any:
        if isinstance(data, dict):
            reject_secret_material(data)
        return data

    def public(self) -> dict[str, Any]:
        """The exact object Middleware may return: the reference and its metadata, never a value."""
        return self.model_dump(mode="json", exclude_none=True)


def parse_references(items: Any) -> list[SecretReference]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise SecretReferenceError("secret_references must be a list")
    if len(items) > 64:
        raise SecretReferenceError("at most 64 secret references per service")
    parsed = [SecretReference.model_validate(item) for item in items]
    seen: set[tuple[str, str]] = set()
    for reference in parsed:
        key = (reference.environment, reference.secret_ref)
        if key in seen:
            raise SecretReferenceError(
                f"duplicate secret reference {reference.secret_ref}"
            )
        seen.add(key)
    return parsed


def references_for_environments(
    references: list[SecretReference], environments: list[str]
) -> None:
    """A service may only reference secrets of environments it is declared in."""
    for reference in references:
        if reference.environment not in environments:
            raise SecretReferenceError(
                f"{reference.secret_ref} belongs to {reference.environment}, which the service does not declare"
            )
