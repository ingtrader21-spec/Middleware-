"""Canonical PostgreSQL connection/TLS authority for Middleware.

Every long-running runtime process and protected migration path must interpret
DATABASE_URL through this module. The native libpq-style DSN is passed to
asyncpg unchanged so sslmode/sslrootcert/sslcert/sslkey are parsed by the
driver consistently; SQLAlchemy receives only a credential-free dialect URL.

DB-04/DB-05 own certificate issuance and mandatory client-certificate policy.
This module already validates explicit certificate paths when supplied and
requires verify-full in staging/production, without silently downgrading TLS.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from urllib.parse import parse_qsl, urlsplit


class DatabaseConnectionError(ValueError):
    """Credential-free database connection policy failure."""


_TARGET_OVERRIDE_QUERY_KEYS = frozenset(
    {
        "host",
        "hostaddr",
        "port",
        "database",
        "dbname",
        "user",
        "password",
        "dsn",
        "server_settings",
    }
)
_TLS_PATH_KEYS = ("sslrootcert", "sslcert", "sslkey")
# Staging/production accept only the TLS keys the runtime profile lock allows,
# so the migration path (which has no profile lock) cannot inject startup GUCs.
_SECURE_QUERY_KEYS = frozenset({"sslmode", *_TLS_PATH_KEYS})
_SAFE_APPLICATION_NAME = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")


@dataclass(frozen=True)
class DatabaseConnectionAuthority:
    """One parsed connection contract shared by runtime and migrations."""

    native_dsn: str
    sqlalchemy_url: str
    connect_args: dict[str, object]
    sslmode: str | None
    tls_paths: dict[str, Path]


def _native_postgres_dsn(value: str) -> tuple[str, object]:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise DatabaseConnectionError("DATABASE_URL is malformed") from exc
    if parsed.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise DatabaseConnectionError("DATABASE_URL must use PostgreSQL")
    if not parsed.hostname or not parsed.path.strip("/") or parsed.fragment:
        raise DatabaseConnectionError(
            "DATABASE_URL requires an explicit host and database"
        )
    suffix = value.split(":", 1)[1]
    return "postgresql:" + suffix, parsed


def _query_values(
    parsed: object, *, secure_environment: bool
) -> dict[str, str]:
    query = getattr(parsed, "query", "")
    values: dict[str, str] = {}
    for raw_key, raw_value in parse_qsl(query, keep_blank_values=True):
        key = raw_key.lower()
        # asyncpg matches DSN keys case-sensitively: SSLMODE=verify-full would
        # pass this policy yet leave the driver on its default sslmode=prefer.
        if raw_key != key:
            raise DatabaseConnectionError(
                "DATABASE_URL query parameter names must be lowercase"
            )
        if key in values:
            raise DatabaseConnectionError(
                f"DATABASE_URL query parameter is duplicated: {key}"
            )
        if key in _TARGET_OVERRIDE_QUERY_KEYS:
            raise DatabaseConnectionError(
                "DATABASE_URL query must not override its target or identity"
            )
        if secure_environment and key not in _SECURE_QUERY_KEYS:
            raise DatabaseConnectionError(
                f"staging/production DATABASE_URL query parameter is not allowed: {key}"
            )
        values[key] = raw_value
    return values


def _is_absolute_tls_path(value: str) -> bool:
    """Validate DSN path syntax independently from the tooling host OS."""

    return PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()


def _validate_tls_paths(
    query: dict[str, str], *, validate_files: bool
) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for key in _TLS_PATH_KEYS:
        raw = query.get(key, "")
        if not raw:
            continue
        # parse_qsl already percent-decoded once, exactly as asyncpg does;
        # decoding again would validate a different file than the driver opens.
        if not _is_absolute_tls_path(raw):
            raise DatabaseConnectionError(f"{key} must be an absolute path")
        paths[key] = Path(raw)

    if bool(paths.get("sslcert")) != bool(paths.get("sslkey")):
        raise DatabaseConnectionError("sslcert and sslkey must be configured together")

    if not validate_files:
        return paths

    for key, path in paths.items():
        if not path.is_file() or not os.access(path, os.R_OK):
            raise DatabaseConnectionError(f"{key} file is unavailable")
        if key == "sslkey" and path.stat().st_mode & 0o077:
            raise DatabaseConnectionError(
                "sslkey permissions must deny group/other access"
            )
    return paths


def build_database_connection_authority(
    value: str,
    *,
    command_timeout_seconds: int,
    application_name: str,
    search_path: str = "public",
    secure_environment: bool = False,
    validate_tls_files: bool = True,
) -> DatabaseConnectionAuthority:
    """Build the one SQLAlchemy/asyncpg connection contract.

    value remains the authoritative DSN. We never translate TLS options into
    asyncpg keyword arguments because doing so can change semantics.
    """

    if not _SAFE_APPLICATION_NAME.fullmatch(application_name):
        raise DatabaseConnectionError("database application_name is invalid")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_, ]{0,255}", search_path):
        raise DatabaseConnectionError("database search_path is invalid")
    if command_timeout_seconds < 1:
        raise DatabaseConnectionError("database command timeout must be positive")

    native_dsn, parsed = _native_postgres_dsn(value)
    query = _query_values(parsed, secure_environment=secure_environment)
    sslmode = query.get("sslmode") or None
    if secure_environment and sslmode != "verify-full":
        raise DatabaseConnectionError(
            "staging/production DATABASE_URL must use sslmode=verify-full"
        )
    tls_paths = _validate_tls_paths(query, validate_files=validate_tls_files)

    server_settings = {
        "search_path": search_path,
        "application_name": application_name,
    }
    connect_args: dict[str, object] = {
        "dsn": native_dsn,
        "command_timeout": command_timeout_seconds,
        "server_settings": server_settings,
    }
    return DatabaseConnectionAuthority(
        native_dsn=native_dsn,
        sqlalchemy_url="postgresql+asyncpg://",
        connect_args=connect_args,
        sslmode=sslmode,
        tls_paths=tls_paths,
    )


def asyncpg_connection_kwargs(
    authority: DatabaseConnectionAuthority,
) -> tuple[str, dict[str, object]]:
    """Return native DSN plus non-TLS asyncpg kwargs for direct connections."""

    kwargs = dict(authority.connect_args)
    dsn = str(kwargs.pop("dsn"))
    return dsn, kwargs
