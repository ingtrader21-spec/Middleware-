"""Canonical PostgreSQL DSN/TLS connection authority.

All primary Middleware PostgreSQL consumers use this module to interpret the
same DATABASE_URL. The authority preserves the native PostgreSQL DSN (including
sslmode/certificate query parameters) and passes it to asyncpg through the
dsn keyword. SQLAlchemy uses a credential-free dialect URL plus the same
native DSN in connect_args so ORM runtime and migration verification cannot
silently disagree about TLS.

Production is fail closed: sslmode=verify-full plus explicit readable CA,
client certificate and private key files are required. Development/test remain
usable with local PostgreSQL; staging policy is tightened by DB-05 rather than
implicitly downgraded here.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from urllib.parse import parse_qsl, urlsplit


class DatabaseConnectionError(ValueError):
    """Credential-free database connection policy failure."""


_TARGET_OVERRIDE_KEYS = frozenset(
    {"host", "hostaddr", "port", "database", "dbname", "user", "password", "dsn", "server_settings"}
)
_UNSAFE_PRODUCTION_SSLMODES = frozenset({"disable", "allow", "prefer", "require", "verify-ca"})
_CERT_QUERY_KEYS = ("sslrootcert", "sslcert", "sslkey")


def _native_postgres_dsn(database_url: str) -> str:
    if database_url.startswith("postgresql+asyncpg://"):
        return "postgresql://" + database_url.removeprefix("postgresql+asyncpg://")
    if database_url.startswith("postgres://"):
        return "postgresql://" + database_url.removeprefix("postgres://")
    return database_url


def _validate_file(value: str, *, label: str, private_key: bool = False) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise DatabaseConnectionError(f"{label} must use an absolute path")
    if not path.is_file() or not os.access(path, os.R_OK):
        raise DatabaseConnectionError(f"{label} is unavailable or unreadable")
    if private_key and os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise DatabaseConnectionError("database client private key permissions are too broad")
    return str(path)


@dataclass(frozen=True)
class DatabaseConnectionAuthority:
    """Validated, driver-neutral representation of one PostgreSQL target."""

    native_dsn: str
    hostname: str
    database: str
    environment: str
    sslmode: str | None
    application_name: str
    search_path: str
    command_timeout: float

    @property
    def sqlalchemy_url(self) -> str:
        return "postgresql+asyncpg://"

    @property
    def connect_args(self) -> dict[str, object]:
        return {
            "dsn": self.native_dsn,
            "command_timeout": self.command_timeout,
            "server_settings": {
                "search_path": self.search_path,
                "application_name": self.application_name,
            },
        }

    def asyncpg_pool_kwargs(self, *, min_size: int, max_size: int) -> dict[str, object]:
        if min_size < 0 or max_size < 1 or min_size > max_size:
            raise DatabaseConnectionError("invalid PostgreSQL pool bounds")
        return {**self.connect_args, "min_size": min_size, "max_size": max_size}

    @property
    def asyncpg_connect_kwargs(self) -> dict[str, object]:
        return dict(self.connect_args)


def database_connection_authority(
    database_url: str,
    *,
    environment: str | None = None,
    application_name: str,
    command_timeout: float = 30,
    search_path: str = "public",
) -> DatabaseConnectionAuthority:
    """Validate one DSN and return the only supported connection interpretation."""

    if not database_url:
        raise DatabaseConnectionError("DATABASE_URL is required")
    parsed = urlsplit(database_url)
    if parsed.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise DatabaseConnectionError("DATABASE_URL must use PostgreSQL")
    if not parsed.hostname or not parsed.path.strip("/") or parsed.fragment:
        raise DatabaseConnectionError("DATABASE_URL requires an explicit host and database")
    resolved_environment = (environment or os.environ.get("APP_ENV") or "development").lower()
    if resolved_environment not in {"development", "test", "staging", "production"}:
        raise DatabaseConnectionError("unsupported application environment")
    if parsed.username is None and resolved_environment in {"staging", "production"}:
        raise DatabaseConnectionError(
            "staging/production DATABASE_URL requires an explicit PostgreSQL user"
        )

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query: dict[str, str] = {}
    for key, value in query_pairs:
        lowered = key.lower()
        if lowered in _TARGET_OVERRIDE_KEYS:
            raise DatabaseConnectionError("DATABASE_URL query must not override connection identity")
        if lowered in query and query[lowered] != value:
            raise DatabaseConnectionError("DATABASE_URL has conflicting duplicate options")
        query[lowered] = value

    if not application_name or any(ch.isspace() for ch in application_name):
        raise DatabaseConnectionError("database application_name must be a non-empty token")
    if search_path != "public":
        raise DatabaseConnectionError("database search_path must be public")
    if command_timeout <= 0:
        raise DatabaseConnectionError("database command timeout must be positive")

    sslmode = query.get("sslmode")
    for key, label in (
        ("sslrootcert", "database CA certificate"),
        ("sslcert", "database client certificate"),
        ("sslkey", "database client private key"),
    ):
        value = query.get(key)
        if value:
            _validate_file(value, label=label, private_key=key == "sslkey")

    supplied_client_material = [bool(query.get(key)) for key in _CERT_QUERY_KEYS]
    if any(supplied_client_material) and not all(supplied_client_material):
        raise DatabaseConnectionError(
            "database TLS certificate configuration requires CA, client certificate and private key"
        )

    if resolved_environment == "production":
        if sslmode in _UNSAFE_PRODUCTION_SSLMODES or sslmode != "verify-full":
            raise DatabaseConnectionError("production PostgreSQL requires sslmode=verify-full")
        if not all(query.get(key) for key in _CERT_QUERY_KEYS):
            raise DatabaseConnectionError(
                "production PostgreSQL requires CA, client certificate and private key"
            )

    return DatabaseConnectionAuthority(
        native_dsn=_native_postgres_dsn(database_url),
        hostname=parsed.hostname,
        database=parsed.path.strip("/"),
        environment=resolved_environment,
        sslmode=sslmode,
        application_name=application_name,
        search_path=search_path,
        command_timeout=float(command_timeout),
    )


def native_postgres_dsn(database_url: str) -> str:
    """Compatibility helper backed by the canonical authority scheme rule."""

    parsed = urlsplit(database_url)
    if parsed.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise DatabaseConnectionError("DATABASE_URL must use PostgreSQL")
    return _native_postgres_dsn(database_url)
