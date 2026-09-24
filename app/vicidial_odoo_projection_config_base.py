from __future__ import annotations

import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Self
from urllib.parse import urlsplit, urlunsplit

from .vicidial_odoo_projection_errors import ProjectionConfigurationError

_TRUE = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSE = frozenset({"", "0", "false", "no", "off", "disabled"})
_SAFE_DURABLE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
_ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_PROFILES = _ROOT / "config" / "runtime-profiles.v1.json"


def parse_bool(value: str | None, *, name: str, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise ProjectionConfigurationError(f"{name} must be an explicit boolean")


def _absolute_like(path: str | Path) -> bool:
    raw = str(path).replace("\\", "/")
    return raw.startswith("/") or Path(raw).is_absolute()


def _read_private_text(path: Path, *, minimum_bytes: int = 1) -> str:
    if not _absolute_like(path):
        raise ProjectionConfigurationError("secret paths must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProjectionConfigurationError(
            f"protected file cannot be opened: {path}"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ProjectionConfigurationError(
                "protected path is not a regular file"
            )
        if info.st_mode & 0o077:
            raise ProjectionConfigurationError(
                "protected file must be mode 0600 or stricter"
            )
        raw = os.read(descriptor, 65537)
        if len(raw) > 65536:
            raise ProjectionConfigurationError(
                "protected file exceeds 65536 bytes"
            )
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ProjectionConfigurationError(
            "protected file must contain UTF-8 text"
        ) from exc
    if len(value.encode("utf-8")) < minimum_bytes:
        raise ProjectionConfigurationError("protected value is too short")
    return value


def _https_origin(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ProjectionConfigurationError(
            "Odoo base URL must be one HTTPS origin without credentials or path"
        )
    return urlunsplit(("https", parsed.netloc, "", "", ""))


def _runtime_profile(profile_id: str) -> Mapping[str, Any]:
    try:
        document = json.loads(_RUNTIME_PROFILES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProjectionConfigurationError(
            "runtime profile registry cannot be loaded"
        ) from exc
    profiles = document.get("profiles") if isinstance(document, dict) else None
    if not isinstance(profiles, list):
        raise ProjectionConfigurationError(
            "runtime profile registry is malformed"
        )
    matches = [
        profile
        for profile in profiles
        if isinstance(profile, dict) and profile.get("profile_id") == profile_id
    ]
    if len(matches) != 1:
        raise ProjectionConfigurationError(
            "RUNTIME_PROFILE_ID is not registered exactly once"
        )
    return matches[0]


def _validate_nats_profile(
    *,
    nats_url: str,
    nats_stream: str,
    nats_subject_prefix: str,
    profile: Mapping[str, Any],
) -> None:
    nats = profile.get("nats")
    if not isinstance(nats, dict):
        raise ProjectionConfigurationError(
            "selected runtime profile has no NATS authority"
        )
    expected_host = nats.get("host")
    expected_port = nats.get("port")
    expected_stream = nats.get("stream")
    expected_prefix = nats.get("subject_prefix")
    if (
        not isinstance(expected_host, str)
        or type(expected_port) is not int
        or not isinstance(expected_stream, str)
        or not isinstance(expected_prefix, str)
    ):
        raise ProjectionConfigurationError(
            "selected runtime profile has malformed NATS authority"
        )

    parsed = urlsplit(nats_url)
    try:
        observed_port = parsed.port
    except ValueError as exc:
        raise ProjectionConfigurationError("NATS URL port is invalid") from exc
    if (
        parsed.scheme != "tls"
        or parsed.hostname is None
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or observed_port is None
    ):
        raise ProjectionConfigurationError(
            "enabled projection requires one credential-free TLS NATS origin"
        )
    if (
        parsed.hostname.lower() != expected_host.lower()
        or observed_port != expected_port
        or nats_stream != expected_stream
        or nats_subject_prefix != expected_prefix
    ):
        raise ProjectionConfigurationError(
            "NATS URL, stream, and subject prefix must match "
            "the selected runtime profile"
        )


def _validate_profile_credential_path(
    credential: Path,
    *,
    profile: Mapping[str, Any],
) -> None:
    prefix = profile.get("secret_path_prefix")
    if not isinstance(prefix, str) or not prefix.startswith("/"):
        raise ProjectionConfigurationError(
            "selected runtime profile has malformed secret-path authority"
        )
    normalized = posixpath.normpath(str(credential).replace("\\", "/"))
    if not normalized.startswith(prefix):
        raise ProjectionConfigurationError(
            "NATS credential path does not match the runtime profile"
        )


@dataclass(frozen=True, slots=True)
class ProjectionSettings:
    enabled: bool
    synthetic_only: bool
    app_env: str
    runtime_profile_id: str | None
    activation_id: str | None
    nats_url: str | None
    nats_stream: str
    nats_subject_prefix: str
    nats_credentials_file: Path | None
    durable_consumer: str
    state_path: Path
    odoo_base_url: str | None
    tenant_secrets: Mapping[str, bytes]
    default_secret: bytes | None
    batch_size: int = 10
    fetch_timeout_seconds: float = 2.0

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
    ) -> Self:
        source = os.environ if env is None else env
        enabled = parse_bool(
            source.get("VICIDIAL_ODOO_PROJECTION_ENABLED"),
            name="VICIDIAL_ODOO_PROJECTION_ENABLED",
            default=False,
        )
        synthetic_only = parse_bool(
            source.get("VICIDIAL_ODOO_SYNTHETIC_ONLY"),
            name="VICIDIAL_ODOO_SYNTHETIC_ONLY",
            default=True,
        )
        tenant_secrets: dict[str, bytes] = {}
        tenant_file = source.get(
            "VICIDIAL_ODOO_TENANT_HMAC_SECRETS_FILE",
            "",
        ).strip()
        if tenant_file:
            decoded = json.loads(
                _read_private_text(Path(tenant_file), minimum_bytes=2)
            )
            if not isinstance(decoded, dict) or not all(
                isinstance(key, str)
                and key
                and isinstance(value, str)
                and len(value.encode()) >= 32
                for key, value in decoded.items()
            ):
                raise ProjectionConfigurationError(
                    "tenant HMAC secret file must map tenant IDs "
                    "to >=32-byte strings"
                )
            tenant_secrets = {
                key: value.encode() for key, value in decoded.items()
            }
        default_secret: bytes | None = None
        secret_file = source.get(
            "VICIDIAL_ODOO_HMAC_SECRET_FILE",
            "",
        ).strip()
        if secret_file:
            default_secret = _read_private_text(
                Path(secret_file),
                minimum_bytes=32,
            ).encode()
        state_path = Path(
            source.get(
                "VICIDIAL_ODOO_STATE_PATH",
                "/var/lib/codestra-middleware/"
                "vicidial-odoo-projection.sqlite3",
            )
        )
        credentials = source.get("NATS_CREDS_FILE", "").strip()
        app_env = source.get("APP_ENV", "development").strip().lower()
        runtime_profile_id = (
            source.get("RUNTIME_PROFILE_ID", "").strip() or None
        )
        settings = cls(
            enabled=enabled,
            synthetic_only=synthetic_only,
            app_env=app_env,
            runtime_profile_id=runtime_profile_id,
            activation_id=source.get(
                "VICIDIAL_ODOO_ACTIVATION_ID",
                "",
            ).strip()
            or None,
            nats_url=source.get("NATS_URL", "").strip() or None,
            nats_stream=source.get(
                "NATS_STREAM",
                "CODESTRA_EVENTS",
            ).strip(),
            nats_subject_prefix=source.get(
                "NATS_SUBJECT_PREFIX",
                "codestra.events",
            ).strip(),
            nats_credentials_file=(
                Path(credentials) if credentials else None
            ),
            durable_consumer=source.get(
                "VICIDIAL_ODOO_DURABLE_CONSUMER",
                f"codestra-vicidial-odoo-{app_env}-v1",
            ).strip(),
            state_path=state_path,
            odoo_base_url=(
                source.get("ODOO_19_BASE_URL", "").strip() or None
            ),
            tenant_secrets=tenant_secrets,
            default_secret=default_secret,
            batch_size=int(
                source.get("VICIDIAL_ODOO_BATCH_SIZE", "10")
            ),
            fetch_timeout_seconds=float(
                source.get(
                    "VICIDIAL_ODOO_FETCH_TIMEOUT_SECONDS",
                    "2",
                )
            ),
        )
        settings.validate(source)
        return settings

    def validate(self, source: Mapping[str, str]) -> None:
        if self.app_env not in {
            "development",
            "test",
            "staging",
            "production",
        }:
            raise ProjectionConfigurationError("APP_ENV is not recognized")
        if not self.enabled:
            return
        if not self.runtime_profile_id:
            raise ProjectionConfigurationError(
                "enabled projection requires RUNTIME_PROFILE_ID"
            )
        profile = _runtime_profile(self.runtime_profile_id)
        if profile.get("environment") != self.app_env:
            raise ProjectionConfigurationError(
                "RUNTIME_PROFILE_ID environment does not match APP_ENV"
            )
        if (
            self.activation_id is not None
            and profile.get("production_activation_allowed") is not True
        ):
            raise ProjectionConfigurationError(
                "VICIDIAL_ODOO_ACTIVATION_ID is forbidden "
                "by the runtime profile"
            )
        if not _absolute_like(self.state_path):
            raise ProjectionConfigurationError(
                "projection state path must be absolute"
            )
        if not _SAFE_DURABLE.fullmatch(self.durable_consumer):
            raise ProjectionConfigurationError(
                "durable consumer name is invalid"
            )
        if self.app_env not in self.durable_consumer.lower():
            raise ProjectionConfigurationError(
                "durable consumer must be environment-scoped"
            )
        if not 1 <= self.batch_size <= 100:
            raise ProjectionConfigurationError(
                "batch size must be between 1 and 100"
            )
        if not 0.1 <= self.fetch_timeout_seconds <= 30:
            raise ProjectionConfigurationError(
                "fetch timeout must be between 0.1 and 30 seconds"
            )
        if not self.nats_url:
            raise ProjectionConfigurationError(
                "enabled projection requires a NATS URL"
            )
        _validate_nats_profile(
            nats_url=self.nats_url,
            nats_stream=self.nats_stream,
            nats_subject_prefix=self.nats_subject_prefix,
            profile=profile,
        )
        if (
            self.nats_credentials_file is None
            or not _absolute_like(self.nats_credentials_file)
        ):
            raise ProjectionConfigurationError(
                "enabled projection requires an absolute "
                "NATS credentials path"
            )
        _validate_profile_credential_path(
            self.nats_credentials_file,
            profile=profile,
        )
        if not self.odoo_base_url:
            raise ProjectionConfigurationError(
                "enabled projection requires ODOO_19_BASE_URL"
            )
        _https_origin(self.odoo_base_url)
        if not self.tenant_secrets and not self.default_secret:
            raise ProjectionConfigurationError(
                "enabled projection requires an Odoo HMAC secret file"
            )
        if self.app_env == "staging" and not self.synthetic_only:
            raise ProjectionConfigurationError(
                "staging projection must remain TEST_SYN-only"
            )
        if (
            source.get("PRODUCTION_DIALING", "DISABLED")
            .strip()
            .upper()
            != "DISABLED"
        ):
            raise ProjectionConfigurationError(
                "PRODUCTION_DIALING must remain DISABLED"
            )
        for name in (
            "VICIDIAL_WRITES_ENABLED",
            "EXTERNAL_DIAL_ENABLED",
            "PRODUCTION_CALLBACKS_ENABLED",
            "LIVE_SMS_DELIVERY",
            "LIVE_EMAIL_DELIVERY",
        ):
            if parse_bool(
                source.get(name),
                name=name,
                default=False,
            ):
                raise ProjectionConfigurationError(
                    f"{name} must remain disabled"
                )
        if self.app_env == "production":
            if not self.activation_id:
                raise ProjectionConfigurationError(
                    "production projection requires "
                    "VICIDIAL_ODOO_ACTIVATION_ID"
                )
            if not parse_bool(
                source.get("EXTERNAL_DELIVERY_ENABLED"),
                name="EXTERNAL_DELIVERY_ENABLED",
                default=False,
            ) or not parse_bool(
                source.get("ODOO_WRITE"),
                name="ODOO_WRITE",
                default=False,
            ):
                raise ProjectionConfigurationError(
                    "production projection requires "
                    "EXTERNAL_DELIVERY_ENABLED and ODOO_WRITE"
                )

    @property
    def subject(self) -> str:
        return (
            f"{self.nats_subject_prefix}."
            "vicidial.call.lifecycle.>"
        )
