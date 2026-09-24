from __future__ import annotations

from pathlib import Path

from temporalio.client import Client
from temporalio.service import TLSConfig

from app.core.config import ConfigurationError, Settings


def _read_credential(path: Path | None, label: str) -> bytes:
    if path is None:
        raise ConfigurationError(f"{label} is required")
    try:
        value = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"cannot read {label}") from exc
    if not value:
        raise ConfigurationError(f"{label} must not be empty")
    return value


async def connect_temporal(settings: Settings) -> Client:
    if settings.temporal_worker_mode == "disabled" or not settings.temporal_address:
        raise ConfigurationError("Temporal worker is disabled")

    insecure_test = (
        settings.temporal_allow_insecure_test_connection
        and settings.app_env in {"test", "development"}
    )
    tls: bool | TLSConfig
    if insecure_test:
        tls = False
    else:
        tls = TLSConfig(
            server_root_ca_cert=_read_credential(
                settings.temporal_server_root_ca_file,
                "TEMPORAL_SERVER_ROOT_CA_FILE",
            ),
            client_cert=_read_credential(
                settings.temporal_client_cert_file,
                "TEMPORAL_CLIENT_CERT_FILE",
            ),
            client_private_key=_read_credential(
                settings.temporal_client_key_file,
                "TEMPORAL_CLIENT_KEY_FILE",
            ),
            domain=settings.temporal_tls_server_name,
        )
    return await Client.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
        tls=tls,
        identity="codestra-middleware-temporal-worker",
    )
