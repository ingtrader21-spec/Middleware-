"""Registered telephony command worker entrypoint.

Runtime composition supplies the registry-backed client.  The deployment flag
defaults false, so source merge alone cannot dispatch a command.
"""

from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from redis.asyncio import Redis

from app.adapters.telephony.client import (
    RegistryTargetAttestor,
    TelephonyServiceClient,
)
from app.core.config import settings
from app.core.endpoint_registry import (
    RegistryResolver,
    ResolutionRequest,
    SessionEndpointRepository,
    SignedSnapshotCache,
)
from app.core.service_client import CommonServiceClient
from app.core.token_manager import TokenManager
from app.db.session import SessionFactory
from app.entrypoints.runtime import run_worker
from app.workers.telephony_commands import TelephonyDispatcher, dispatch_one

SERVICE = "middleware-telephony-command-worker"
QUEUE = "telephony-commands"
_client_factory: Callable[[], TelephonyDispatcher] | None = None


def configure_client_factory(
    factory: Callable[[], TelephonyDispatcher],
) -> None:
    global _client_factory
    _client_factory = factory


def build_client_factory() -> Callable[[], TelephonyDispatcher]:
    credential_root = Path(settings.telephony_credential_directory)
    if (
        not credential_root.is_absolute()
        or not credential_root.is_dir()
        or credential_root.is_symlink()
    ):
        raise RuntimeError("protected telephony credential directory is unavailable")

    async def load_private_key(reference: str) -> str:
        if not reference or Path(reference).name != reference:
            raise RuntimeError("invalid telephony credential reference")
        path = credential_root / reference
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError("telephony credential reference is not protected")
        return path.read_text().strip()

    resolver = RegistryResolver(
        SessionEndpointRepository(SessionFactory),
        SignedSnapshotCache(
            Redis.from_url(settings.redis_url, decode_responses=True),
            settings.load_registry_snapshot_key(),
            l1_ttl_seconds=settings.registry_l1_ttl_seconds,
            l2_ttl_seconds=settings.registry_l2_ttl_seconds,
            stale_grace_seconds=settings.registry_stale_grace_seconds,
        ),
    )
    token_manager = TokenManager(settings.telephony_service_client_id, load_private_key)

    def factory() -> TelephonyDispatcher:
        common = CommonServiceClient(
            resolver,
            token_manager,
            token_endpoint_key=ResolutionRequest(
                environment=settings.environment,
                service_key="identity",
                endpoint_key="oauth.token",
            ),
        )
        return TelephonyServiceClient(common, RegistryTargetAttestor(common))

    return factory


async def cycle() -> dict[str, object]:
    if not settings.telephony_command_worker_enabled:
        return {"claimed": 0, "disabled": True}
    if _client_factory is None:
        raise RuntimeError("telephony command client factory is not configured")
    return await dispatch_one(
        SessionFactory,
        _client_factory,
        environment=settings.environment,
        traceparent_factory=lambda: (
            "00-" + uuid4().hex + "-" + uuid4().hex[:16] + "-01"
        ),
    )


def main() -> None:
    if settings.telephony_command_worker_enabled:
        configure_client_factory(build_client_factory())
    run_worker(SERVICE, QUEUE, cycle)


if __name__ == "__main__":
    main()
