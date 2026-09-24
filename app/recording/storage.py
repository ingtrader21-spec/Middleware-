from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

from .domain import ObjectHead


class PrivateObjectStorage(Protocol):
    def reserve_upload(
        self, opaque_identifier: str, content_type: str, checksum: str, ttl: int
    ) -> tuple[str, datetime]: ...

    def head(self, opaque_identifier: str) -> ObjectHead: ...

    def presign_read(
        self, opaque_identifier: str, version_id: str, ttl: int
    ) -> str: ...


class MemoryObjectStorage:
    """Deterministic test adapter. It never accepts file bytes."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], ObjectHead] = {}

    def reserve_upload(
        self, opaque_identifier: str, content_type: str, checksum: str, ttl: int
    ) -> tuple[str, datetime]:
        expires = datetime.now(UTC) + timedelta(seconds=ttl)
        return (
            f"https://private-storage.invalid/upload/{opaque_identifier}?ttl={ttl}",
            expires,
        )

    def head(self, opaque_identifier: str) -> ObjectHead:
        matches = [
            head for (identifier, _version), head in self.objects.items()
            if identifier == opaque_identifier
        ]
        if len(matches) != 1:
            raise KeyError("object HEAD did not resolve exactly one current version")
        return matches[0]

    def presign_read(
        self, opaque_identifier: str, version_id: str, ttl: int
    ) -> str:
        return (
            f"https://private-storage.invalid/play/{opaque_identifier}"
            f"?version={version_id}&ttl={ttl}&signature=opaque"
        )
