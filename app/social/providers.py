from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from app.social.domain import (
    Capability,
    NormalizedEvent,
    ProviderName,
    ProviderResult,
    SocialPost,
)


class SocialError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        status_code: int = 400,
        unknown_result: bool = False,
    ):
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.retryable = retryable
        self.status_code = status_code
        self.unknown_result = unknown_result


class SocialProviderAdapter(ABC):
    name: ProviderName

    @abstractmethod
    async def health_check(self) -> dict[str, Any]: ...

    @abstractmethod
    def get_capabilities(self) -> frozenset[Capability]: ...

    async def list_accounts(self) -> list[dict[str, Any]]:
        return self._unsupported(Capability.POST_CREATE)

    async def get_account(self, provider_account_id: str) -> dict[str, Any]:
        return self._unsupported(Capability.POST_CREATE)

    async def create_post(
        self, post: SocialPost, account_refs: list[str], correlation_id: str
    ) -> ProviderResult:
        return self._unsupported(Capability.POST_CREATE)

    async def update_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return self._unsupported(Capability.POST_UPDATE)

    async def schedule_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return self._unsupported(Capability.POST_SCHEDULE)

    async def publish_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return self._unsupported(Capability.POST_PUBLISH)

    async def cancel_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return self._unsupported(Capability.POST_CANCEL)

    async def delete_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return self._unsupported(Capability.POST_DELETE)

    async def get_post(self, provider_post_id: str) -> ProviderResult:
        return self._unsupported(Capability.POST_CREATE)

    async def get_post_status(self, provider_post_id: str) -> ProviderResult:
        return self._unsupported(Capability.POST_CREATE)

    async def upload_media(
        self, media: Mapping[str, Any], correlation_id: str
    ) -> dict[str, Any]:
        return self._unsupported(Capability.MEDIA_UPLOAD)

    async def get_comments(self, provider_post_id: str) -> list[dict[str, Any]]:
        return self._unsupported(Capability.COMMENT_READ)

    async def get_messages(self, provider_account_id: str) -> list[dict[str, Any]]:
        return self._unsupported(Capability.MESSAGE_READ)

    async def get_analytics(self, provider_post_id: str) -> dict[str, Any]:
        return self._unsupported(Capability.ANALYTICS)

    async def normalize_webhook(
        self, payload: Mapping[str, Any], correlation_id: str
    ) -> NormalizedEvent:
        return self._unsupported(Capability.WEBHOOK_EVENTS)

    async def verify_webhook(self, body: bytes, headers: Mapping[str, str]) -> None:
        self._unsupported(Capability.WEBHOOK_EVENTS)

    @staticmethod
    def _unsupported(capability: Capability):
        raise SocialError(
            "SOCIAL_PROVIDER_CAPABILITY_UNSUPPORTED",
            f"Provider capability {capability} is unsupported",
            status_code=422,
        )


class SocialProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[ProviderName, SocialProviderAdapter] = {}

    def register(self, adapter: SocialProviderAdapter) -> None:
        if adapter.name in (ProviderName.DISABLED,):
            raise ValueError("disabled is not an adapter")
        self._providers[adapter.name] = adapter

    def get(self, name: ProviderName | str) -> SocialProviderAdapter:
        try:
            provider = ProviderName(name)
        except ValueError as exc:
            raise SocialError(
                "SOCIAL_PROVIDER_NOT_FOUND", "Unknown social provider", status_code=404
            ) from exc
        if provider is ProviderName.DISABLED:
            raise SocialError(
                "SOCIAL_PROVIDER_DISABLED",
                "Social provider is disabled",
                status_code=503,
            )
        try:
            return self._providers[provider]
        except KeyError as exc:
            raise SocialError(
                "SOCIAL_PROVIDER_NOT_CONFIGURED",
                "Social provider is not configured",
                status_code=503,
            ) from exc

    def require(
        self, name: ProviderName | str, capability: Capability
    ) -> SocialProviderAdapter:
        adapter = self.get(name)
        if capability not in adapter.get_capabilities():
            adapter._unsupported(capability)
        return adapter

    def providers(self) -> tuple[SocialProviderAdapter, ...]:
        return tuple(self._providers.values())


def is_retryable_error(error: BaseException) -> bool:
    return isinstance(error, SocialError) and error.retryable
