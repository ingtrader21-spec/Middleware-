"""Server A OpenAI provider worker entrypoint."""

import asyncio

from app.core.config import settings
from app.db.session import SessionFactory
from app.providers.openai_responses import OpenAIResponsesProvider
from app.workers.openai_jobs import run_forever


def main() -> None:
    if not settings.openai_provider_enabled:
        raise RuntimeError("OPENAI_PROVIDER_ENABLED is false")
    provider = OpenAIResponsesProvider(
        api_key=settings.openai_api_key,
        timeout_seconds=settings.openai_request_timeout_seconds,
        max_retries=settings.openai_max_retries,
    )
    asyncio.run(run_forever(provider, SessionFactory))


if __name__ == "__main__":
    main()
