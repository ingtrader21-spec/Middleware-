"""Controlled staging social worker entrypoint."""

import asyncio

from redis.asyncio import Redis

from app.core.config import settings
from app.db.session import SessionFactory
from app.workers.social import run_forever


def main() -> None:
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    asyncio.run(run_forever(SessionFactory, redis))


if __name__ == "__main__":
    main()
