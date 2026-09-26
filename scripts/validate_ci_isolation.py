#!/usr/bin/env python3
"""Validate actual CI connection targets, not static production-denial fixtures."""
from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import urlsplit

FLAGS = (
    "LIVE_WRITES_ENABLED", "N8N_PRODUCTION_WORKFLOWS_ENABLED",
    "VICIDIAL_WRITE_ENABLED", "CALLBACK_DISPATCH_ENABLED", "MESSAGING_ENABLED",
    "OUTBOX_WORKER_ENABLED",
)


def _expected_port(environ: Mapping[str, str], name: str) -> int:
    raw = environ.get(name, "")
    if not raw.isdigit():
        raise ValueError(f"{name}: assigned service port required")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}: assigned service port required")
    return port


def validate(environ: Mapping[str, str]) -> None:
    postgres_port = _expected_port(environ, "CI_POSTGRES_PORT")
    redis_port = _expected_port(environ, "CI_REDIS_PORT")
    for name in ("DATABASE_URL", "TEST_DATABASE_URL"):
        target = urlsplit(environ.get(name, ""))
        if (target.scheme not in {"postgresql", "postgresql+asyncpg"}
                or target.hostname != "127.0.0.1" or target.port != postgres_port
                or target.path != "/middleware_rehearsal" or target.query or target.fragment):
            raise ValueError(f"{name}: isolated rehearsal database required")
    redis = urlsplit(environ.get("REDIS_URL", ""))
    if (redis.scheme != "redis" or redis.hostname != "127.0.0.1"
            or redis.port != redis_port
            or redis.path != "/15" or redis.query or redis.fragment):
        raise ValueError("REDIS_URL: isolated Redis namespace required")
    if any(environ.get(name) != "false" for name in FLAGS):
        raise ValueError("all external effects and apply workers must remain disabled")


def main() -> int:
    try:
        validate(os.environ)
    except ValueError as exc:
        print(f"CI_ISOLATION=FAIL {exc}")
        return 1
    print("CI_ISOLATION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
