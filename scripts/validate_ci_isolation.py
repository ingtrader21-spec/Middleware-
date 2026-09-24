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


def validate(environ: Mapping[str, str]) -> None:
    for name in ("DATABASE_URL", "TEST_DATABASE_URL"):
        target = urlsplit(environ.get(name, ""))
        if (target.scheme not in {"postgresql", "postgresql+asyncpg"}
                or target.hostname != "127.0.0.1" or target.port != 5432
                or target.path != "/middleware_rehearsal" or target.query or target.fragment):
            raise ValueError(f"{name}: isolated rehearsal database required")
    if environ.get("REDIS_URL") != "redis://127.0.0.1:6379/15":
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
