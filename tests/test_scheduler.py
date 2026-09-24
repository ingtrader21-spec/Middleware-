import asyncio

import pytest

from app.workers.scheduler import run_forever


def test_scheduler_fails_closed_when_disabled():
    with pytest.raises(RuntimeError, match="OUTBOX_WORKER_ENABLED is false"):
        asyncio.run(run_forever())
