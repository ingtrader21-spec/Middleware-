from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.odoo.lead_automation import PermanentApplyError
from app.core.reliability import RetryPolicy
from app.entrypoints import scraper_odoo_delivery_worker
from app.sales.queue import ScraperRedisQueue
from app.workers import scraper_odoo_delivery
from app.workers.outbox import record_failure


def test_worker_classifies_odoo_contract_errors_as_permanent() -> None:
    assert scraper_odoo_delivery._permanent_failure(PermanentApplyError("denied"))


def test_worker_does_not_classify_transport_errors_as_permanent() -> None:
    assert not scraper_odoo_delivery._permanent_failure(TimeoutError())


class _Result:
    rowcount = 1


class _Session:
    def __init__(self) -> None:
        self.parameters = None
        self.committed = False

    async def execute(self, _statement, parameters):
        self.parameters = parameters
        return _Result()

    async def commit(self):
        self.committed = True


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _MetricsSession:
    def __init__(self) -> None:
        self.execute_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def execute(self, _statement, _parameters=None):
        self.execute_count += 1
        return _Rows([])


class _NoSignalQueue:
    async def enqueue(self, *_args):
        raise AssertionError("disabled worker must not enqueue Redis signals")

    async def claim(self, *_args, **_kwargs):
        raise AssertionError("disabled worker must not consume Redis signals")


class _FakeRedis:
    async def aclose(self) -> None:
        return None


class _StopLoop(Exception):
    pass


@pytest.mark.asyncio
async def test_permanent_failure_dead_letters_on_first_attempt() -> None:
    session = _Session()
    status = await record_failure(
        cast(AsyncSession, session),
        uuid4(),
        0,
        "PermanentApplyError",
        RetryPolicy(max_attempts=8, base_seconds=1, max_seconds=60),
        permanent=True,
    )
    assert status == "dead_letter"
    assert session.parameters is not None
    assert session.parameters["attempts"] == 1
    assert session.parameters["next_attempt_at"] is None
    assert session.parameters["dead_lettered_at"] is not None
    assert session.committed


@pytest.mark.asyncio
async def test_disabled_worker_emits_zero_metrics_without_signaling(
    monkeypatch,
) -> None:
    session = _MetricsSession()
    monkeypatch.setattr(scraper_odoo_delivery, "SessionFactory", lambda: session)
    monkeypatch.setattr(
        scraper_odoo_delivery.settings,
        "scraper_middleware_delivery_enabled",
        False,
    )

    signaled = await scraper_odoo_delivery.recover_and_signal(
        cast(ScraperRedisQueue, _NoSignalQueue())
    )

    assert signaled == 0
    assert session.execute_count == 2
    for status in scraper_odoo_delivery.INBOX_STATES:
        assert (
            scraper_odoo_delivery.QUEUE_DEPTH.labels(
                target="scraper", status=status
            )._value.get()
            == 0
        )
    assert scraper_odoo_delivery.OLDEST_AGE.labels(target="scraper")._value.get() == 0
    assert scraper_odoo_delivery.DLQ_DEPTH.labels(target="scraper")._value.get() == 0


@pytest.mark.asyncio
async def test_disabled_worker_loop_does_not_consume_signals(monkeypatch) -> None:
    queue = _NoSignalQueue()

    async def recover(_queue) -> int:
        return 0

    async def stop_after_one_cycle(_seconds) -> None:
        raise _StopLoop

    monkeypatch.setattr(
        scraper_odoo_delivery.Redis,
        "from_url",
        lambda *_args, **_kwargs: _FakeRedis(),
    )
    monkeypatch.setattr(scraper_odoo_delivery, "ScraperRedisQueue", lambda _redis: queue)
    monkeypatch.setattr(scraper_odoo_delivery, "recover_and_signal", recover)
    monkeypatch.setattr(scraper_odoo_delivery.asyncio, "sleep", stop_after_one_cycle)
    monkeypatch.setattr(
        scraper_odoo_delivery.settings,
        "scraper_middleware_delivery_enabled",
        False,
    )

    with pytest.raises(_StopLoop):
        await scraper_odoo_delivery.run_forever()


def test_worker_exposes_internal_metrics_before_processing(monkeypatch) -> None:
    calls: list[object] = []

    async def no_op_worker() -> None:
        return None

    def run(coroutine) -> None:
        calls.append("run")
        coroutine.close()

    monkeypatch.setattr(
        scraper_odoo_delivery_worker,
        "configure_logging",
        lambda: calls.append("logging"),
    )
    monkeypatch.setattr(
        scraper_odoo_delivery_worker,
        "validate_runtime",
        lambda service: calls.append(("validate", service)),
    )
    monkeypatch.setattr(
        scraper_odoo_delivery_worker,
        "start_http_server",
        lambda port, addr: calls.append(("metrics", port, addr)),
    )
    monkeypatch.setattr(scraper_odoo_delivery_worker, "run_forever", no_op_worker)
    monkeypatch.setattr(scraper_odoo_delivery_worker.asyncio, "run", run)

    scraper_odoo_delivery_worker.main()

    assert calls == [
        "logging",
        ("validate", "middleware-scraper-odoo-delivery"),
        ("metrics", scraper_odoo_delivery_worker.METRICS_PORT, "0.0.0.0"),
        "run",
    ]
