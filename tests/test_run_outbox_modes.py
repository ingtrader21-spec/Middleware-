"""The outbox worker's mode guard: adapter dispatch (the V3 execution bus) is
a worker mode of its own, so a process whose only enabled capability is owned
by a kernel adapter drains its adapter-command rows instead of refusing to
start; with every mode off it still fails closed."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.commands import ADAPTER_COMMAND_DESTINATION
from app.core.config import ConfigurationError, Settings
from workers import run_outbox


class _Runtime:
    def __init__(self, enabled: tuple[str, ...]) -> None:
        self.pool = object()
        self.platform = SimpleNamespace(
            registry=SimpleNamespace(enabled_adapter_ids=lambda: enabled),
            dispatch=self._dispatch,
        )
        self.closed = False

    async def _dispatch(self, record) -> None:  # pragma: no cover - never invoked here
        raise AssertionError("dispatch is not exercised by the mode guard")

    async def close(self) -> None:
        self.closed = True


class _Worker:
    instances: list["_Worker"] = []

    def __init__(self, store, handlers) -> None:
        self.handlers = dict(handlers)
        _Worker.instances.append(self)

    async def run_forever(self) -> None:
        return None


@pytest.fixture
def worker_process(monkeypatch: pytest.MonkeyPatch, test_settings: Settings):
    """All legacy modes off (the checked staging shape); the runtime is faked
    so the guard is exercised without a database."""
    assert test_settings.outbox_dispatch_enabled is False
    assert test_settings.temporal_worker_mode == "disabled"
    assert test_settings.odoo_19_delivery_enabled is False
    assert test_settings.klyrow_odoo_projection_enabled is False
    monkeypatch.setattr(run_outbox.Settings, "from_env", staticmethod(lambda: test_settings))
    monkeypatch.setattr(run_outbox, "PostgresOutboxStore", lambda pool: object())
    monkeypatch.setattr(run_outbox, "OutboxWorker", _Worker)
    _Worker.instances.clear()
    runtimes: list[_Runtime] = []

    def install(enabled: tuple[str, ...]) -> _Runtime:
        runtime = _Runtime(enabled)
        runtimes.append(runtime)

        async def build(settings, **kwargs):
            assert kwargs["role"] == "worker"
            return runtime

        monkeypatch.setattr(run_outbox, "build_runtime_container", build)
        return runtime

    return install


@pytest.mark.asyncio
async def test_adapter_dispatch_alone_is_a_valid_worker_mode(worker_process) -> None:
    runtime = worker_process(("test-syn",))
    await run_outbox.main()
    assert len(_Worker.instances) == 1
    assert list(_Worker.instances[0].handlers) == [ADAPTER_COMMAND_DESTINATION]
    assert runtime.closed is True


@pytest.mark.asyncio
async def test_every_mode_off_still_fails_closed(worker_process) -> None:
    runtime = worker_process(())
    with pytest.raises(ConfigurationError, match="adapter outbox dispatch are all"):
        await run_outbox.main()
    assert _Worker.instances == []
    assert runtime.closed is True
