from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID

import pytest

from codestra_connector_runtime.api.crypto import EncryptedBodyStore
from codestra_connector_runtime.api.webhook_ingress import WebhookIngressService

TENANT_ID = "11111111-1111-4111-8111-111111111111"
WEBHOOK_ID = "22222222-2222-4222-8222-222222222222"


class ReconciliationRepository:
    def __init__(self, states: dict[str, str | Exception]) -> None:
        self.states = states
        self.calls: list[str] = []

    def webhook_body_reference_state(
        self,
        *,
        tenant_id: UUID,
        webhook_id: UUID,
        event_id: str,
        body_sha256: str,
        encrypted_body_reference: str,
    ) -> str:
        assert str(tenant_id) == TENANT_ID
        assert str(webhook_id) == WEBHOOK_ID
        assert len(body_sha256) == 64
        assert event_id
        self.calls.append(encrypted_body_reference)
        result = self.states[encrypted_body_reference]
        if isinstance(result, Exception):
            raise result
        return result


def make_store(tmp_path: Path) -> EncryptedBodyStore:
    root = tmp_path / "bodies"
    root.mkdir(mode=0o700)
    store = EncryptedBodyStore(root=root, key=b"k" * 32)
    store.reconciliation_root.mkdir(mode=0o700)
    return store


def persist(
    store: EncryptedBodyStore,
    body: bytes,
    *,
    event_id: str,
) -> tuple[str, bool]:
    return store.persist_with_status(
        body,
        tenant_id=TENANT_ID,
        webhook_id=WEBHOOK_ID,
        event_id=event_id,
    )


def service(
    repository: ReconciliationRepository,
    store: EncryptedBodyStore,
) -> WebhookIngressService:
    return WebhookIngressService(
        repository=repository,  # type: ignore[arg-type]
        settings=object(),  # type: ignore[arg-type]
        body_store=store,
        secrets=object(),  # type: ignore[arg-type]
    )


def target(store: EncryptedBodyStore, reference: str) -> Path:
    return store.root / Path(reference.removeprefix("file:"))


def test_duplicate_persistence_reuses_one_body_and_pending_record(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    first_reference, first_created = persist(
        store,
        b'{"status":"delivered"}',
        event_id="evt-duplicate",
    )
    second_reference, second_created = persist(
        store,
        b'{"status":"delivered"}',
        event_id="evt-duplicate",
    )
    assert first_reference == second_reference
    assert first_created is True
    assert second_created is False
    assert store.has_pending(first_reference)
    assert len(list(store.reconciliation_root.glob("*.json"))) == 1
    store.mark_accepted(first_reference)
    assert not store.has_pending(first_reference)
    assert store.read(
        first_reference,
        tenant_id=TENANT_ID,
        webhook_id=WEBHOOK_ID,
        event_id="evt-duplicate",
        body_sha256=hashlib.sha256(
            b'{"status":"delivered"}'
        ).hexdigest(),
    ) == b'{"status":"delivered"}'


def test_reconciliation_retains_accepted_and_removes_rejected(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    accepted, _ = persist(store, b"accepted", event_id="evt-accepted")
    rolled_back, _ = persist(
        store,
        b"rolled-back",
        event_id="evt-rollback",
    )
    conflict, _ = persist(store, b"conflict", event_id="evt-conflict")
    repository = ReconciliationRepository(
        {
            accepted: "accepted",
            rolled_back: "unreferenced",
            conflict: "rejected",
        }
    )
    result = service(repository, store).reconcile_pending_bodies(
        grace_seconds=0,
        now=10**12,
    )
    assert result == {
        "examined": 3,
        "retained": 1,
        "removed": 2,
        "deferred": 0,
        "invalid": 0,
    }
    assert target(store, accepted).is_file()
    assert not target(store, rolled_back).exists()
    assert not target(store, conflict).exists()
    assert list(store.reconciliation_root.glob("*.json")) == []


def test_database_or_process_error_is_deferred_and_retried(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    reference, _ = persist(
        store,
        b"unknown-outcome",
        event_id="evt-unknown",
    )
    repository = ReconciliationRepository(
        {reference: RuntimeError("database outcome unavailable")}
    )
    ingress = service(repository, store)
    first = ingress.reconcile_pending_bodies(
        grace_seconds=0,
        now=10**12,
    )
    assert first["deferred"] == 1
    assert store.has_pending(reference)
    assert target(store, reference).is_file()
    repository.states[reference] = "unreferenced"
    second = ingress.reconcile_pending_bodies(
        grace_seconds=0,
        now=10**12,
    )
    assert second["removed"] == 1
    assert not store.has_pending(reference)
    assert not target(store, reference).exists()


def test_recent_pending_record_is_not_reconciled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = make_store(tmp_path)
    monkeypatch.setattr(
        "codestra_connector_runtime.api.crypto.time.time",
        lambda: 1_000.0,
    )
    reference, _ = persist(store, b"recent", event_id="evt-recent")
    repository = ReconciliationRepository({reference: "unreferenced"})
    result = service(repository, store).reconcile_pending_bodies(
        grace_seconds=300,
        now=1_299.0,
    )
    assert result["examined"] == 0
    assert repository.calls == []
    assert store.has_pending(reference)
    assert target(store, reference).is_file()


def test_failed_delete_keeps_retry_record_until_next_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = make_store(tmp_path)
    reference, _ = persist(
        store,
        b"retry-delete",
        event_id="evt-retry",
    )
    body_path = target(store, reference)
    original_unlink = Path.unlink
    failed = False

    def flaky_unlink(path: Path, missing_ok: bool = False) -> None:
        nonlocal failed
        if path == body_path and not failed:
            failed = True
            raise OSError("simulated filesystem failure")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)
    with pytest.raises(OSError, match="simulated filesystem failure"):
        store.discard_pending(reference)
    assert body_path.is_file()
    assert store.has_pending(reference)
    store.discard_pending(reference)
    assert not body_path.exists()
    assert not store.has_pending(reference)


def test_corrupt_record_is_counted_without_deleting_body(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    reference, _ = persist(store, b"safe", event_id="evt-safe")
    pending_path = next(store.reconciliation_root.glob("*.json"))
    pending_path.write_text("{not-json", encoding="utf-8")
    repository = ReconciliationRepository({reference: "unreferenced"})
    result = service(repository, store).reconcile_pending_bodies(
        grace_seconds=0,
        now=10**12,
    )
    assert result["invalid"] == 1
    assert result["examined"] == 0
    assert target(store, reference).is_file()
