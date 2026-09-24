"""Durable encrypted raw-webhook body storage and reconciliation journal."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True, slots=True)
class PendingBodyRecord:
    """Credential-free evidence for a body awaiting database reconciliation."""

    reference: str
    tenant_id: str
    webhook_id: str
    event_id: str
    body_sha256: str
    created_at: float


@dataclass(frozen=True, slots=True)
class EncryptedBodyStore:
    root: Path
    key: bytes

    @classmethod
    def from_key_file(cls, root: Path, key_file: Path) -> "EncryptedBodyStore":
        raw = key_file.read_bytes().strip()
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception:
            decoded = raw
        if len(decoded) not in {16, 24, 32}:
            raise ValueError("body encryption key must be 16, 24, or 32 bytes")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        store = cls(root=root, key=decoded)
        store.reconciliation_root.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        os.chmod(store.reconciliation_root, 0o700)
        return store

    @property
    def reconciliation_root(self) -> Path:
        return self.root / ".pending-reconciliation"

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        directory_fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _relative_reference(reference: str) -> Path:
        if not reference.startswith("file:"):
            raise ValueError("unsupported encrypted body reference")
        relative = Path(reference.removeprefix("file:"))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid encrypted body reference")
        return relative

    def _target(self, reference: str) -> Path:
        return self.root / self._relative_reference(reference)

    def _pending_path(self, reference: str) -> Path:
        self._relative_reference(reference)
        digest = hashlib.sha256(reference.encode("utf-8")).hexdigest()
        return self.reconciliation_root / f"{digest}.json"

    def _write_pending_record(self, record: PendingBodyRecord) -> None:
        self.reconciliation_root.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        payload = {
            "schema_version": 1,
            "reference": record.reference,
            "tenant_id": record.tenant_id,
            "webhook_id": record.webhook_id,
            "event_id": record.event_id,
            "body_sha256": record.body_sha256,
            "created_at": record.created_at,
        }
        target = self._pending_path(record.reference)
        file_descriptor, temporary_path = tempfile.mkstemp(
            prefix=".pending-record-",
            dir=self.reconciliation_root,
        )
        try:
            with os.fdopen(
                file_descriptor,
                "w",
                encoding="utf-8",
            ) as stream:
                json.dump(
                    payload,
                    stream,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, target)
            self._fsync_directory(self.reconciliation_root)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def persist(
        self,
        body: bytes,
        *,
        tenant_id: str,
        webhook_id: str,
        event_id: str,
    ) -> str:
        reference, _ = self.persist_with_status(
            body,
            tenant_id=tenant_id,
            webhook_id=webhook_id,
            event_id=event_id,
        )
        return reference

    def persist_with_status(
        self,
        body: bytes,
        *,
        tenant_id: str,
        webhook_id: str,
        event_id: str,
    ) -> tuple[str, bool]:
        """Persist a body and durably journal its unresolved DB outcome."""
        body_digest = hashlib.sha256(body).hexdigest()
        safe_event = hashlib.sha256(
            event_id.encode("utf-8")
        ).hexdigest()[:24]
        relative = (
            Path(tenant_id)
            / webhook_id
            / f"{safe_event}-{body_digest}.bin"
        )
        reference = "file:" + relative.as_posix()
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target.parent, 0o700)

        pending = PendingBodyRecord(
            reference=reference,
            tenant_id=tenant_id,
            webhook_id=webhook_id,
            event_id=event_id,
            body_sha256=body_digest,
            created_at=time.time(),
        )
        if target.exists():
            self._write_pending_record(pending)
            return reference, False

        nonce = os.urandom(12)
        associated = (
            f"{tenant_id}:{webhook_id}:{event_id}:{body_digest}"
        ).encode("utf-8")
        ciphertext = AESGCM(self.key).encrypt(nonce, body, associated)
        payload = b"CRB1" + nonce + ciphertext
        file_descriptor, temporary_path = tempfile.mkstemp(
            prefix=".pending-body-",
            dir=target.parent,
        )
        try:
            with os.fdopen(file_descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_path, 0o600)
            # Journal first. A crash before body promotion leaves a
            # harmless record; the inverse order can leave an orphan.
            self._write_pending_record(pending)
            os.replace(temporary_path, target)
            self._fsync_directory(target.parent)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
        return reference, True

    def scan_pending_records(
        self,
        *,
        older_than_seconds: int = 300,
        now: float | None = None,
    ) -> tuple[list[PendingBodyRecord], int]:
        """Return mature records and count malformed records safely."""
        if older_than_seconds < 0:
            raise ValueError("older_than_seconds must be non-negative")
        current = time.time() if now is None else now
        cutoff = current - older_than_seconds
        records: list[PendingBodyRecord] = []
        invalid = 0
        if not self.reconciliation_root.exists():
            return records, invalid
        for path in sorted(self.reconciliation_root.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if value.get("schema_version") != 1:
                    raise ValueError("unsupported pending record schema")
                record = PendingBodyRecord(
                    reference=str(value["reference"]),
                    tenant_id=str(value["tenant_id"]),
                    webhook_id=str(value["webhook_id"]),
                    event_id=str(value["event_id"]),
                    body_sha256=str(value["body_sha256"]),
                    created_at=float(value["created_at"]),
                )
                self._relative_reference(record.reference)
                if not (
                    len(record.body_sha256) == 64
                    and all(
                        character in "0123456789abcdef"
                        for character in record.body_sha256
                    )
                ):
                    raise ValueError("invalid body digest")
            except (OSError, KeyError, TypeError, ValueError):
                invalid += 1
                continue
            if record.created_at <= cutoff:
                records.append(record)
        return records, invalid

    def has_pending(self, reference: str) -> bool:
        return self._pending_path(reference).is_file()

    def mark_accepted(self, reference: str) -> None:
        """Clear reconciliation evidence but retain the accepted body."""
        self._pending_path(reference).unlink(missing_ok=True)
        if self.reconciliation_root.exists():
            self._fsync_directory(self.reconciliation_root)

    def discard_pending(self, reference: str) -> None:
        """Delete a rejected body, then clear its durable retry record."""
        self.remove(reference)
        self.mark_accepted(reference)

    def read(
        self,
        reference: str,
        *,
        tenant_id: str,
        webhook_id: str,
        event_id: str,
        body_sha256: str,
    ) -> bytes:
        payload = self._target(reference).read_bytes()
        if len(payload) < 4 + 12 + 16 or payload[:4] != b"CRB1":
            raise ValueError("encrypted body record is invalid")
        nonce = payload[4:16]
        ciphertext = payload[16:]
        associated = (
            f"{tenant_id}:{webhook_id}:{event_id}:{body_sha256}"
        ).encode("utf-8")
        body = AESGCM(self.key).decrypt(nonce, ciphertext, associated)
        if hashlib.sha256(body).hexdigest() != body_sha256:
            raise ValueError("encrypted body digest does not match")
        return body

    def remove(self, reference: str) -> None:
        """Remove a rejected body without permitting path traversal."""
        self._target(reference).unlink(missing_ok=True)
