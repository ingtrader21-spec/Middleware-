from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .vicidial_odoo_projection_errors import ProjectionConflict
from .vicidial_odoo_projection_models import OdooCallEvent, canonical_event_body

_ALLOWED_TRANSITIONS = {
    "received": {
        "received",
        "retryable",
        "reconciliation_required",
        "delivered",
        "failed",
    },
    "retryable": {
        "retryable",
        "reconciliation_required",
        "delivered",
        "failed",
    },
    "reconciliation_required": {
        "reconciliation_required",
        "retryable",
        "delivered",
        "failed",
    },
    "delivered": {"delivered"},
    "failed": {"failed"},
}


class ProjectionState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ProjectionConflict("projection state path may not be a symlink")
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS projection_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS projection_events_call_idx "
                "ON projection_events(tenant_id, call_id, created_at)"
            )
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def register(self, event: OdooCallEvent) -> str:
        body_sha = hashlib.sha256(canonical_event_body(event)).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT payload_sha256, state FROM projection_events WHERE event_id=?",
                (event.event_id,),
            ).fetchone()
            if row:
                if row["payload_sha256"] != body_sha:
                    raise ProjectionConflict("event ID was reused with different content")
                return str(row["state"])
            conn.execute(
                """
                INSERT INTO projection_events(
                    event_id, tenant_id, call_id, event_type, payload_sha256,
                    state, created_at, updated_at
                ) VALUES(?,?,?,?,?,'received',?,?)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    event.call_id,
                    event.event_type,
                    body_sha,
                    now,
                    now,
                ),
            )
        return "received"

    def transition(self, event_id: str, state: str, error: str | None = None) -> None:
        if state not in _ALLOWED_TRANSITIONS:
            raise ValueError("unsupported projection state")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT state FROM projection_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if row is None:
                raise ProjectionConflict("projection event is not registered")
            current = str(row["state"])
            if current not in _ALLOWED_TRANSITIONS:
                raise ProjectionConflict("projection event has an invalid durable state")
            if state not in _ALLOWED_TRANSITIONS[current]:
                raise ProjectionConflict(
                    f"projection state cannot move from {current} to {state}"
                )
            conn.execute(
                """
                UPDATE projection_events
                SET state=?, last_error=?, updated_at=?
                WHERE event_id=?
                """,
                (
                    state,
                    (error or "")[:1024] or None,
                    datetime.now(timezone.utc).isoformat(),
                    event_id,
                ),
            )
