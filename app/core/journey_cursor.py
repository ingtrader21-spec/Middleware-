"""Versioned, resource-bound keyset positions; cursors never grant authority."""

import base64
import hashlib
import json
import re
from datetime import datetime
from uuid import UUID


def scope_key(tenant_id: str, lead_id: str) -> str:
    return hashlib.sha256(json.dumps([tenant_id, lead_id]).encode()).hexdigest()


def decode_cursor(cursor: str | None, tenant_id: str, lead_id: str):
    if cursor is None:
        return None, None, None, False
    try:
        if not isinstance(cursor, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,500}", cursor):
            raise ValueError()
        value = json.loads(
            base64.b64decode(
                cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
            )
        )
        if not isinstance(value, list) or len(value) != 6:
            raise ValueError()
        version, scope, lifecycle, timestamp, exposure, done = value
        if type(version) is not int or version != 1 or scope != scope_key(tenant_id, lead_id):
            raise ValueError()
        if (
            type(lifecycle) is not int
            or not 0 <= lifecycle <= 9223372036854775807
            or type(done) is not bool
        ):
            raise ValueError()
        if (timestamp is not None and (not isinstance(timestamp, str) or not timestamp)) or (
            exposure is not None and (not isinstance(exposure, str) or not exposure)
        ):
            raise ValueError()
        at = datetime.fromisoformat(timestamp) if timestamp is not None else None
        identifier = UUID(exposure) if exposure is not None else None
        if (at is None) != (identifier is None) or (
            at is not None and at.tzinfo is None
        ):
            raise ValueError()
        if (not done and at is None) or (done and lifecycle == 0):
            raise ValueError()
        return lifecycle, at, identifier, done
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        raise ValueError("invalid journey cursor") from exc


def encode_cursor(tenant_id, lead_id, lifecycle, exposures, limit):
    if len(lifecycle) <= limit and len(exposures) <= limit:
        return None
    last = exposures[min(limit, len(exposures)) - 1] if exposures else None
    value = [
        1,
        scope_key(tenant_id, lead_id),
        lifecycle[limit - 1]["version"] if len(lifecycle) > limit else 0,
        last["reserved_at"].isoformat() if last else None,
        str(last["exposure_id"]) if last else None,
        len(exposures) <= limit,
    ]
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
