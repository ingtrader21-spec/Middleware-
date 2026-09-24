import asyncio
import base64
import json
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1.publisher import _quarantine, _security_rejection
from app.api.v1.quarantine import detail, list_records, reprocess, review
from app.core.config import settings
from app.core.quarantine import encrypt_payload, fingerprint
from app.db.models import (
    IntegrationDelivery,
    IntegrationEvent,
    InvalidEventQuarantine,
    SecurityRejection,
)
from app.workers.quarantine import cleanup_expired
from app.entrypoints.event_gateway import app as gateway_app


def test_invalid_event_quarantine_database_gates(tmp_path, monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    encryption_key = b"e" * 32
    fingerprint_key = b"f" * 32
    encryption_file = tmp_path / "encryption"
    fingerprint_file = tmp_path / "fingerprint"
    encryption_file.write_text(
        base64.urlsafe_b64encode(encryption_key).decode().rstrip("=")
    )
    fingerprint_file.write_text(
        base64.urlsafe_b64encode(fingerprint_key).decode().rstrip("=")
    )
    reviewer_key = b"r" * 32
    reviewer_file = tmp_path / "reviewer"
    reviewer_file.write_text(
        base64.urlsafe_b64encode(reviewer_key).decode().rstrip("=")
    )
    monkeypatch.setattr(
        settings, "quarantine_encryption_key_file", str(encryption_file)
    )
    monkeypatch.setattr(
        settings, "quarantine_fingerprint_secret_file", str(fingerprint_file)
    )
    monkeypatch.setattr(settings, "quarantine_reviewer_secret_file", str(reviewer_file))
    publisher_key = b"p" * 32
    publisher_file = tmp_path / "publishers.json"
    publisher_file.write_text(
        json.dumps(
            {
                "publisher-test": base64.urlsafe_b64encode(publisher_key)
                .decode()
                .rstrip("=")
            }
        )
    )
    monkeypatch.setattr(settings, "publisher_hmac_keys_file", str(publisher_file))
    monkeypatch.setattr(settings, "publisher_canary_enabled", True)
    asyncio.run(_scenario(database_url, encryption_key, fingerprint_key, reviewer_key))
    with TestClient(gateway_app) as client:
        _http_security_scenario(database_url, publisher_key, client)


def _request(correlation: str):
    return SimpleNamespace(
        state=SimpleNamespace(
            correlation_id=correlation,
            client_correlation_id="validated-client-correlation",
        ),
        headers={
            "X-Codestra-Publisher-ID": "claimed-unverified",
            "X-Codestra-Key-ID": "publisher-test",
        },
        client=SimpleNamespace(host="127.0.0.1"),
    )


def _valid_event(event_id: str, campaign: str = "TEST_SYN") -> bytes:
    now = datetime.now(timezone.utc)
    value = {
        "schema_version": "2.0",
        "event_id": event_id,
        "event_type": "synthetic.publisher_canary",
        "source_system": "test",
        "created_at": now.isoformat(),
        "occurred_at": now.isoformat(),
        "boot_session_id": "synthetic",
        "sequence": 1,
        "call_uniqueid": "synthetic",
        "correlation_id": "caller-value-is-not-server-identity",
        "business_unit": "MOY",
        "campaign": campaign,
        "agent_id": "SYNTHETIC",
        "customer_reference": None,
        "payload": {},
        "policy_decision": {},
        "recording_reference": None,
        "delivery": {"expires_at": (now + timedelta(hours=1)).isoformat()},
        "privacy": {
            "classification": "synthetic",
            "contains_customer_data": False,
        },
        "idempotency": {"key": "synthetic"},
    }
    return json.dumps(value, separators=(",", ":")).encode()


def _signed_headers(body: bytes, secret: bytes, nonce: str) -> dict[str, str]:
    import time

    timestamp = str(int(time.time()))
    event_id = str(uuid4())
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        ("v2", "publisher-test", timestamp, nonce, event_id, digest)
    ).encode()
    signature = (
        base64.urlsafe_b64encode(hmac.new(secret, canonical, hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    return {
        "X-Codestra-Key-ID": "publisher-test",
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Nonce": nonce,
        "X-Codestra-Body-SHA256": digest,
        "X-Codestra-Event-ID": event_id,
        "X-Codestra-Signature": "v2=" + signature,
    }


def _counts(database_url: str) -> tuple[int, int, int]:
    async def read():
        engine = create_async_engine(database_url)
        try:
            async with engine.connect() as connection:
                values = []
                for table in (
                    "security_rejection",
                    "invalid_event_quarantine",
                    "integration_event",
                ):
                    values.append(
                        int(
                            (
                                await connection.execute(
                                    text(f"SELECT count(*) FROM {table}")
                                )
                            ).scalar()
                        )
                    )
                return tuple(values)
        finally:
            await engine.dispose()

    return asyncio.run(read())


def _http_security_scenario(
    database_url: str, publisher_key: bytes, client: TestClient
) -> None:
    missing = client.post("/api/v2/telephony/canary", content=b'{"secret":"x"}')
    assert missing.status_code == 401
    assert _counts(database_url) == (2, 3, 1)

    malformed = b'{"authorization":"Bearer never-return"'
    headers = _signed_headers(malformed, publisher_key, "malformed-once")
    response = client.post(
        "/api/v2/telephony/canary", content=malformed, headers=headers
    )
    assert response.status_code == 422
    security, quarantined, canonical = _counts(database_url)
    assert (security, canonical) == (2, 1)
    assert quarantined == 4

    replay = client.post("/api/v2/telephony/canary", content=malformed, headers=headers)
    assert replay.status_code == 401
    security_after, quarantined_after, canonical_after = _counts(database_url)
    assert security_after == security + 1
    assert quarantined_after == quarantined
    assert canonical_after == canonical

    invalid_signature = dict(_signed_headers(b"{}", publisher_key, "bad-signature"))
    invalid_signature["X-Codestra-Signature"] = "v2=invalid"
    assert (
        client.post(
            "/api/v2/telephony/canary", content=b"{}", headers=invalid_signature
        ).status_code
        == 401
    )
    assert _counts(database_url)[1:] == (quarantined, canonical)

    oversized = b"x" * (settings.request_max_bytes + 1)
    assert (
        client.post(
            "/api/v2/telephony/canary",
            content=oversized,
            headers=_signed_headers(oversized, publisher_key, "oversized"),
        ).status_code
        == 413
    )
    assert _counts(database_url)[1:] == (quarantined, canonical)


def _review_authorization(
    reviewer_key: bytes, reviewer: str, scopes: str, units: str
) -> str:
    return hmac.new(
        reviewer_key,
        "\n".join((reviewer, scopes, units)).encode(),
        hashlib.sha256,
    ).hexdigest()


async def _scenario(
    database_url: str,
    encryption_key: bytes,
    fingerprint_key: bytes,
    reviewer_key: bytes,
):
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            await session.execute(
                text(
                    "TRUNCATE quarantine_correction, invalid_event_quarantine, "
                    "security_rejection, integration_delivery, integration_event, "
                    "publisher_nonce, audit_event CASCADE"
                )
            )
            await session.commit()

            attacker = b'{"authorization":"Bearer never-store","phone":"+18095550123"}'
            await _security_rejection(
                session,
                _request("security-rejection"),
                attacker,
                "invalid_signature",
            )
            assert await session.scalar(select(func.count(SecurityRejection.id))) == 1
            assert (
                await session.scalar(select(func.count(InvalidEventQuarantine.id))) == 0
            )
            assert await session.scalar(select(func.count(IntegrationEvent.id))) == 0
            rejection_columns = {
                column.name for column in SecurityRejection.__table__.columns
            }
            assert not rejection_columns.intersection(
                {"raw_payload", "payload", "encrypted_payload"}
            )

            malformed = b'{"event_type":"bad","token":"never-preview"}'
            await _quarantine(
                session,
                _request("authenticated-invalid"),
                malformed,
                key_id="publisher-test",
                publisher_id="publisher-test",
                reason="schema_rejected",
                parsed=None,
            )
            invalid = await session.scalar(select(InvalidEventQuarantine))
            assert invalid is not None
            assert (
                invalid.encrypted_payload and malformed not in invalid.encrypted_payload
            )
            assert "never-preview" not in json.dumps(invalid.sanitized_preview)
            assert await session.scalar(select(func.count(IntegrationEvent.id))) == 0
            assert await session.scalar(select(func.count(IntegrationDelivery.id))) == 0

            invalid.received_at = datetime.now(timezone.utc) - timedelta(days=2)
            invalid.retention_deadline = datetime.now(timezone.utc) - timedelta(days=1)
            invalid.legal_hold = True
            await session.commit()
            assert await cleanup_expired(session) == {"expired": 0}
            await session.refresh(invalid)
            assert invalid.encrypted_payload is not None

            raw = _valid_event(str(uuid4()))
            digest = fingerprint(raw, fingerprint_key)
            encrypted = encrypt_payload(raw, encryption_key, "test-v1", digest)
            replay_record = InvalidEventQuarantine(
                server_correlation_id="reprocess-server",
                client_correlation_id="client",
                authenticated_publisher_id="publisher-test",
                authentication_state="VERIFIED",
                authentication_key_id="publisher-test",
                original_signature_verification="VERIFIED",
                payload_fingerprint=digest,
                encrypted_payload=encrypted.ciphertext,
                encryption_nonce=encrypted.nonce,
                encryption_key_version=encrypted.key_version,
                sanitized_preview={"business_unit": "MOY"},
                reason_code="schema_rejected",
                business_unit="MOY",
                status="REPLAY_APPROVED",
                retention_policy_version="test",
                retention_deadline=datetime.now(timezone.utc) + timedelta(days=1),
                received_at=datetime.now(timezone.utc),
            )
            session.add(replay_record)
            await session.commit()
            replay_id = replay_record.id
            for operation in (
                lambda: list_records(
                    business_unit="MOY",
                    scopes="",
                    reviewer="",
                    authorized_units="",
                    authorization_context="",
                    db=session,
                ),
                lambda: detail(
                    replay_id,
                    scopes="",
                    reviewer="",
                    authorized_units="",
                    authorization_context="",
                    db=session,
                ),
                lambda: review(
                    replay_id,
                    target_state="REPLAYING",
                    record_version=replay_record.record_version,
                    scopes="",
                    reviewer="",
                    authorized_units="",
                    authorization_context="",
                    db=session,
                ),
                lambda: reprocess(
                    replay_id,
                    scopes="",
                    reviewer="",
                    authorized_units="",
                    authorization_context="",
                    db=session,
                ),
            ):
                with pytest.raises(HTTPException) as unauthorized:
                    await operation()
                assert unauthorized.value.status_code == 403

        async def attempt():
            async with factory() as candidate:
                scopes = "quarantine:replay"
                return await reprocess(
                    replay_id,
                    scopes=scopes,
                    reviewer="reviewer-test",
                    authorized_units="MOY",
                    authorization_context=_review_authorization(
                        reviewer_key, "reviewer-test", scopes, "MOY"
                    ),
                    db=candidate,
                )

        results = await asyncio.gather(attempt(), attempt())
        assert {result["duplicate"] for result in results} == {False, True}
        async with factory() as session:
            assert await session.scalar(select(func.count(IntegrationEvent.id))) == 1
            assert await session.scalar(select(func.count(IntegrationDelivery.id))) == 2
            replayed = await session.get(InvalidEventQuarantine, replay_id)
            assert replayed is not None
            assert replayed.status == "REPLAYED"
            assert replayed.replay_count == 1

            denied_raw = _valid_event(str(uuid4()))
            denied_digest = fingerprint(denied_raw, fingerprint_key)
            denied_encrypted = encrypt_payload(
                denied_raw, encryption_key, "test-v1", denied_digest
            )
            denied = InvalidEventQuarantine(
                server_correlation_id="policy-denied",
                authenticated_publisher_id="publisher-test",
                authentication_state="VERIFIED",
                original_signature_verification="VERIFIED",
                payload_fingerprint=denied_digest,
                encrypted_payload=denied_encrypted.ciphertext,
                encryption_nonce=denied_encrypted.nonce,
                encryption_key_version="test-v1",
                sanitized_preview={"business_unit": "COD"},
                reason_code="policy_rejected",
                business_unit="COD",
                status="REPLAY_APPROVED",
                retention_policy_version="test",
                retention_deadline=datetime.now(timezone.utc) + timedelta(days=1),
                received_at=datetime.now(timezone.utc),
            )
            session.add(denied)
            await session.commit()
            with pytest.raises(HTTPException) as policy_error:
                scopes = "quarantine:replay"
                await reprocess(
                    denied.id,
                    scopes=scopes,
                    reviewer="reviewer-test",
                    authorized_units="COD",
                    authorization_context=_review_authorization(
                        reviewer_key, "reviewer-test", scopes, "COD"
                    ),
                    db=session,
                )
            assert policy_error.value.status_code == 403
            assert await session.scalar(select(func.count(IntegrationEvent.id))) == 1
            await session.refresh(denied)
            assert denied.status == "REJECTED"
            with pytest.raises(HTTPException) as access_error:
                scopes = "quarantine:read"
                await detail(
                    replay_id,
                    scopes=scopes,
                    reviewer="reviewer-test",
                    authorized_units="COD",
                    authorization_context=_review_authorization(
                        reviewer_key, "reviewer-test", scopes, "COD"
                    ),
                    db=session,
                )
            assert access_error.value.status_code == 403

            invalid = await session.scalar(
                select(InvalidEventQuarantine).where(
                    InvalidEventQuarantine.server_correlation_id
                    == "authenticated-invalid"
                )
            )
            invalid.legal_hold = False
            await session.commit()
            assert await cleanup_expired(session) == {"expired": 1}
            await session.refresh(invalid)
            assert invalid.status == "EXPIRED"
            assert invalid.encrypted_payload is None
    finally:
        await engine.dispose()
