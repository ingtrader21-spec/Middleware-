#!/usr/bin/env python3
"""Signed synthetic no-effect harness for the Telnexa callback trust chain.

The harness mints an ephemeral client CA plus good and hostile client leaves,
signs synthetic callbacks with a throwaway API key and HMAC secret, and drives
them in-process through the real FastAPI router:

* ``POST /api/v1/events/telnexa/verify`` must accept only the fully trusted
  synthetic callback and reject every identity, certificate, signature,
  freshness and binding defect with its exact status and detail.
* ``POST /api/v1/events/telnexa`` must refuse synthetic and untrusted callbacks
  before any database statement.  The database dependency is replaced with a
  sentinel that records every call; the run fails if one is made.

No network, provider, SMS runtime, database or real credential is used, and
the process-wide settings are never mutated.  Output is machine-readable JSON.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import sys
import tempfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from app.api.internal.telnexa_events import (  # noqa: E402
    PATH,
    VERIFY_PATH,
    router,
)
from app.db.session import get_session  # noqa: E402
from app.telnexa_callback_identity import (  # noqa: E402
    CLIENT_CERT_DER_HEADER,
    DEFAULT_CLIENT_URI_SAN,
    LEGACY_CLIENT_CERT_HEADER,
)

TRUSTED_PROXY_CIDR = "10.250.241.0/29"
TRUSTED_PROXY_PEER = ("10.250.241.2", 44321)
UNTRUSTED_PEER = ("203.0.113.9", 44321)


@dataclass(frozen=True)
class IssuedCertificate:
    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate

    @property
    def der_b64(self) -> str:
        return base64.b64encode(
            self.certificate.public_bytes(serialization.Encoding.DER)
        ).decode("ascii")

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def sha256(self) -> str:
        return self.certificate.fingerprint(hashes.SHA256()).hex()


def issue_authority(common_name: str = "Codestra Telnexa Callback Test CA") -> IssuedCertificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return IssuedCertificate(key, certificate)


def issue_client_leaf(
    authority: IssuedCertificate,
    *,
    uri_san: str = DEFAULT_CLIENT_URI_SAN,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    extended_usage: tuple[x509.ObjectIdentifier, ...] = (ExtendedKeyUsageOID.CLIENT_AUTH,),
) -> IssuedCertificate:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "telnexa-callback")])
        )
        .issuer_name(authority.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(hours=1))
        .not_valid_after(not_after or now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(uri_san),
                    x509.IPAddress(ipaddress.ip_address("10.40.0.9")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(list(extended_usage)), critical=False)
        .sign(authority.key, hashes.SHA256())
    )
    return IssuedCertificate(key, certificate)


def synthetic_event(
    *,
    event_id: str | None = None,
    timestamp: int | None = None,
    tenant_id: str = "synthetic-tenant",
) -> dict[str, Any]:
    signed_at = int(time.time()) if timestamp is None else timestamp
    return {
        "event_id": event_id or f"synthetic-{uuid4().hex}",
        "event_type": "sms.message.delivered.v1",
        "event_version": "1.0",
        "schema_version": "1.0",
        "timestamp": str(signed_at),
        "occurred_at": datetime.now(UTC).isoformat(),
        "tenant_id": tenant_id,
        "correlation_id": f"synthetic-correlation-{uuid4().hex[:12]}",
        "idempotency_key": f"synthetic-idempotency-{uuid4().hex[:12]}",
        "message_id": str(uuid4()),
        "provider_reference": "synthetic-provider-reference",
        "status": "delivered",
        "provider_status": "DELIVRD",
    }


def signed_request(
    event: dict[str, Any],
    *,
    api_key: str,
    hmac_secret: bytes,
    certificate_der_b64: str | None,
) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    canonical = f"{event['timestamp']}\n{event['event_id']}\ntelnexa\n".encode() + body
    signature = hmac.new(hmac_secret, canonical, hashlib.sha256).hexdigest()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Event-Id": event["event_id"],
        "X-Timestamp": event["timestamp"],
        "X-Signature": f"sha256={signature}",
        "Idempotency-Key": event["idempotency_key"],
    }
    if certificate_der_b64 is not None:
        headers[CLIENT_CERT_DER_HEADER] = certificate_der_b64
    return body, headers


class SentinelSession:
    """Database stand-in that records, and therefore exposes, every effect."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def execute(self, statement: object, parameters: object = None) -> None:
        self.calls.append(str(statement))
        raise RuntimeError("synthetic harness forbids database effects")

    async def commit(self) -> None:
        self.calls.append("COMMIT")

    async def rollback(self) -> None:
        return None


@dataclass
class HarnessCase:
    name: str
    path: str
    expected_status: int
    expected_detail: str | None
    observed_status: int = 0
    observed_detail: str | None = None
    passed: bool = False


@dataclass
class HarnessRun:
    cases: list[HarnessCase] = field(default_factory=list)
    database_calls: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.database_calls and all(case.passed for case in self.cases)

    def as_json(self) -> dict[str, Any]:
        return {
            "harness": "telnexa-callback-trust",
            "effect": "none",
            "passed": self.passed,
            "database_calls": len(self.database_calls),
            "case_count": len(self.cases),
            "cases": [case.__dict__ for case in self.cases],
        }


def _runtime_settings(ca_file: Path, api_key: str, hmac_secret: bytes, **overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "telnexa_event_ingress_enabled": False,
        "sms_delivery": False,
        "telnexa_event_synthetic_verify_enabled": True,
        "telnexa_event_api_key": api_key,
        "telnexa_event_api_key_file": "",
        "telnexa_event_hmac_secret": hmac_secret.decode(),
        "telnexa_event_hmac_secret_file": "",
        "telnexa_event_signature_ttl_seconds": 300,
        "telnexa_event_request_max_bytes": 1_048_576,
        "telnexa_event_trusted_proxy_cidrs": TRUSTED_PROXY_CIDR,
        "telnexa_event_client_ca_file": str(ca_file),
        "telnexa_event_client_uri_san": DEFAULT_CLIENT_URI_SAN,
        "telnexa_event_client_cert_sha256": "",
        "telnexa_event_reconcile_max_attempts": 12,
        "telnexa_event_reconcile_batch_size": 100,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


async def run_harness() -> HarnessRun:
    api_key = secrets.token_urlsafe(32)
    hmac_secret = secrets.token_hex(32).encode()
    authority = issue_authority()
    # Same subject as the trusted CA, different key: only the signature differs.
    rogue_authority = issue_authority()
    good = issue_client_leaf(authority)
    now = datetime.now(UTC)
    hostile = {
        "rogue_ca": issue_client_leaf(rogue_authority),
        "wrong_spiffe_id": issue_client_leaf(
            authority, uri_san="spiffe://codestra.internal/provider/klyrow/callback"
        ),
        "expired": issue_client_leaf(
            authority, not_before=now - timedelta(days=3), not_after=now - timedelta(days=1)
        ),
        "server_auth_only": issue_client_leaf(
            authority, extended_usage=(ExtendedKeyUsageOID.SERVER_AUTH,)
        ),
    }
    sentinel = SentinelSession()
    run = HarnessRun()

    async def sentinel_session() -> AsyncIterator[SentinelSession]:
        yield sentinel

    with tempfile.TemporaryDirectory(prefix="telnexa-harness-") as directory:
        ca_file = Path(directory) / "telnexa-client-ca.pem"
        ca_file.write_bytes(authority.pem)
        ca_file.chmod(0o600)

        async def send(
            name: str,
            path: str,
            expected_status: int,
            expected_detail: str | None,
            *,
            event: dict[str, Any] | None = None,
            certificate: str | None = good.der_b64,
            peer: tuple[str, int] = TRUSTED_PROXY_PEER,
            extra_headers: dict[str, str] | None = None,
            mutate: Any = None,
            settings_overrides: dict[str, Any] | None = None,
        ) -> None:
            app = FastAPI()
            app.include_router(router)
            app.dependency_overrides[get_session] = sentinel_session
            app.state.runtime = SimpleNamespace(
                settings=_runtime_settings(
                    ca_file, api_key, hmac_secret, **(settings_overrides or {})
                )
            )
            body, headers = signed_request(
                event or synthetic_event(),
                api_key=api_key,
                hmac_secret=hmac_secret,
                certificate_der_b64=certificate,
            )
            headers.update(extra_headers or {})
            if mutate is not None:
                body, headers = mutate(body, headers)
            transport = httpx.ASGITransport(app=app, client=peer)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://middleware.internal"
            ) as client:
                response = await client.post(path, content=body, headers=headers)
            detail: str | None = None
            try:
                payload = response.json()
                detail = payload.get("detail") if isinstance(payload, dict) else None
            except ValueError:
                detail = None
            case = HarnessCase(name, path, expected_status, expected_detail)
            case.observed_status = response.status_code
            case.observed_detail = detail
            case.passed = response.status_code == expected_status and (
                expected_detail is None or detail == expected_detail
            )
            if case.passed and expected_status == 200:
                payload = response.json()
                case.passed = (
                    payload.get("effect") == "none"
                    and payload.get("persisted") is False
                    and payload["identity"]["certificate_sha256"] == good.sha256
                )
            run.cases.append(case)

        def forged_signature(body: bytes, headers: dict[str, str]) -> tuple[bytes, dict[str, str]]:
            return body, {**headers, "X-Signature": "sha256=" + "0" * 64}

        def rebound_idempotency(body: bytes, headers: dict[str, str]) -> tuple[bytes, dict[str, str]]:
            return body, {**headers, "Idempotency-Key": "synthetic-other-key"}

        await send("verify_accepts_trusted_synthetic", VERIFY_PATH, 200, None)
        await send(
            "verify_accepts_pinned_fingerprint",
            VERIFY_PATH,
            200,
            None,
            settings_overrides={"telnexa_event_client_cert_sha256": good.sha256},
        )
        await send(
            "verify_disabled_by_default",
            VERIFY_PATH,
            503,
            "telnexa_synthetic_verify_disabled",
            settings_overrides={"telnexa_event_synthetic_verify_enabled": False},
        )
        await send(
            "untrusted_peer_rejected",
            VERIFY_PATH,
            403,
            "untrusted_telnexa_callback_peer",
            peer=UNTRUSTED_PEER,
        )
        await send(
            "missing_client_certificate",
            VERIFY_PATH,
            401,
            "telnexa_client_certificate_required",
            certificate=None,
        )
        await send(
            "legacy_certificate_header_rejected",
            VERIFY_PATH,
            401,
            "invalid_telnexa_client_certificate",
            extra_headers={LEGACY_CLIENT_CERT_HEADER: good.der_b64},
        )
        await send(
            "malformed_certificate",
            VERIFY_PATH,
            401,
            "invalid_telnexa_client_certificate",
            certificate="not-base64-der!",
        )
        for name, leaf in hostile.items():
            await send(
                f"{name}_certificate_rejected",
                VERIFY_PATH,
                403,
                "untrusted_telnexa_client_certificate",
                certificate=leaf.der_b64,
            )
        await send(
            "fingerprint_pin_mismatch",
            VERIFY_PATH,
            403,
            "untrusted_telnexa_client_certificate",
            settings_overrides={"telnexa_event_client_cert_sha256": "a" * 64},
        )
        await send(
            "missing_ca_fails_closed",
            VERIFY_PATH,
            503,
            "telnexa_callback_identity_unavailable",
            settings_overrides={"telnexa_event_client_ca_file": "/nonexistent/ca.pem"},
        )
        await send(
            "forged_signature_rejected",
            VERIFY_PATH,
            401,
            "invalid_telnexa_signature",
            mutate=forged_signature,
        )
        await send(
            "wrong_api_key_rejected",
            VERIFY_PATH,
            401,
            "invalid_telnexa_authorization",
            extra_headers={"Authorization": "Bearer wrong-api-key"},
        )
        await send(
            "stale_signature_rejected",
            VERIFY_PATH,
            401,
            "expired_telnexa_signature",
            event=synthetic_event(timestamp=int(time.time()) - 3600),
        )
        await send(
            "header_body_binding_mismatch",
            VERIFY_PATH,
            409,
            "telnexa_header_body_binding_mismatch",
            mutate=rebound_idempotency,
        )
        await send(
            "verify_refuses_non_synthetic_event",
            VERIFY_PATH,
            422,
            "non_synthetic_telnexa_event_rejected",
            event=synthetic_event(event_id=f"delivery-{uuid4().hex}"),
        )
        await send(
            "ingress_disabled_by_default",
            PATH,
            503,
            "telnexa_event_ingress_disabled",
        )
        enabled_ingress = {
            "telnexa_event_ingress_enabled": True,
            "sms_delivery": True,
        }
        await send(
            "ingress_refuses_synthetic_before_database",
            PATH,
            422,
            "synthetic_telnexa_event_rejected",
            settings_overrides=enabled_ingress,
        )
        await send(
            "ingress_refuses_rogue_certificate_before_database",
            PATH,
            403,
            "untrusted_telnexa_client_certificate",
            certificate=hostile["rogue_ca"].der_b64,
            event=synthetic_event(event_id=f"delivery-{uuid4().hex}"),
            settings_overrides=enabled_ingress,
        )
        await send(
            "ingress_refuses_untrusted_peer_before_database",
            PATH,
            403,
            "untrusted_telnexa_callback_peer",
            peer=UNTRUSTED_PEER,
            event=synthetic_event(event_id=f"delivery-{uuid4().hex}"),
            settings_overrides=enabled_ingress,
        )
    run.database_calls = list(sentinel.calls)
    return run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write JSON evidence to this path")
    args = parser.parse_args(argv)
    run = asyncio.run(run_harness())
    evidence = json.dumps(run.as_json(), indent=2, sort_keys=True, default=str)
    if args.output:
        args.output.write_text(evidence + "\n", encoding="utf-8")
    print(evidence)
    return 0 if run.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
