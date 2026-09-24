from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict

AUTH_PATH = "/internal/api/v1/ai/auth/verify"
SCOPE = "ai.auth.verify/read-only"
SERVICE_ID_HEADER = "X-Service-ID"
HMAC_KEY_ID_HEADER = "X-HMAC-Key-ID"
TIMESTAMP_HEADER = "X-Timestamp"
NONCE_HEADER = "X-Nonce"
BODY_DIGEST_HEADER = "X-Body-SHA256"
SIGNATURE_HEADER = "X-Signature"
CORRELATION_HEADER = "X-Correlation-ID"
REQUEST_ID_HEADER = "X-Request-ID"
WORKER_ID_HEADER = "X-Worker-ID"
SIGNATURE_VERSION_HEADER = "X-Signature-Version"
CLIENT_CERT_DER_HEADER = "X-Codestra-Client-Certificate-DER"
LEGACY_CLIENT_CERT_HEADER = "X-Codestra-Client-Certificate"
MAX_CERTIFICATE_DER_BASE64_BYTES = 16_384

HEX_64 = re.compile(r"[0-9a-f]{64}")
DECIMAL_TIMESTAMP = re.compile(r"[0-9]{10,11}")
SAFE_NONCE = re.compile(r"[A-Za-z0-9._~-]{16,128}")
SAFE_CORRELATION = re.compile(r"[A-Za-z0-9._:-]{8,128}")
UTC = timezone.utc


def _ipv4_address(value: str) -> ipaddress.IPv4Address:
    parsed = ipaddress.ip_address(value)
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise RuntimeError("Qwen verifier IP SAN must be IPv4")
    return parsed


def _ipv4_network(value: str) -> ipaddress.IPv4Network:
    parsed = ipaddress.ip_network(value, strict=True)
    if not isinstance(parsed, ipaddress.IPv4Network):
        raise RuntimeError("Qwen trusted proxy network must be IPv4")
    return parsed


@dataclass(frozen=True)
class IdentityConfig:
    service_id: str
    hmac_key_id: str
    hmac_secret_file: Path
    certificate_serial: int
    certificate_uri_san: str
    certificate_ip_san: ipaddress.IPv4Address


@dataclass(frozen=True)
class VerifierConfig:
    service_id: str
    hmac_key_id: str
    hmac_secret_file: Path
    client_ca_file: Path
    certificate_serial: int
    certificate_uri_san: str
    certificate_ip_san: ipaddress.IPv4Address
    replay_directory: Path
    trusted_proxy_network: ipaddress.IPv4Network
    allowed_clock_skew_seconds: int = 300
    additional_identities: tuple[IdentityConfig, ...] = ()

    def identities(self) -> tuple[IdentityConfig, ...]:
        return (
            IdentityConfig(
                self.service_id,
                self.hmac_key_id,
                self.hmac_secret_file,
                self.certificate_serial,
                self.certificate_uri_san,
                self.certificate_ip_san,
            ),
            *self.additional_identities,
        )

    @classmethod
    def from_environment(cls) -> VerifierConfig:
        required = {
            "QWEN_SERVICE_ID": os.getenv("QWEN_SERVICE_ID", ""),
            "QWEN_HMAC_KEY_ID": os.getenv("QWEN_HMAC_KEY_ID", ""),
            "QWEN_HMAC_SECRET_FILE": os.getenv("QWEN_HMAC_SECRET_FILE", ""),
            "QWEN_CLIENT_CA_FILE": os.getenv("QWEN_CLIENT_CA_FILE", ""),
            "QWEN_CERTIFICATE_SERIAL": os.getenv("QWEN_CERTIFICATE_SERIAL", ""),
            "QWEN_CERTIFICATE_URI_SAN": os.getenv("QWEN_CERTIFICATE_URI_SAN", ""),
            "QWEN_CERTIFICATE_IP_SAN": os.getenv("QWEN_CERTIFICATE_IP_SAN", ""),
            "QWEN_REPLAY_DIRECTORY": os.getenv("QWEN_REPLAY_DIRECTORY", ""),
            "QWEN_TRUSTED_PROXY_CIDR": os.getenv("QWEN_TRUSTED_PROXY_CIDR", ""),
        }
        if not all(required.values()):
            raise RuntimeError("Qwen verifier configuration is incomplete")
        skew = int(os.getenv("QWEN_ALLOWED_CLOCK_SKEW_SECONDS", "300"))
        if skew < 1 or skew > 300:
            raise RuntimeError("Qwen verifier clock skew is outside policy")
        additional: tuple[IdentityConfig, ...] = ()
        registry_value = os.getenv("QWEN_IDENTITY_REGISTRY_FILE", "")
        if registry_value:
            registry = Path(registry_value)
            if (
                not registry.is_absolute()
                or registry.is_symlink()
                or not registry.is_file()
                or registry.stat().st_mode & 0o077
            ):
                raise RuntimeError("Qwen identity registry is unavailable")
            try:
                document = json.loads(registry.read_text())
                rows = document["identities"]
                additional = tuple(
                    IdentityConfig(
                        service_id=row["service_id"],
                        hmac_key_id=row["hmac_key_id"],
                        hmac_secret_file=Path(row["hmac_secret_file"]),
                        certificate_serial=int(row["certificate_serial"]),
                        certificate_uri_san=row["certificate_uri_san"],
                        certificate_ip_san=_ipv4_address(row["certificate_ip_san"]),
                    )
                    for row in rows
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("Qwen identity registry is invalid") from exc
        return cls(
            service_id=required["QWEN_SERVICE_ID"],
            hmac_key_id=required["QWEN_HMAC_KEY_ID"],
            hmac_secret_file=Path(required["QWEN_HMAC_SECRET_FILE"]),
            client_ca_file=Path(required["QWEN_CLIENT_CA_FILE"]),
            certificate_serial=int(required["QWEN_CERTIFICATE_SERIAL"]),
            certificate_uri_san=required["QWEN_CERTIFICATE_URI_SAN"],
            certificate_ip_san=_ipv4_address(required["QWEN_CERTIFICATE_IP_SAN"]),
            replay_directory=Path(required["QWEN_REPLAY_DIRECTORY"]),
            trusted_proxy_network=_ipv4_network(required["QWEN_TRUSTED_PROXY_CIDR"]),
            allowed_clock_skew_seconds=skew,
            additional_identities=additional,
        )


class VerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authentication_status: str
    correlation_id: str
    server_timestamp: str


def canonical_signing_string(
    method: str,
    path: str,
    service_id: str,
    timestamp: str,
    nonce: str,
    body_digest: str,
) -> bytes:
    return (
        f"{method}\n{path}\n{service_id}\n{timestamp}\n{nonce}\n{body_digest}".encode(
            "ascii"
        )
    )


def canonical_signing_string_v2(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_digest: str,
    request_id: str,
    correlation_id: str,
    worker_id: str,
    tenant_id: str = "",
    workspace_id: str = "",
) -> bytes:
    fields: tuple[str, ...] = (
        method,
        path,
        timestamp,
        nonce,
        body_digest,
        request_id,
        correlation_id,
        worker_id,
    )
    if tenant_id or workspace_id:
        fields += (tenant_id, workspace_id)
    return "\n".join(fields).encode("ascii")


def _load_secret(identity: IdentityConfig) -> bytes:
    path = identity.hmac_secret_file
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise HTTPException(503, "authentication verifier unavailable")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise HTTPException(503, "authentication verifier unavailable")
    secret = path.read_bytes().strip()
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", secret):
        raise HTTPException(503, "authentication verifier unavailable")
    return secret


def _verified_certificate(
    encoded_certificate: str, config: VerifierConfig, identity: IdentityConfig
) -> None:
    try:
        if (
            not encoded_certificate
            or len(encoded_certificate) > MAX_CERTIFICATE_DER_BASE64_BYTES
        ):
            raise ValueError("certificate size")
        der = base64.b64decode(encoded_certificate, validate=True)
        if not der or len(der) > 12_288:
            raise ValueError("certificate size")
        certificate = x509.load_der_x509_certificate(der)
        if certificate.public_bytes(Encoding.DER) != der:
            raise ValueError("certificate encoding")
        if certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME) != [
            x509.NameAttribute(NameOID.COMMON_NAME, identity.service_id)
        ]:
            raise ValueError("service identity")
        if (
            not config.client_ca_file.is_absolute()
            or config.client_ca_file.is_symlink()
            or not config.client_ca_file.is_file()
        ):
            raise ValueError("CA")
        authority = x509.load_pem_x509_certificate(config.client_ca_file.read_bytes())
        certificate.verify_directly_issued_by(authority)
        now = datetime.now(UTC)
        if certificate.serial_number != identity.certificate_serial:
            raise ValueError("serial")
        if not (
            certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        ):
            raise ValueError("validity")
        uris = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        if uris != [identity.certificate_uri_san]:
            raise ValueError("uri")
        addresses = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.IPAddress)
        if addresses != [identity.certificate_ip_san]:
            raise ValueError("ip")
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError("key usage")
        extended = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in extended:
            raise ValueError("extended key usage")
    except (
        InvalidSignature,
        ValueError,
        UnicodeError,
        binascii.Error,
        x509.ExtensionNotFound,
    ) as exc:
        raise HTTPException(401, "authentication denied") from exc


def _claim_nonce(config: VerifierConfig, service_id: str, nonce: str) -> None:
    directory = config.replay_directory
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise HTTPException(503, "authentication verifier unavailable")
    digest = hashlib.sha256(f"{service_id}\n{nonce}".encode("ascii")).hexdigest()
    marker = directory / digest
    try:
        descriptor = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as exc:
        raise HTTPException(409, "replay detected") from exc
    try:
        os.write(descriptor, b"claimed\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def create_app(config: VerifierConfig | None = None) -> FastAPI:
    verifier = config or VerifierConfig.from_environment()
    app = FastAPI(
        title="Codestra Qwen Authentication Verifier",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
    )

    @app.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readiness() -> dict[str, str]:
        try:
            for identity in verifier.identities():
                _load_secret(identity)
            if not os.access(verifier.replay_directory, os.W_OK):
                raise OSError
        except (HTTPException, OSError):
            raise HTTPException(503, "authentication verifier unavailable") from None
        return {"status": "ready"}

    @app.post(AUTH_PATH, response_model=VerificationResponse)
    async def verify_authentication(
        request: Request,
        x_service_id: str = Header(alias=SERVICE_ID_HEADER),
        x_hmac_key_id: str = Header(alias=HMAC_KEY_ID_HEADER),
        x_timestamp: str = Header(alias=TIMESTAMP_HEADER),
        x_nonce: str = Header(alias=NONCE_HEADER),
        x_body_sha256: str = Header(alias=BODY_DIGEST_HEADER),
        x_signature: str = Header(alias=SIGNATURE_HEADER),
        x_correlation_id: str = Header(alias=CORRELATION_HEADER),
        x_request_id: str | None = Header(default=None, alias=REQUEST_ID_HEADER),
        x_worker_id: str | None = Header(default=None, alias=WORKER_ID_HEADER),
        x_signature_version: str = Header(default="v1", alias=SIGNATURE_VERSION_HEADER),
        x_client_certificate_der: str = Header(alias=CLIENT_CERT_DER_HEADER),
        legacy_client_certificate: str | None = Header(
            default=None, alias=LEGACY_CLIENT_CERT_HEADER
        ),
    ) -> VerificationResponse:
        try:
            peer = ipaddress.ip_address(request.client.host if request.client else "")
        except ValueError as exc:
            raise HTTPException(401, "authentication denied") from exc
        if peer not in verifier.trusted_proxy_network:
            raise HTTPException(401, "authentication denied")
        if legacy_client_certificate is not None:
            raise HTTPException(401, "authentication denied")
        identity = next(
            (
                item
                for item in verifier.identities()
                if item.service_id == x_service_id and item.hmac_key_id == x_hmac_key_id
            ),
            None,
        )
        if identity is None:
            raise HTTPException(401, "authentication denied")
        _verified_certificate(x_client_certificate_der, verifier, identity)
        if not DECIMAL_TIMESTAMP.fullmatch(x_timestamp):
            raise HTTPException(401, "authentication denied")
        timestamp = int(x_timestamp)
        now = int(time.time())
        if abs(now - timestamp) > verifier.allowed_clock_skew_seconds:
            raise HTTPException(401, "authentication denied")
        if not SAFE_NONCE.fullmatch(x_nonce):
            raise HTTPException(401, "authentication denied")
        if not SAFE_CORRELATION.fullmatch(x_correlation_id):
            raise HTTPException(400, "invalid correlation ID")
        if not HEX_64.fullmatch(x_body_sha256) or not HEX_64.fullmatch(x_signature):
            raise HTTPException(401, "authentication denied")
        body = await request.body()
        computed_digest = hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(computed_digest, x_body_sha256):
            raise HTTPException(401, "authentication denied")
        if x_signature_version == "v1":
            canonical = canonical_signing_string(
                request.method,
                request.url.path,
                x_service_id,
                x_timestamp,
                x_nonce,
                x_body_sha256,
            )
        elif x_signature_version == "v2":
            if (
                not x_request_id
                or not x_worker_id
                or not SAFE_CORRELATION.fullmatch(x_request_id)
            ):
                raise HTTPException(401, "authentication denied")
            if not SAFE_CORRELATION.fullmatch(x_worker_id):
                raise HTTPException(401, "authentication denied")
            canonical = canonical_signing_string_v2(
                request.method,
                request.url.path,
                x_timestamp,
                x_nonce,
                x_body_sha256,
                x_request_id,
                x_correlation_id,
                x_worker_id,
            )
        else:
            raise HTTPException(401, "authentication denied")
        expected = hmac.new(
            _load_secret(identity), canonical, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, x_signature):
            raise HTTPException(401, "authentication denied")
        _claim_nonce(verifier, x_service_id, x_nonce)
        return VerificationResponse(
            authentication_status="authenticated",
            correlation_id=x_correlation_id,
            server_timestamp=datetime.now(UTC).isoformat(),
        )

    return app
