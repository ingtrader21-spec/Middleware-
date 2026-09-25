"""Private mTLS identity contract for Telnexa delivery callbacks.

The internal Middleware edge terminates Telnexa's mutual TLS session and
forwards the verified leaf certificate as base64 DER in
``X-Codestra-Client-Certificate-DER``.  The application does not trust the edge
blindly: the forwarding peer must sit in an allow-listed proxy network, and
the forwarded leaf is re-verified against the pinned Telnexa client CA, its
validity window, the exact SPIFFE URI SAN, client-auth usage and (optionally)
an exact SHA-256 fingerprint allow-list.  Every failure is fail-closed.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi import HTTPException, Request


CLIENT_CERT_DER_HEADER = "X-Codestra-Client-Certificate-DER"
LEGACY_CLIENT_CERT_HEADER = "X-Codestra-Client-Certificate"
DEFAULT_CLIENT_URI_SAN = "spiffe://codestra.internal/provider/telnexa/callback"
MAX_CERTIFICATE_DER_BASE64_BYTES = 16_384
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
LOGGER = logging.getLogger(__name__)

CLIENT_CERTIFICATE_HEADER_CONTRACT = {
    "name": CLIENT_CERT_DER_HEADER,
    "in": "header",
    "required": True,
    "schema": {
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_CERTIFICATE_DER_BASE64_BYTES,
    },
    "description": (
        "Base64 DER of the Telnexa mTLS client leaf, forwarded only by the "
        "allow-listed internal edge and re-verified against the pinned CA, "
        "URI SAN and fingerprint allow-list."
    ),
}


@dataclass(frozen=True)
class TelnexaCallbackTrustConfig:
    trusted_proxy_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    client_ca_file: Path
    client_uri_san: str
    pinned_certificate_sha256: frozenset[str]


@dataclass(frozen=True)
class TelnexaCallbackIdentity:
    """The verified caller identity; safe to persist as evidence."""

    certificate_sha256: str
    certificate_serial: str
    uri_san: str
    not_valid_after: datetime

    def evidence(self) -> dict[str, str]:
        return {
            "certificateSha256": self.certificate_sha256,
            "certificateSerial": self.certificate_serial,
            "uriSan": self.uri_san,
            "notValidAfter": self.not_valid_after.isoformat(),
        }


def parse_trusted_proxy_networks(
    value: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = tuple(
        ipaddress.ip_network(item.strip(), strict=True)
        for item in value.split(",")
        if item.strip()
    )
    if not networks:
        raise ValueError("at least one trusted proxy network is required")
    for network in networks:
        if not network.is_private or network.num_addresses > 256:
            raise ValueError("trusted proxy networks must be small private ranges")
    return networks


def parse_pinned_fingerprints(value: str) -> frozenset[str]:
    pins = frozenset(item.strip().lower() for item in value.split(",") if item.strip())
    if any(not SHA256_HEX.fullmatch(pin) for pin in pins):
        raise ValueError("pinned certificate fingerprints must be lowercase sha256 hex")
    return pins


def validate_client_uri_san(value: str) -> str:
    if not re.fullmatch(r"spiffe://[a-z0-9.-]+(/[A-Za-z0-9._-]+)+", value):
        raise ValueError("Telnexa client URI SAN must be an exact SPIFFE ID")
    return value


def trust_config(
    *,
    trusted_proxy_cidrs: object,
    client_ca_file: object,
    client_uri_san: object,
    pinned_certificate_sha256: object,
) -> TelnexaCallbackTrustConfig:
    """Build the trust contract or raise 503; configuration is never guessed."""

    try:
        networks = parse_trusted_proxy_networks(str(trusted_proxy_cidrs or ""))
        ca_file = Path(str(client_ca_file or ""))
        if not str(client_ca_file or "") or not ca_file.is_absolute():
            raise ValueError("Telnexa client CA must be an absolute path")
        uri_san = validate_client_uri_san(str(client_uri_san or ""))
        pins = parse_pinned_fingerprints(str(pinned_certificate_sha256 or ""))
    except ValueError as exc:
        raise HTTPException(503, "telnexa_callback_identity_unavailable") from exc
    return TelnexaCallbackTrustConfig(networks, ca_file, uri_san, pins)


def _load_authority(path: Path) -> x509.Certificate:
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("CA file is not a regular file")
        authority = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "telnexa_callback_identity_unavailable") from exc
    try:
        constraints = authority.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise HTTPException(503, "telnexa_callback_identity_unavailable") from exc
    if not constraints.ca:
        raise HTTPException(503, "telnexa_callback_identity_unavailable")
    return authority


def _header_values(request: Request, name: str) -> list[str]:
    raw_name = name.lower().encode("ascii")
    return [
        value.decode("latin-1")
        for key, value in request.scope.get("headers", [])
        if key == raw_name
    ]


def _reject(detail: str, reason: str, status_code: int = 403) -> HTTPException:
    LOGGER.warning("telnexa callback identity rejected: %s", reason)
    return HTTPException(status_code, detail)


def verify_callback_identity(
    request: Request,
    config: TelnexaCallbackTrustConfig,
    *,
    now: datetime | None = None,
) -> TelnexaCallbackIdentity:
    """Verify the forwarding peer and the forwarded client certificate."""

    client = request.scope.get("client")
    try:
        peer = ipaddress.ip_address(client[0] if client else "")
    except ValueError as exc:
        raise _reject("untrusted_telnexa_callback_peer", "peer address") from exc
    if not any(peer in network for network in config.trusted_proxy_networks):
        raise _reject("untrusted_telnexa_callback_peer", "peer not in proxy networks")

    if _header_values(request, LEGACY_CLIENT_CERT_HEADER):
        raise _reject(
            "invalid_telnexa_client_certificate", "legacy certificate header", 401
        )
    values = _header_values(request, CLIENT_CERT_DER_HEADER)
    if not values or not values[0]:
        raise _reject(
            "telnexa_client_certificate_required", "certificate header missing", 401
        )
    if len(values) != 1 or len(values[0]) > MAX_CERTIFICATE_DER_BASE64_BYTES:
        raise _reject(
            "invalid_telnexa_client_certificate", "certificate header shape", 401
        )
    try:
        certificate = x509.load_der_x509_certificate(
            base64.b64decode(values[0], validate=True)
        )
    except (ValueError, binascii.Error) as exc:
        raise _reject(
            "invalid_telnexa_client_certificate", "certificate encoding", 401
        ) from exc

    authority = _load_authority(config.client_ca_file)
    moment = now or datetime.now(UTC)
    try:
        certificate.verify_directly_issued_by(authority)
        if not (
            certificate.not_valid_before_utc <= moment <= certificate.not_valid_after_utc
        ):
            raise ValueError("validity window")
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if constraints.ca:
            raise ValueError("CA certificate presented as client leaf")
        uris = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        if uris != [config.client_uri_san]:
            raise ValueError("URI SAN")
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError("key usage")
        extended = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in extended:
            raise ValueError("client auth usage")
    except (
        InvalidSignature,
        UnsupportedAlgorithm,
        TypeError,
        ValueError,
        x509.ExtensionNotFound,
    ) as exc:
        raise _reject("untrusted_telnexa_client_certificate", str(exc)) from exc

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    if config.pinned_certificate_sha256 and not any(
        hmac.compare_digest(fingerprint, pin)
        for pin in sorted(config.pinned_certificate_sha256)
    ):
        raise _reject("untrusted_telnexa_client_certificate", "fingerprint pin")
    return TelnexaCallbackIdentity(
        certificate_sha256=fingerprint,
        certificate_serial=format(certificate.serial_number, "x"),
        uri_san=config.client_uri_san,
        not_valid_after=certificate.not_valid_after_utc,
    )
