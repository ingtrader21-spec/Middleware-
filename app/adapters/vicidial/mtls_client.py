from __future__ import annotations

import json
import logging
import socket
import ssl
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from app.core.config import Settings, VICIDIAL_PRIVATE_HOSTS, VICIDIAL_PRIVATE_PORT


LOGGER = logging.getLogger("codestra.vicidial_mtls")
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
CONNECT_TIMEOUT_SECONDS = 3.0
RESPONSE_TIMEOUT_SECONDS = 8.0

APPROVED_ROUTES = frozenset(
    {
        (
            "POST",
            "authorization.internal.codestra.agency",
            "/api/v1/transfers/authorize",
        ),
        ("POST", "edge.internal.codestra.agency", "/v1/transfers/execute"),
        ("POST", "edge.internal.codestra.agency", "/v1/calls/originate"),
        ("POST", "edge.internal.codestra.agency", "/v1/agents/sync"),
        ("POST", "edge.internal.codestra.agency", "/v1/agents/disable"),
        ("POST", "edge.internal.codestra.agency", "/v1/extensions/reserve"),
        ("POST", "edge.internal.codestra.agency", "/v1/extensions/adopt"),
        ("POST", "edge.internal.codestra.agency", "/v1/webrtc/provision"),
        ("POST", "edge.internal.codestra.agency", "/v1/webrtc/rotate"),
        ("POST", "edge.internal.codestra.agency", "/v1/webrtc/revoke"),
    }
)
APPROVED_PRIVATE_IPV4_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
APPROVED_PRIVATE_IPV6_NETWORKS = (IPv6Network("fc00::/7"),)


def _approved_private_address(address: IPv4Address | IPv6Address) -> bool:
    if isinstance(address, IPv4Address):
        return any(address in network for network in APPROVED_PRIVATE_IPV4_NETWORKS)
    return any(address in network for network in APPROVED_PRIVATE_IPV6_NETWORKS)


class VicidialMtlsError(RuntimeError):
    """A secret-safe, fail-closed VICIdial transport error."""


class VicidialMtlsClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport_factory: Callable[[], httpx.BaseTransport] | None = None,
        resolver: Callable[[str], Sequence[str]] | None = None,
    ):
        self._settings = settings
        self._resolver = resolver or self._resolve_addresses
        self._ensure_configured()
        ssl_context = self._build_ssl_context()
        if transport_factory is None:

            def factory() -> httpx.BaseTransport:
                return httpx.HTTPTransport(verify=ssl_context, retries=0)

        else:
            factory = transport_factory
        # A transport pool is scoped to one governed DNS identity. Two names
        # may resolve to one private IP, but must never reuse a TLS connection
        # whose certificate was verified under the other name.
        self._clients = {
            hostname: httpx.Client(
                transport=factory(),
                timeout=httpx.Timeout(
                    connect=CONNECT_TIMEOUT_SECONDS,
                    read=RESPONSE_TIMEOUT_SECONDS,
                    write=RESPONSE_TIMEOUT_SECONDS,
                    pool=CONNECT_TIMEOUT_SECONDS,
                ),
                follow_redirects=False,
                trust_env=False,
            )
            for hostname in sorted(VICIDIAL_PRIVATE_HOSTS)
        }

    def close(self) -> None:
        for client in self._clients.values():
            client.close()

    def __enter__(self) -> VicidialMtlsClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def authorize(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if (
            not self._settings.transfer_control_enabled
            or not self._settings.vicidial_read_enabled
        ):
            raise VicidialMtlsError("VICidial authorization is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_authorization_url}/api/v1/transfers/authorize",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def execute(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if not (
            self._settings.transfer_control_enabled
            and self._settings.vicidial_write_enabled
            and self._settings.live_writes_enabled
        ):
            raise VicidialMtlsError("VICIdial transfer execution is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/transfers/execute",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def originate(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Ask the VICIdial-side edge adapter to place an outbound call.

        Gated by the same triple flag as ``execute`` so a caller cannot
        reach a real dial by only flipping one setting. The caller
        (``app.api.v1.telephony.originate_call``) additionally re-checks
        the same flags plus the default-deny WebRTC production policy
        before this method is ever called, so this is defense-in-depth,
        not the only gate.
        """
        if not (
            self._settings.external_dial_enabled
            and self._settings.vicidial_write_enabled
            and self._settings.live_writes_enabled
        ):
            raise VicidialMtlsError("VICIdial call origination is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/calls/originate",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def sync_agent(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Create or update one agent (Mission 4A create_agent/update_agent).

        Calls the real, general ``POST /v1/agents/sync`` endpoint of the
        Vicidialer-Codestra adapter (``codestra_vicidial.app``), which takes
        an unrestricted ``AgentCommand`` - unlike
        ``/v1/agents/provision-disabled``, which is hard-locked to one
        synthetic break-glass test agent and is deliberately never called
        here. ``payload["agent"]`` must already be shaped like that
        service's ``AgentSpec`` (``user_id`` matching ``^[A-Z]{3}[0-9]{4,12}$``,
        exactly one campaign, ``active: False`` - VICIdial itself always
        provisions disabled, activation is a separate step there).
        """
        if not (self._settings.vicidial_write_enabled and self._settings.live_writes_enabled):
            raise VicidialMtlsError("VICIdial agent sync is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/agents/sync",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def disable_agent(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Disable one agent (Mission 4A disable_agent).

        Calls the real ``POST /v1/agents/disable`` endpoint. ``payload``
        must contain ``context`` and ``user_id`` matching
        ``DisableAgentCommand``.
        """
        if not (self._settings.vicidial_write_enabled and self._settings.live_writes_enabled):
            raise VicidialMtlsError("VICIdial agent disable is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/agents/disable",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def reserve_extension(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Allocate the next free extension from one named pool
        (Mission 6 reserve_extension). ``payload["reservation"]`` must be
        shaped like Vicidialer-Codestra's ``ExtensionReserveSpec``
        (``user_id``, ``pool``). The response's ``actual`` already reflects
        that service's own internal read-back - a distinct GET call is not
        needed, matching how ``sync_agent``/``disable_agent`` work today.
        """
        if not (self._settings.vicidial_write_enabled and self._settings.live_writes_enabled):
            raise VicidialMtlsError("VICIdial extension reservation is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/extensions/reserve",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def adopt_extension(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Bind an already-existing extension (e.g. 6101) without ever
        consuming a pool slot (Mission 6 adopt_extension). Deliberately a
        separate method from reserve_extension, calling a separate route -
        never conflate the two, since adopt must never rotate a
        potentially-live SIP credential (see the Vicidialer-Codestra side
        for the corresponding safety logic).
        """
        if not (self._settings.vicidial_write_enabled and self._settings.live_writes_enabled):
            raise VicidialMtlsError("VICIdial extension adoption is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/extensions/adopt",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def provision_webrtc(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue a short-lived, single-use WebRTC registration credential
        (Mission 6/7). A concurrent second call for the same user returns
        409 WEBRTC_SESSION_ALREADY_ACTIVE from the edge service - callers
        must not treat that as a generic adapter failure."""
        if not (self._settings.vicidial_write_enabled and self._settings.live_writes_enabled):
            raise VicidialMtlsError("VICIdial WebRTC provisioning is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/webrtc/provision",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def rotate_webrtc_secret(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if not (self._settings.vicidial_write_enabled and self._settings.live_writes_enabled):
            raise VicidialMtlsError("VICIdial WebRTC credential rotation is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/webrtc/rotate",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def revoke_webrtc(
        self,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Atomically invalidate the session ticket, credential reference,
        and phone-row SIP secret for one user (Mission 6) - one call, not
        several independently-callable steps that could partially fail."""
        if not (self._settings.vicidial_write_enabled and self._settings.live_writes_enabled):
            raise VicidialMtlsError("VICIdial WebRTC revocation is disabled")
        return self.request(
            "POST",
            f"{self._settings.vicidial_edge_url}/v1/webrtc/revoke",
            payload,
            correlation_id=correlation_id,
            request_id=request_id,
        )

    def request(
        self,
        method: str,
        url: str,
        payload: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        parsed = urlsplit(url)
        route = (method.upper(), parsed.hostname or "", parsed.path)
        if (
            route not in APPROVED_ROUTES
            or parsed.scheme != "https"
            or parsed.port != VICIDIAL_PRIVATE_PORT
            or parsed.hostname not in VICIDIAL_PRIVATE_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise VicidialMtlsError("VICIdial method or route is not approved")
        private_addresses = self._assert_private_resolution(parsed.hostname)
        destination = private_addresses[0]
        destination_host = (
            f"[{destination}]"
            if isinstance(destination, IPv6Address)
            else str(destination)
        )
        pinned_url = f"https://{destination_host}:{VICIDIAL_PRIVATE_PORT}{parsed.path}"

        try:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        except (TypeError, ValueError) as exc:
            raise VicidialMtlsError(
                "VICIdial payload is not JSON serializable"
            ) from exc
        if len(body) > MAX_PAYLOAD_BYTES:
            raise VicidialMtlsError("VICidial payload exceeds the configured limit")

        correlation = correlation_id or str(uuid4())
        request = request_id or str(uuid4())
        LOGGER.info(
            "vicidial_request_started",
            extra={
                "correlation_id": correlation,
                "request_id": request,
                "route": parsed.path,
            },
        )
        try:
            with self._clients[parsed.hostname].stream(
                method.upper(),
                pinned_url,
                content=body,
                headers={
                    "Host": f"{parsed.hostname}:{VICIDIAL_PRIVATE_PORT}",
                    "Content-Type": "application/json",
                    "X-Correlation-ID": correlation,
                    "X-Request-ID": request,
                },
                # Connect to the validated numeric destination without a
                # second DNS lookup, while still authenticating the governed
                # hostname in the peer certificate.
                extensions={"sni_hostname": parsed.hostname},
            ) as response:
                response.raise_for_status()
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise VicidialMtlsError(
                            "VICidial response exceeds the configured limit"
                        )
                    chunks.append(chunk)
        except VicidialMtlsError:
            raise
        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.HTTPStatusError,
        ) as exc:
            LOGGER.warning(
                "vicidial_request_failed",
                extra={
                    "correlation_id": correlation,
                    "request_id": request,
                    "route": parsed.path,
                    "error_type": type(exc).__name__,
                },
            )
            raise VicidialMtlsError("VICidial private request failed closed") from exc

        try:
            decoded = json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VicidialMtlsError("VICidial response is not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise VicidialMtlsError("VICidial response must be a JSON object")
        LOGGER.info(
            "vicidial_request_completed",
            extra={
                "correlation_id": correlation,
                "request_id": request,
                "route": parsed.path,
                "status_code": response.status_code,
            },
        )
        return decoded

    def _ensure_configured(self) -> None:
        if not self._settings.vicidial_mtls_configured:
            raise VicidialMtlsError("VICidial private mTLS is not configured")

    def _build_ssl_context(self) -> ssl.SSLContext:
        ca_file = self._required_file(self._settings.vicidial_ca_file, "CA bundle")
        cert_file = self._required_file(
            self._settings.vicidial_client_cert_file, "client certificate"
        )
        key_file = self._required_file(
            self._settings.vicidial_client_key_file, "client key"
        )
        try:
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=str(ca_file)
            )
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            if self._settings.vicidial_crl_file:
                crl_file = self._required_file(self._settings.vicidial_crl_file, "CRL")
                context.load_verify_locations(cafile=str(crl_file))
                context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
            return context
        except (OSError, ssl.SSLError) as exc:
            raise VicidialMtlsError(
                "VICidial mTLS credentials are invalid or unreadable"
            ) from exc

    @staticmethod
    def _required_file(value: str, label: str) -> Path:
        path = Path(value)
        if not path.is_file():
            raise VicidialMtlsError(f"VICidial {label} is missing")
        return path

    def _assert_private_resolution(
        self, hostname: str
    ) -> tuple[IPv4Address | IPv6Address, ...]:
        try:
            addresses = self._resolver(hostname)
            parsed = [ip_address(address) for address in addresses]
        except (OSError, ValueError) as exc:
            raise VicidialMtlsError(
                "VICidial private DNS resolution failed closed"
            ) from exc
        if not parsed or any(
            not _approved_private_address(address) for address in parsed
        ):
            raise VicidialMtlsError(
                "VICidial hostname did not resolve exclusively to the private IP"
            )
        return tuple(parsed)

    @staticmethod
    def _resolve_addresses(hostname: str) -> list[str]:
        return sorted(
            {
                str(result[4][0])
                for result in socket.getaddrinfo(
                    hostname,
                    VICIDIAL_PRIVATE_PORT,
                    # The HTTP stack may select either address family. Inspect
                    # every A and AAAA destination so a public IPv6 answer
                    # cannot bypass a private-only IPv4 preflight.
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
            }
        )
