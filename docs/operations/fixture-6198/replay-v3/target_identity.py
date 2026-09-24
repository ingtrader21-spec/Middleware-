"""Fail-closed discovery and verification of the RC4 event gateway."""
from __future__ import annotations

import ipaddress
import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from types import TracebackType
from typing import Callable, Protocol

EXPECTED_CONTAINER = "compose-middleware-event-gateway-1"
EXPECTED_PROJECT = "compose"
EXPECTED_SERVICE = "middleware-event-gateway"
EXPECTED_IMAGE = (
    "codestra/middleware@sha256:"
    "8902cd852ab0b03701b3c5ab6b28d184c6a632e9d9b0deb39b0d5280ed38ed46"
)
EXPECTED_IMAGE_ID = (
    "sha256:8902cd852ab0b03701b3c5ab6b28d184c6a632e9d9b0deb39b0d5280ed38ed46"
)
EXPECTED_NETWORK = "codestra_backend"
EXPECTED_PORT = 8095
LEGACY_CONTAINER = "codestra-middleware-1"
LEGACY_SERVICE = "middleware"
LEGACY_IMAGE_PREFIX = "codestra/middleware:webphone-keycloak-staging-"

HEALTH_BODY = {"status": "ok", "service": EXPECTED_SERVICE}
READY_BODY = {
    "status": "ready",
    "service": EXPECTED_SERVICE,
    "authorization": "online",
    "delivery": "disabled",
}


class IdentityError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class ResponseHeaders(Protocol):
    def get_content_type(self) -> str: ...


class HttpResponse(Protocol):
    status: int
    headers: ResponseHeaders

    def read(self, amount: int) -> bytes: ...

    def __enter__(self) -> HttpResponse: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


HttpOpener = Callable[..., HttpResponse]


@dataclass(frozen=True)
class Target:
    container_id: str
    container_name: str
    image: str
    image_id: str
    project: str
    service: str
    network: str
    address: str
    ingress_url: str

    def redacted_evidence(self) -> dict[str, str]:
        return {
            "container_id": self.container_id,
            "container_name": self.container_name,
            "image": self.image,
            "image_id": self.image_id,
            "project": self.project,
            "service": self.service,
            "network": self.network,
            "internal_address": self.address,
            "health_contract": "healthz+readyz",
        }


def docker(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["docker", *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise IdentityError(f"Docker identity query failed: {type(exc).__name__}") from exc
    return result.stdout


def _one_candidate(run: Callable[[list[str]], str]) -> str:
    values = [
        value for value in run([
            "ps", "--quiet",
            "--filter", f"label=com.docker.compose.project={EXPECTED_PROJECT}",
            "--filter", f"label=com.docker.compose.service={EXPECTED_SERVICE}",
        ]).splitlines()
        if value
    ]
    if len(values) != 1:
        raise IdentityError("exactly one approved event-gateway container is required")
    return values[0]


def discover(run: Callable[[list[str]], str] = docker) -> Target:
    candidate = _one_candidate(run)
    try:
        value = json.loads(run(["inspect", candidate]))
        if not isinstance(value, list) or len(value) != 1:
            raise IdentityError("container inspect result is ambiguous")
        info = value[0]
        labels = info["Config"]["Labels"]
        state = info["State"]
        name = info["Name"].removeprefix("/")
        image = info["Config"]["Image"]
        image_id = info["Image"]
        networks = info["NetworkSettings"]["Networks"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise IdentityError("container identity metadata is invalid") from exc
    if (
        name != EXPECTED_CONTAINER
        or labels.get("com.docker.compose.project") != EXPECTED_PROJECT
        or labels.get("com.docker.compose.service") != EXPECTED_SERVICE
        or labels.get("com.docker.compose.oneoff") != "False"
        or labels.get("com.docker.compose.image") != EXPECTED_IMAGE_ID
    ):
        raise IdentityError("Compose identity mismatch")
    if (
        state.get("Running") is not True
        or state.get("Status") != "running"
        or state.get("Health", {}).get("Status") != "healthy"
    ):
        raise IdentityError("event-gateway container is not healthy and running")
    if image != EXPECTED_IMAGE or image_id != EXPECTED_IMAGE_ID:
        raise IdentityError("approved image digest mismatch")
    if (
        name == LEGACY_CONTAINER
        or labels.get("com.docker.compose.service") == LEGACY_SERVICE
        or image.startswith(LEGACY_IMAGE_PREFIX)
    ):
        raise IdentityError("legacy middleware target is forbidden")
    if EXPECTED_NETWORK not in networks or not networks[EXPECTED_NETWORK].get("IPAddress"):
        raise IdentityError("approved internal network membership is missing")
    try:
        network_values = json.loads(run(["network", "inspect", EXPECTED_NETWORK]))
        if (
            not isinstance(network_values, list)
            or len(network_values) != 1
            or network_values[0].get("Internal") is not True
        ):
            raise IdentityError("approved network is not internal")
        address = ipaddress.ip_address(networks[EXPECTED_NETWORK]["IPAddress"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise IdentityError("internal target address is invalid") from exc
    if not address.is_private or address.is_loopback or address.is_unspecified:
        raise IdentityError("public, loopback, or unspecified targets are forbidden")
    return Target(
        container_id=info["Id"],
        container_name=name,
        image=image,
        image_id=image_id,
        project=EXPECTED_PROJECT,
        service=EXPECTED_SERVICE,
        network=EXPECTED_NETWORK,
        address=str(address),
        ingress_url=f"http://{address}:{EXPECTED_PORT}/api/v1/events/vicidial",
    )


def _strict_get(
    url: str,
    expected: dict[str, str],
    opener: HttpOpener | None = None,
) -> None:
    client = opener or urllib.request.build_opener(NoRedirect()).open
    request = urllib.request.Request(url, method="GET")
    try:
        with client(request, timeout=5) as response:
            if response.status != 200:
                raise IdentityError("identity endpoint returned non-200")
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise IdentityError("identity endpoint is not JSON")
            body = response.read(16384)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise IdentityError("identity endpoint redirect is forbidden") from exc
        raise IdentityError(f"identity endpoint returned HTTP {exc.code}") from exc
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise IdentityError(f"identity endpoint unavailable: {type(exc).__name__}") from exc
    try:
        value = json.loads(body)
    except json.JSONDecodeError as exc:
        raise IdentityError("identity response is invalid JSON") from exc
    if value != expected:
        raise IdentityError("identity response schema mismatch")


def verify_health(target: Target, opener: HttpOpener | None = None) -> None:
    origin = f"http://{target.address}:{EXPECTED_PORT}"
    _strict_get(f"{origin}/healthz", HEALTH_BODY, opener)
    _strict_get(f"{origin}/readyz", READY_BODY, opener)
