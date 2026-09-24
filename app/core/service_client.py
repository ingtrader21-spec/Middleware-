import hashlib
import json
import ssl
import time
from typing import Any
from uuid import uuid4

import httpx

from app.core.endpoint_registry import (
    RegistryResolver,
    ResolutionRequest,
    ResolvedEndpoint,
)
from app.core.token_manager import ClientSecretTokenManager, TokenManager


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class CommonServiceClient:
    def __init__(
        self,
        resolver: RegistryResolver,
        token_manager: TokenManager | ClientSecretTokenManager,
        *,
        token_endpoint_key: ResolutionRequest,
        transport: httpx.AsyncBaseTransport | None = None,
        verify: ssl.SSLContext | str | bool = True,
    ) -> None:
        self.resolver = resolver
        self.token_manager = token_manager
        self.token_endpoint_key = token_endpoint_key
        self.http = httpx.AsyncClient(
            follow_redirects=False,
            transport=transport,
            verify=verify,
            trust_env=False,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )

    async def aclose(self) -> None:
        await self.http.aclose()

    async def request(
        self,
        route_request: ResolutionRequest,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        request_id: str,
        correlation_id: str,
        causation_id: str,
        traceparent: str,
        tracestate: str = "",
    ) -> httpx.Response:
        if route_request.mutation and not idempotency_key:
            raise ValueError("mutation requires durable idempotency key")
        route = await self.resolver.resolve(route_request)
        return await self.request_resolved(
            route,
            payload,
            idempotency_key=idempotency_key,
            request_id=request_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            traceparent=traceparent,
            tracestate=tracestate,
        )

    async def request_resolved(
        self,
        route: ResolvedEndpoint,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        request_id: str,
        correlation_id: str,
        causation_id: str,
        traceparent: str,
        tracestate: str = "",
    ) -> httpx.Response:
        if route.method not in {"GET", "HEAD"} and not idempotency_key:
            raise ValueError("mutation requires durable idempotency key")
        token_route = await self.resolver.resolve(self.token_endpoint_key)
        token_url = f"{token_route.base_url.rstrip('/')}/{token_route.path.lstrip('/')}"
        access_token = await self.token_manager.get_token(
            self.http,
            token_url=token_url,
            audience=route.required_audience,
            scopes=route.required_scopes,
            credential_reference_id=route.credential_reference_id,
        )
        body = canonical_json(payload)
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
            "X-Codestra-Request-ID": request_id,
            "X-Codestra-Correlation-ID": correlation_id,
            "X-Codestra-Causation-ID": causation_id,
            "X-Codestra-Timestamp": str(int(time.time())),
            "X-Codestra-Nonce": str(uuid4()),
            "X-Codestra-Body-SHA256": hashlib.sha256(body).hexdigest(),
            "traceparent": traceparent,
        }
        if tracestate:
            headers["tracestate"] = tracestate
        url = f"{route.base_url.rstrip('/')}/{route.path.lstrip('/')}"
        response = await self.http.request(
            route.method,
            url,
            content=body,
            headers=headers,
            timeout=httpx.Timeout(
                route.timeout_ms / 1000,
                connect=route.connection_timeout_ms / 1000,
            ),
        )
        if response.is_redirect:
            raise RuntimeError("redirect rejected for internal service route")
        return response
