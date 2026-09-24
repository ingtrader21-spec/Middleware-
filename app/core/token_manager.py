import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import uuid4

import httpx
import jwt


@dataclass(frozen=True)
class AccessToken:
    value: str
    expires_at: int


class TokenManager:
    def __init__(
        self,
        client_id: str,
        private_key_loader: Callable[[str], Awaitable[str]],
        *,
        refresh_margin_seconds: int = 60,
    ) -> None:
        self.client_id = client_id
        self.private_key_loader = private_key_loader
        self.refresh_margin_seconds = refresh_margin_seconds
        self._tokens: dict[tuple[str, tuple[str, ...]], AccessToken] = {}
        self._lock = asyncio.Lock()

    async def get_token(
        self,
        http: httpx.AsyncClient,
        *,
        token_url: str,
        audience: str,
        scopes: tuple[str, ...],
        credential_reference_id: str,
    ) -> str:
        key = (audience, scopes)
        now = int(time.time())
        cached = self._tokens.get(key)
        if cached and cached.expires_at - self.refresh_margin_seconds > now:
            return cached.value
        async with self._lock:
            cached = self._tokens.get(key)
            if cached and cached.expires_at - self.refresh_margin_seconds > now:
                return cached.value
            private_key = await self.private_key_loader(credential_reference_id)
            assertion = jwt.encode(
                {
                    "iss": self.client_id,
                    "sub": self.client_id,
                    "aud": token_url,
                    "iat": now,
                    "exp": now + 300,
                    "jti": str(uuid4()),
                },
                private_key,
                algorithm="RS256",
            )
            response = await http.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": assertion,
                    "audience": audience,
                    "scope": " ".join(scopes),
                },
            )
            response.raise_for_status()
            body = response.json()
            token = AccessToken(
                value=str(body["access_token"]),
                expires_at=now + min(int(body.get("expires_in", 300)), 300),
            )
            self._tokens[key] = token
            return token.value


class ClientSecretTokenManager:
    """Short-lived client-credentials tokens backed by a mounted secret file."""

    def __init__(
        self,
        client_id: str,
        client_secret_loader: Callable[[str], Awaitable[str]],
        *,
        refresh_margin_seconds: int = 60,
    ) -> None:
        self.client_id = client_id
        self.client_secret_loader = client_secret_loader
        self.refresh_margin_seconds = refresh_margin_seconds
        self._tokens: dict[tuple[str, tuple[str, ...]], AccessToken] = {}
        self._lock = asyncio.Lock()

    async def get_token(
        self,
        http: httpx.AsyncClient,
        *,
        token_url: str,
        audience: str,
        scopes: tuple[str, ...],
        credential_reference_id: str,
    ) -> str:
        key = (audience, scopes)
        now = int(time.time())
        cached = self._tokens.get(key)
        if cached and cached.expires_at - self.refresh_margin_seconds > now:
            return cached.value
        async with self._lock:
            cached = self._tokens.get(key)
            if cached and cached.expires_at - self.refresh_margin_seconds > now:
                return cached.value
            secret = await self.client_secret_loader(credential_reference_id)
            response = await http.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": secret,
                    "audience": audience,
                    "scope": " ".join(scopes),
                },
            )
            response.raise_for_status()
            body = response.json()
            token = AccessToken(
                value=str(body["access_token"]),
                expires_at=now + min(int(body.get("expires_in", 300)), 300),
            )
            self._tokens[key] = token
            return token.value
