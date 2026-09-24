"""Short-lived OAuth2 service tokens loaded from protected credential references."""

from pathlib import Path
from typing import Any

import httpx


class ServiceTokenError(RuntimeError):
    pass


async def client_credentials_token(
    *,
    token_url: str,
    client_id: str,
    client_secret_file: str,
    audience: str,
    scope: str,
    client: httpx.AsyncClient,
) -> str:
    path = Path(client_secret_file)
    if not path.is_absolute() or not path.is_file():
        raise ServiceTokenError("protected credential reference is unavailable")
    secret = path.read_text(encoding="utf-8").strip()
    if not secret:
        raise ServiceTokenError("protected credential reference is empty")
    response = await client.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
            "audience": audience,
            "scope": scope,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if response.status_code != 200 or response.is_redirect:
        raise ServiceTokenError("service token request rejected")
    try:
        document: dict[str, Any] = response.json()
    except ValueError as exc:
        raise ServiceTokenError("service token response is invalid") from exc
    token = document.get("access_token")
    if not isinstance(token, str) or not token:
        raise ServiceTokenError("service token response omitted access_token")
    return token
