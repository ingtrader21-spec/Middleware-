import httpx
import pytest

from app.core.token_manager import ClientSecretTokenManager


@pytest.mark.asyncio
async def test_client_secret_token_manager_uses_mounted_value_and_caches():
    calls = 0

    async def load_secret(reference: str) -> str:
        assert reference == "secret://staging/odoo-results"
        return "x" * 48

    def issue_token(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.url.path == "/token"
        assert b"client_secret=" in request.content
        return httpx.Response(
            200, json={"access_token": "synthetic.jwt", "expires_in": 300}
        )

    manager = ClientSecretTokenManager("middleware-staging", load_secret)
    async with httpx.AsyncClient(transport=httpx.MockTransport(issue_token)) as client:
        first = await manager.get_token(
            client,
            token_url="https://identity.test/token",
            audience="codestra-odoo",
            scopes=("odoo.integration.results.write",),
            credential_reference_id="secret://staging/odoo-results",
        )
        second = await manager.get_token(
            client,
            token_url="https://identity.test/token",
            audience="codestra-odoo",
            scopes=("odoo.integration.results.write",),
            credential_reference_id="secret://staging/odoo-results",
        )
    assert first == second == "synthetic.jwt"
    assert calls == 1
