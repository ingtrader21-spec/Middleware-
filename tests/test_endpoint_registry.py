from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.core.endpoint_registry import (
    RegistryDependencyUnavailable,
    RegistryResolver,
    ResolutionDenied,
    ResolutionRequest,
    ResolvedEndpoint,
    precedence_score,
)


def binding(**values):
    defaults = {
        "organization_scope": "",
        "business_unit_scope": "",
        "campaign_scope": "",
        "workflow_scope": "",
        "event_type_scope": "",
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def endpoint(stale_read_safe: bool = False) -> ResolvedEndpoint:
    now = datetime.now(UTC).isoformat()
    return ResolvedEndpoint(
        endpoint_id="endpoint",
        endpoint_version_id="version",
        service_key="n8n",
        endpoint_key="events.ingest",
        api_version="v1",
        method="POST",
        base_url="https://example.invalid",
        path="/events",
        authentication_profile="private_key_jwt",
        required_audience="n8n",
        required_scopes=("events.write",),
        credential_reference_id="secret://test/key",
        tls_profile_id="test",
        timeout_ms=1000,
        connection_timeout_ms=500,
        redirects_allowed=False,
        target_attestation_required=True,
        stale_read_safe=stale_read_safe,
        configuration_version=1,
        configuration_checksum="sha256:" + "0" * 64,
        effective_at=now,
        expires_at=None,
        registry_generation=1,
    )


def test_five_tier_precedence_is_explicit():
    request = ResolutionRequest(
        environment="production",
        service_key="n8n",
        endpoint_key="events.ingest",
        organization_public_id="ORG",
        business_unit_public_id="BU",
        campaign_public_id="CMP",
        workflow_key="WF",
        event_type="EVENT",
    )
    assert precedence_score(binding(), request) == 1
    assert precedence_score(binding(organization_scope="ORG"), request) == 2
    assert (
        precedence_score(
            binding(organization_scope="ORG", business_unit_scope="BU"), request
        )
        == 3
    )
    assert (
        precedence_score(
            binding(
                organization_scope="ORG",
                business_unit_scope="BU",
                campaign_scope="CMP",
            ),
            request,
        )
        == 4
    )
    assert (
        precedence_score(
            binding(
                organization_scope="ORG",
                business_unit_scope="BU",
                campaign_scope="CMP",
                workflow_scope="WF",
                event_type_scope="EVENT",
            ),
            request,
        )
        == 5
    )
    assert precedence_score(binding(campaign_scope="OTHER"), request) == -1


class Repo:
    def __init__(self, result=None, error: Exception | None = None):
        self.result = result or []
        self.error = error

    async def candidates(self, request):
        if self.error:
            raise self.error
        return self.result


class Cache:
    def __init__(self, fresh=None, l2=None, stale=None):
        self.fresh = fresh
        self.l2 = l2
        self.stale = stale
        self.put_value = None

    async def get(self, request, *, allow_stale):
        return self.stale if allow_stale else self.fresh

    async def get_l2(self, request, generation):
        return self.l2

    async def put(self, request, value):
        self.put_value = value


@pytest.mark.asyncio
async def test_authoritative_result_populates_cache():
    value = endpoint()
    cache = Cache()
    resolver = RegistryResolver(Repo([value]), cache)
    assert (
        await resolver.resolve(ResolutionRequest("production", "n8n", "events.ingest"))
        == value
    )
    assert cache.put_value == value


@pytest.mark.asyncio
async def test_no_route_fails_without_hidden_fallback():
    resolver = RegistryResolver(Repo([]), Cache())
    with pytest.raises(ResolutionDenied, match="NO_ACTIVE_ROUTE"):
        await resolver.resolve(ResolutionRequest("production", "n8n", "events.ingest"))


@pytest.mark.asyncio
async def test_mutation_denies_expired_cache_when_dependencies_fail():
    resolver = RegistryResolver(
        Repo(error=RegistryDependencyUnavailable("database unavailable")),
        Cache(stale=endpoint(stale_read_safe=True)),
    )
    with pytest.raises(ResolutionDenied, match="ENDPOINT_REGISTRY_UNAVAILABLE"):
        await resolver.resolve(
            ResolutionRequest("production", "n8n", "events.ingest", mutation=True)
        )


@pytest.mark.asyncio
async def test_stale_safe_read_is_bounded_fallback():
    value = endpoint(stale_read_safe=True)
    resolver = RegistryResolver(
        Repo(error=RegistryDependencyUnavailable("database unavailable")),
        Cache(stale=value),
    )
    assert (
        await resolver.resolve(ResolutionRequest("production", "n8n", "events.ingest"))
        == value
    )
