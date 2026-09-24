import hashlib
import hmac
import json
import logging
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from redis.exceptions import RedisError
from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db.models import (
    IntegrationEndpoint,
    IntegrationEndpointVersion,
    IntegrationCredentialReference,
    IntegrationRouteBinding,
    IntegrationSchemaVersion,
    IntegrationService,
)


class ResolutionDenied(RuntimeError):
    def __init__(self, reason: str, *, retryable: bool = False) -> None:
        self.reason = reason
        self.retryable = retryable
        super().__init__(f"ENDPOINT_RESOLUTION=DENIED REASON={reason}")


class RegistryDependencyUnavailable(RuntimeError):
    pass


logger = logging.getLogger("endpoint_registry")


@dataclass(frozen=True)
class ResolutionRequest:
    environment: str
    service_key: str
    endpoint_key: str
    api_version: str = "v1"
    organization_public_id: str = ""
    business_unit_public_id: str = ""
    campaign_public_id: str = ""
    workflow_key: str = ""
    event_type: str = ""
    mutation: bool = False

    def cache_hash(self) -> str:
        canonical = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class ResolvedEndpoint:
    endpoint_id: str
    endpoint_version_id: str
    service_key: str
    endpoint_key: str
    api_version: str
    method: str
    base_url: str
    path: str
    authentication_profile: str
    required_audience: str
    required_scopes: tuple[str, ...]
    credential_reference_id: str
    tls_profile_id: str
    timeout_ms: int
    connection_timeout_ms: int
    redirects_allowed: bool
    target_attestation_required: bool
    stale_read_safe: bool
    configuration_version: int
    configuration_checksum: str
    effective_at: str
    expires_at: str | None
    registry_generation: int


class EndpointRepository(Protocol):
    async def candidates(
        self, request: ResolutionRequest
    ) -> list[ResolvedEndpoint]: ...


class SnapshotCache(Protocol):
    async def get(
        self, request: ResolutionRequest, *, allow_stale: bool
    ) -> ResolvedEndpoint | None: ...

    async def put(
        self, request: ResolutionRequest, endpoint: ResolvedEndpoint
    ) -> None: ...


def precedence_score(
    binding: IntegrationRouteBinding, request: ResolutionRequest
) -> int:
    scopes = (
        (binding.organization_scope, request.organization_public_id),
        (binding.business_unit_scope, request.business_unit_public_id),
        (binding.campaign_scope, request.campaign_public_id),
        (binding.workflow_scope, request.workflow_key),
        (binding.event_type_scope, request.event_type),
    )
    if any(expected and expected != actual for expected, actual in scopes):
        return -1
    present: tuple[bool, bool, bool, bool, bool] = (
        bool(binding.organization_scope),
        bool(binding.business_unit_scope),
        bool(binding.campaign_scope),
        bool(binding.workflow_scope),
        bool(binding.event_type_scope),
    )
    allowed = {
        (True, True, True, True, True): 5,
        (True, True, True, False, False): 4,
        (True, True, False, False, False): 3,
        (True, False, False, False, False): 2,
        (False, False, False, False, False): 1,
    }
    return allowed.get(present, -1)


class SqlEndpointRepository:
    def __init__(self, session: AsyncSession, generation: int = 0) -> None:
        self.session = session
        self.generation = generation

    async def candidates(self, request: ResolutionRequest) -> list[ResolvedEndpoint]:
        now = datetime.now(UTC)
        statement = (
            select(
                IntegrationService,
                IntegrationEndpoint,
                IntegrationEndpointVersion,
                IntegrationRouteBinding,
            )
            .join(
                IntegrationEndpoint,
                IntegrationEndpoint.service_id == IntegrationService.service_id,
            )
            .join(
                IntegrationEndpointVersion,
                IntegrationEndpointVersion.endpoint_id
                == IntegrationEndpoint.endpoint_id,
            )
            .join(
                IntegrationRouteBinding,
                IntegrationRouteBinding.endpoint_version_id
                == IntegrationEndpointVersion.endpoint_version_id,
            )
            .join(
                IntegrationCredentialReference,
                IntegrationCredentialReference.reference_key
                == IntegrationEndpointVersion.credential_reference_id,
            )
            .join(
                IntegrationSchemaVersion,
                (IntegrationSchemaVersion.service_key == IntegrationService.service_key)
                & (
                    IntegrationSchemaVersion.endpoint_key
                    == IntegrationEndpoint.endpoint_key
                )
                & (
                    IntegrationSchemaVersion.api_version
                    == IntegrationEndpoint.api_version
                ),
            )
            .where(
                and_(
                    IntegrationService.service_key == request.service_key,
                    IntegrationService.enabled.is_(True),
                    IntegrationCredentialReference.enabled.is_(True),
                    IntegrationSchemaVersion.enabled.is_(True),
                    IntegrationEndpoint.endpoint_key == request.endpoint_key,
                    IntegrationEndpoint.api_version == request.api_version,
                    IntegrationRouteBinding.environment == request.environment,
                    IntegrationEndpointVersion.enabled.is_(True),
                    IntegrationEndpointVersion.kill_switch.is_(False),
                    IntegrationEndpointVersion.effective_at <= now,
                    (
                        IntegrationEndpointVersion.expires_at.is_(None)
                        | (IntegrationEndpointVersion.expires_at > now)
                    ),
                )
            )
        )
        try:
            rows = (await self.session.execute(statement)).all()
        except SQLAlchemyError as exc:
            raise RegistryDependencyUnavailable from exc
        ranked = sorted(
            (
                (precedence_score(binding, request), service, endpoint, version)
                for service, endpoint, version, binding in rows
            ),
            key=lambda item: item[0],
            reverse=True,
        )
        valid = [row for row in ranked if row[0] > 0]
        if not valid:
            return []
        best_score = valid[0][0]
        best = [row for row in valid if row[0] == best_score]
        if len(best) != 1:
            raise ResolutionDenied("AMBIGUOUS_ACTIVE_ROUTE")
        _, service, endpoint, version = best[0]
        return [
            ResolvedEndpoint(
                endpoint_id=str(endpoint.endpoint_id),
                endpoint_version_id=str(version.endpoint_version_id),
                service_key=service.service_key,
                endpoint_key=endpoint.endpoint_key,
                api_version=endpoint.api_version,
                method=version.http_method,
                base_url=version.base_url,
                path=version.path_template,
                authentication_profile=version.authentication_mode,
                required_audience=version.required_audience,
                required_scopes=tuple(version.required_scopes),
                credential_reference_id=version.credential_reference_id,
                tls_profile_id=version.tls_profile_id,
                timeout_ms=version.timeout_ms,
                connection_timeout_ms=version.connection_timeout_ms,
                redirects_allowed=version.redirects_allowed,
                target_attestation_required=version.target_attestation_required,
                stale_read_safe=version.stale_read_safe,
                configuration_version=version.configuration_version,
                configuration_checksum=version.configuration_checksum,
                effective_at=version.effective_at.isoformat(),
                expires_at=version.expires_at.isoformat()
                if version.expires_at
                else None,
                registry_generation=self.generation,
            )
        ]


class SessionEndpointRepository:
    """Resolve routes with a short independently managed database session."""

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], generation: int = 0
    ) -> None:
        self.session_factory = session_factory
        self.generation = generation

    async def candidates(self, request: ResolutionRequest) -> list[ResolvedEndpoint]:
        async with self.session_factory() as session:
            return await SqlEndpointRepository(
                session, generation=self.generation
            ).candidates(request)


@dataclass
class _L1Entry:
    endpoint: ResolvedEndpoint
    expires_monotonic: float
    stale_until_monotonic: float


class SignedSnapshotCache:
    def __init__(
        self,
        redis: Any,
        signing_key: bytes,
        *,
        l1_ttl_seconds: int = 15,
        l2_ttl_seconds: int = 60,
        stale_grace_seconds: int = 300,
        max_entries: int = 512,
    ) -> None:
        if not signing_key:
            raise ValueError("registry snapshot signing key is required")
        self.redis = redis
        self.signing_key = signing_key
        self.l1_ttl_seconds = l1_ttl_seconds
        self.l2_ttl_seconds = l2_ttl_seconds
        self.stale_grace_seconds = stale_grace_seconds
        self.max_entries = max_entries
        self._l1: OrderedDict[str, _L1Entry] = OrderedDict()

    def _key(self, request: ResolutionRequest, generation: int) -> str:
        return f"registry:{request.environment}:{generation}:{request.cache_hash()}"

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self.signing_key, payload, hashlib.sha256).hexdigest()

    async def get(
        self, request: ResolutionRequest, *, allow_stale: bool
    ) -> ResolvedEndpoint | None:
        now = time.monotonic()
        request_hash = request.cache_hash()
        entry = self._l1.get(request_hash)
        if entry and (
            now <= entry.expires_monotonic
            or (
                allow_stale
                and entry.endpoint.stale_read_safe
                and now <= entry.stale_until_monotonic
            )
        ):
            self._l1.move_to_end(request_hash)
            return entry.endpoint
        if entry:
            self._l1.pop(request_hash, None)
        return None

    async def get_l2(
        self, request: ResolutionRequest, generation: int
    ) -> ResolvedEndpoint | None:
        raw = await self.redis.get(self._key(request, generation))
        if not raw:
            return None
        envelope = json.loads(raw)
        payload = json.dumps(
            envelope["resolved_endpoint"], sort_keys=True, separators=(",", ":")
        ).encode()
        if not hmac.compare_digest(envelope["signature"], self._sign(payload)):
            raise ResolutionDenied("INVALID_SNAPSHOT_SIGNATURE")
        endpoint = ResolvedEndpoint(
            **{
                **envelope["resolved_endpoint"],
                "required_scopes": tuple(
                    envelope["resolved_endpoint"]["required_scopes"]
                ),
            }
        )
        await self._put_l1(request, endpoint)
        return endpoint

    async def put(self, request: ResolutionRequest, endpoint: ResolvedEndpoint) -> None:
        payload_dict = asdict(endpoint)
        payload = json.dumps(
            payload_dict, sort_keys=True, separators=(",", ":")
        ).encode()
        envelope = json.dumps(
            {"resolved_endpoint": payload_dict, "signature": self._sign(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
        await self.redis.setex(
            self._key(request, endpoint.registry_generation),
            self.l2_ttl_seconds,
            envelope,
        )
        await self._put_l1(request, endpoint)

    async def _put_l1(
        self, request: ResolutionRequest, endpoint: ResolvedEndpoint
    ) -> None:
        now = time.monotonic()
        self._l1[request.cache_hash()] = _L1Entry(
            endpoint=endpoint,
            expires_monotonic=now + self.l1_ttl_seconds,
            stale_until_monotonic=now + self.l1_ttl_seconds + self.stale_grace_seconds,
        )
        self._l1.move_to_end(request.cache_hash())
        while len(self._l1) > self.max_entries:
            self._l1.popitem(last=False)


class RegistryResolver:
    def __init__(
        self,
        repository: EndpointRepository,
        cache: SignedSnapshotCache,
        *,
        generation: int = 0,
    ) -> None:
        self.repository = repository
        self.cache = cache
        self.generation = generation

    async def resolve(self, request: ResolutionRequest) -> ResolvedEndpoint:
        cached = await self.cache.get(request, allow_stale=False)
        if cached:
            return cached
        try:
            candidates = await self.repository.candidates(request)
        except ResolutionDenied:
            raise
        except RegistryDependencyUnavailable:
            candidates = []
            try:
                cached_l2 = await self.cache.get_l2(request, self.generation)
            except (RedisError, json.JSONDecodeError, KeyError, TypeError):
                cached_l2 = None
            if cached_l2:
                return cached_l2
            stale = await self.cache.get(request, allow_stale=not request.mutation)
            if stale:
                return stale
            raise ResolutionDenied("ENDPOINT_REGISTRY_UNAVAILABLE", retryable=True)
        if not candidates:
            raise ResolutionDenied("NO_ACTIVE_ROUTE")
        endpoint = candidates[0]
        try:
            await self.cache.put(request, endpoint)
        except RedisError as exc:
            logger.warning(
                "registry L2 cache population failed: %s", type(exc).__name__
            )
        return endpoint
