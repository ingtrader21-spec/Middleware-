from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx
from jsonschema import Draft202012Validator, FormatChecker

from app.core.config import ConfigurationError, Settings
from .temporal_workflows import ActivityResult, CommandExecutionRequest


ROOT = Path(__file__).resolve().parents[1]
POSTLY_SOCIAL_COMMAND_SCHEMA = (
    ROOT / "contracts" / "postly-social-command.v1.schema.json"
)


class PostlySocialAdapterError(RuntimeError):
    """A deterministic rejection. Retrying an identical command cannot help."""


class PostlySocialUnknownOutcomeError(RuntimeError):
    """The publication may or may not have gone out, and cannot be resolved.

    This must never be retried automatically. Re-submitting would risk a second
    public post on a real social account, which is not reversible by Middleware.
    A human has to inspect the account and reconcile the operation.
    """


@lru_cache(maxsize=1)
def _postly_social_command_validator() -> Draft202012Validator:
    try:
        source = json.loads(POSTLY_SOCIAL_COMMAND_SCHEMA.read_text(encoding="utf-8"))
        specialization = source["allOf"][1]
        local_schema = {**specialization, "$defs": source.get("$defs", {})}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, IndexError) as exc:
        raise PostlySocialAdapterError(
            "canonical Postly social command schema cannot be loaded"
        ) from exc
    Draft202012Validator.check_schema(local_schema)
    return Draft202012Validator(local_schema, format_checker=FormatChecker())


class PostlySocialAdapter:
    """Publish-once transport from the durable command plane to Postly (Postiz).

    Postly's public API is weaker than the other provider contracts in this
    repository, and the adapter is shaped around that rather than pretending
    otherwise:

    * it has **no idempotency key**, so a re-submission publishes a second post;
    * its listing route filters only by date range, so there is no lookup by a
      Middleware identifier.

    The one correlation handle it does offer is ``posts[].group``, an optional
    caller-supplied string that ``GET /public/v1/posts`` returns. This adapter
    sets ``group`` to the command id and reads back by scanning a bounded date
    window for it.

    Outcome discipline therefore differs from the SMS and email adapters:

    * the publication is submitted **exactly once** and is never re-submitted,
      not even to reconcile;
    * an interrupted or ambiguous submission is resolved only by the read-back
      scan. If the scan finds the group, the outcome is known. If it does not,
      the adapter raises :class:`PostlySocialUnknownOutcomeError`, which is
      mapped to a non-retryable failure so the operation lands in
      ``reconciliation_required`` for a human.

    Middleware holds no social network credentials. Connected accounts, tokens
    and per-network publishing rules stay on the Postly side.
    """

    COMMAND_TYPE = "social.publication.publish.v1"
    TARGET = "postly-social"
    CAPABILITY = "SOCIAL_PUBLISH"
    PUBLISH_PATH = "/public/v1/posts"
    LIST_PATH = "/public/v1/posts"

    ACCEPTED_STATUSES = frozenset({200, 201, 202})
    # Postly reports publication progress with these states; anything else
    # (error, draft) does not prove the post reached the network.
    PUBLISHED_STATES = frozenset({"QUEUE", "PUBLISHED"})
    # How far either side of the command's schedule to scan when reading back.
    READBACK_WINDOW = timedelta(days=2)

    FORBIDDEN_PAYLOAD_KEYS = frozenset(
        {
            "access_token",
            "client_secret",
            "password",
            "private_key",
            "provider_token",
            "refresh_token",
        }
    )

    def __init__(
        self,
        settings: Settings,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.settings = settings
        self.env = os.environ if env is None else env

    def _required(self, name: str) -> str:
        value = self.env.get(name, "").strip()
        if not value:
            raise ConfigurationError(
                f"{name} is required for the Postly social adapter"
            )
        return value

    def _base_url(self) -> str:
        value = self._required("POSTLY_SOCIAL_BASE_URL").rstrip("/")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("POSTLY_SOCIAL_BASE_URL must be an HTTP(S) origin")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ConfigurationError(
                "POSTLY_SOCIAL_BASE_URL must not contain credentials, query, or fragment"
            )
        if self.settings.app_env == "production" and parsed.scheme != "https":
            raise ConfigurationError("production social publishing requires HTTPS")
        return value

    def _api_key(self) -> str:
        return self._required("POSTLY_SOCIAL_API_KEY")

    def _headers(self, request: CommandExecutionRequest) -> dict[str, str]:
        # Postly's public middleware reads a bare API key from Authorization;
        # it is not a Bearer token.
        return {
            "Accept": "application/json",
            "Authorization": self._api_key(),
            "Content-Type": "application/json",
            "X-Tenant-ID": request.tenant_id,
            "X-Correlation-ID": request.correlation_id,
        }

    def _validate_identity(self, request: CommandExecutionRequest) -> None:
        if request.target != self.TARGET:
            raise PostlySocialAdapterError(
                "Postly social adapter does not own this command target"
            )
        if request.capability != self.CAPABILITY:
            raise PostlySocialAdapterError(
                "Postly social command capability must be SOCIAL_PUBLISH"
            )
        if request.command_type != self.COMMAND_TYPE:
            raise PostlySocialAdapterError(
                f"unsupported Postly social command type: {request.command_type}"
            )
        if request.command_version != "1.0":
            raise PostlySocialAdapterError(
                "Postly social command version must be 1.0"
            )

    def _validate_payload(self, request: CommandExecutionRequest) -> dict[str, Any]:
        self._validate_identity(request)
        leaked = sorted(self.FORBIDDEN_PAYLOAD_KEYS.intersection(request.payload))
        if leaked:
            raise PostlySocialAdapterError(
                "command payload carries forbidden secret keys: " + ", ".join(leaked)
            )
        error = next(
            iter(
                _postly_social_command_validator().iter_errors(
                    {
                        "command_id": request.command_id,
                        "command_type": request.command_type,
                        "command_version": request.command_version,
                        "target": request.target,
                        "tenant_id": request.tenant_id,
                        "requested_by": request.requested_by,
                        "correlation_id": request.correlation_id,
                        "idempotency_key": request.idempotency_key,
                        "capability": request.capability,
                        "payload": request.payload,
                    }
                )
            ),
            None,
        )
        if error is not None:
            raise PostlySocialAdapterError(
                "Postly social command violates its canonical contract: "
                f"{error.message}"
            )
        return request.payload

    def _require_active(self, request: CommandExecutionRequest) -> dict[str, Any]:
        payload = self._validate_payload(request)
        if not self.settings.social_publishing_enabled:
            raise PostlySocialAdapterError(
                "social publishing is disabled by SOCIAL_DELIVERY_ENABLED or its "
                "umbrella switch SOCIAL_PUBLISHING_ENABLED"
            )
        return payload

    def _publication_document(
        self,
        request: CommandExecutionRequest,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        content = payload["content"]
        scheduled_at = payload.get("scheduled_at")
        return {
            # `group` is the only caller-supplied field Postly echoes back on
            # its listing route, so it carries the command identity.
            "type": "schedule" if scheduled_at else "now",
            "date": scheduled_at,
            "order": "",
            "shortLink": False,
            "tags": [],
            "posts": [
                {
                    "group": request.command_id,
                    "integration": {"id": payload["account_reference"]},
                    "value": [
                        {
                            "content": content["text"],
                            "image": [
                                {"path": url}
                                for url in content.get("media_urls", []) or []
                            ],
                        }
                    ],
                }
            ],
        }

    def _readback_window(self, payload: dict[str, Any]) -> tuple[str, str]:
        anchor = datetime.now(timezone.utc)
        scheduled_at = payload.get("scheduled_at")
        if isinstance(scheduled_at, str) and scheduled_at:
            try:
                anchor = datetime.fromisoformat(scheduled_at.replace("Z", "+00:00"))
            except ValueError:
                pass
        start = (anchor - self.READBACK_WINDOW).isoformat()
        end = (anchor + self.READBACK_WINDOW).isoformat()
        return start, end

    async def execute(self, request: CommandExecutionRequest) -> ActivityResult:
        payload = self._require_active(request)
        body = self._publication_document(request, payload)
        url = self._base_url() + self.PUBLISH_PATH
        headers = self._headers(request)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(25.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(url, json=body, headers=headers)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # The connection never opened, so nothing was published. This is the
            # only social failure that is safe to retry.
            raise PostlySocialAdapterError(
                "Postly connection failed before the publication was sent"
            ) from exc
        except httpx.HTTPError as exc:
            return await self._resolve_unknown(request, payload, reason=str(exc))

        if response.status_code in self.ACCEPTED_STATUSES:
            return ActivityResult(
                status="accepted",
                detail="Postly accepted the social publication",
                provider_operation_id=self._post_id(response) or request.command_id,
            )
        if response.status_code >= 500:
            return await self._resolve_unknown(
                request, payload, reason=f"gateway status {response.status_code}"
            )
        raise PostlySocialAdapterError(
            "Postly rejected the publication with status "
            f"{response.status_code}: {self._error_message(response)}"
        )

    async def _resolve_unknown(
        self,
        request: CommandExecutionRequest,
        payload: dict[str, Any],
        *,
        reason: str,
    ) -> ActivityResult:
        """Resolve an ambiguous publish by reading back. Never by re-publishing."""
        try:
            reconciled = await self.readback(request)
        except PostlySocialAdapterError as exc:
            raise PostlySocialUnknownOutcomeError(
                f"Postly outcome unknown ({reason}) and the read-back failed: {exc}"
            ) from exc
        if reconciled.status == "matched":
            return ActivityResult(
                status="accepted",
                detail=(
                    f"Postly write was interrupted ({reason}); the read-back "
                    "found the publication, so it landed exactly once"
                ),
                provider_operation_id=reconciled.provider_operation_id,
                readback_evidence=reconciled.readback_evidence,
            )
        raise PostlySocialUnknownOutcomeError(
            f"Postly outcome unknown ({reason}) and the read-back did not find "
            "the publication. Postly has no idempotency key, so this must not be "
            "retried automatically: inspect the connected account and reconcile."
        )

    @staticmethod
    def _error_message(response: httpx.Response) -> str:
        try:
            payload = response.json()
        except ValueError:
            return "unparseable-response"
        if isinstance(payload, dict):
            for key in ("msg", "message", "error", "detail"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return value
        return "unspecified"

    @staticmethod
    def _post_id(response: httpx.Response) -> str | None:
        try:
            value = response.json()
        except ValueError:
            return None
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, dict):
            for key in ("postId", "id"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate:
                    return candidate
        return None

    async def readback(self, request: CommandExecutionRequest) -> ActivityResult:
        """Scan a bounded date window for the post carrying this command's group.

        Postly exposes no lookup by caller reference, so this lists the window
        and matches on ``group``. It never re-submits the publication.
        """
        payload = self._validate_payload(request)
        start, end = self._readback_window(payload)
        url = self._base_url() + self.LIST_PATH
        headers = self._headers(request)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.get(
                    url,
                    params={"startDate": start, "endDate": end},
                    headers=headers,
                )
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise PostlySocialAdapterError(
                "Postly publication read-back failed"
            ) from exc

        posts = value.get("posts") if isinstance(value, dict) else None
        if not isinstance(posts, list):
            raise PostlySocialAdapterError(
                "Postly publication read-back is malformed"
            )
        for post in posts:
            if not isinstance(post, dict) or post.get("group") != request.command_id:
                continue
            integration = post.get("integration")
            account = (
                integration.get("id") if isinstance(integration, dict) else None
            )
            if account != payload["account_reference"]:
                return ActivityResult(
                    status="mismatch",
                    detail=(
                        "Postly read-back found the publication on a different "
                        "connected account than the command intended"
                    ),
                    provider_operation_id=str(post.get("id") or request.command_id),
                )
            state = str(post.get("state") or "").upper()
            if state not in self.PUBLISHED_STATES:
                return ActivityResult(
                    status="mismatch",
                    detail=(
                        f"Postly read-back found the publication in state {state}, "
                        "which does not prove it reached the network"
                    ),
                    provider_operation_id=str(post.get("id") or request.command_id),
                )
            return ActivityResult(
                status="matched",
                detail="Postly read-back matched the social publication intent",
                provider_operation_id=str(post.get("id") or request.command_id),
                readback_evidence={
                    "schema_version": "1.0",
                    "post_id": str(post.get("id") or ""),
                    "publication_state": state,
                    "account_reference": payload["account_reference"],
                    "release_url": str(post.get("releaseURL") or ""),
                },
            )
        return ActivityResult(
            status="mismatch",
            detail=(
                "Postly read-back did not find a publication carrying this "
                "command's group in the scanned window"
            ),
            provider_operation_id=request.command_id,
        )
