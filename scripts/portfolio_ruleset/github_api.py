from __future__ import annotations

from typing import TYPE_CHECKING

import dataclasses
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping

if TYPE_CHECKING:
    from scripts.portfolio_ruleset.common import API_VERSION, RolloutError, TOKEN_ENV, require
else:
    from portfolio_ruleset.common import API_VERSION, RolloutError, TOKEN_ENV, require


@dataclasses.dataclass(frozen=True)
class Response:
    status: int
    payload: Any
    headers: Mapping[str, str]


class FailClosedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward a repository-administration token through a redirect."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(FailClosedRedirectHandler())


class GitHubApi:
    def __init__(self, token: str) -> None:
        require(bool(token), f"{TOKEN_ENV} is required")
        self._token = token
        self.base = "https://api.github.com"

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Any | None = None,
        expected: Iterable[int] = (200,),
        retries: int = 3,
    ) -> Response:
        require(path.startswith("/"), "GitHub API path must start with /")
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        expected_set = set(expected)
        last_error: Exception | None = None
        for attempt in range(retries):
            request = urllib.request.Request(
                f"{self.base}{path}",
                data=body,
                method=method,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "User-Agent": "codestra-portfolio-production-ruleset",
                    "X-GitHub-Api-Version": API_VERSION,
                },
            )
            try:
                with NO_REDIRECT_OPENER.open(request, timeout=45) as response:
                    raw = response.read()
                    value = json.loads(raw.decode()) if raw else None
                    result = Response(
                        status=response.status,
                        payload=value,
                        headers=dict(response.headers.items()),
                    )
                require(
                    result.status in expected_set,
                    f"GitHub API {method} {path} returned {result.status}; expected {sorted(expected_set)}",
                )
                return result
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode(errors="replace")[:1600]
                last_error = RolloutError(
                    f"GitHub API {method} {path} returned {exc.code}: {raw}"
                )
                if exc.code not in {429, 500, 502, 503, 504} or attempt + 1 >= retries:
                    raise last_error from exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = RolloutError(f"GitHub API unavailable for {method} {path}")
                if attempt + 1 >= retries:
                    raise last_error from exc
            time.sleep(2**attempt)
        raise RolloutError(str(last_error or "GitHub API request failed"))

    def list_owned_repositories(self, owner: str) -> list[dict[str, Any]]:
        repositories: list[dict[str, Any]] = []
        page = 1
        while True:
            query = urllib.parse.urlencode(
                {
                    "affiliation": "owner",
                    "direction": "asc",
                    "page": page,
                    "per_page": 100,
                    "sort": "full_name",
                    "visibility": "all",
                }
            )
            payload = self.request("GET", f"/user/repos?{query}").payload
            require(isinstance(payload, list), "owned repository response is invalid")
            for repository in payload:
                if not isinstance(repository, dict):
                    continue
                repository_owner = repository.get("owner")
                if isinstance(repository_owner, dict) and repository_owner.get("login") == owner:
                    repositories.append(repository)
            if len(payload) < 100:
                break
            page += 1
        return repositories

    @staticmethod
    def _repo_path(full_name: str) -> str:
        return urllib.parse.quote(full_name, safe="/")

    def list_rulesets(self, full_name: str) -> list[dict[str, Any]]:
        payload = self.request(
            "GET",
            f"/repos/{self._repo_path(full_name)}/rulesets?per_page=100&includes_parents=false",
        ).payload
        require(isinstance(payload, list), f"{full_name}: ruleset list is invalid")
        return [item for item in payload if isinstance(item, dict)]

    def get_ruleset(self, full_name: str, ruleset_id: int) -> dict[str, Any]:
        payload = self.request(
            "GET",
            f"/repos/{self._repo_path(full_name)}/rulesets/{ruleset_id}?includes_parents=false",
        ).payload
        require(isinstance(payload, dict), f"{full_name}: ruleset detail is invalid")
        return payload

    def upsert_ruleset(
        self, full_name: str, desired: Mapping[str, Any], existing: dict[str, Any] | None
    ) -> tuple[int, str]:
        path = f"/repos/{self._repo_path(full_name)}/rulesets"
        if existing:
            ruleset_id = existing.get("id")
            require(isinstance(ruleset_id, int), f"{full_name}: ruleset ID is invalid")
            payload = self.request(
                "PUT", f"{path}/{ruleset_id}", payload=desired, expected=(200,)
            ).payload
            action = "updated"
        else:
            payload = self.request("POST", path, payload=desired, expected=(201,)).payload
            action = "created"
        require(isinstance(payload, dict), f"{full_name}: mutation response is invalid")
        ruleset_id = payload.get("id")
        require(isinstance(ruleset_id, int), f"{full_name}: applied ruleset ID is invalid")
        return ruleset_id, action
