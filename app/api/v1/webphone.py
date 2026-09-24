"""Fail-closed browser facade for the isolated endpoint-6101 staging gate."""

from __future__ import annotations

from typing import cast

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4
from urllib.parse import quote, urlencode, urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request, WebSocket
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.core.providers import get_http_client, get_provisioning_http_client
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs


router = APIRouter(prefix="/webphone-api/v1", tags=["webphone-staging"])
logger = logging.getLogger(__name__)
EXPECTED_ORIGIN = f"{settings.webphone_origin_scheme}://{settings.webphone_origin_host}"
EXPECTED_USER = settings.webphone_expected_user
CAMPAIGN = settings.webphone_staging_campaign
ENDPOINT = settings.webphone_staging_endpoint
TTL_SECONDS = 300


class ProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    campaign_id: str = Field(min_length=1, max_length=20, pattern=r"^[A-Za-z0-9_-]+$")
    endpoint: str = Field(pattern=r"^[0-9]{4}$")
    browser_session_id: str


class SessionAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    browser_session_binding: str


@dataclass(frozen=True)
class BrowserIdentity:
    subject: str
    employee_id: str
    odoo_employee_id: str
    vicidial_username: str
    role: str
    campaigns: frozenset[str]
    endpoint: int | None
    tenant_id: str
    business_unit_id: str
    agent_id: str


@dataclass(frozen=True)
class Session:
    session_id: str
    credential_id: str
    binding_id: str
    user: str
    expires_at: datetime


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._user_session: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def reserve(self, session: Session) -> None:
        async with self._lock:
            self.purge()
            prior = self._user_session.get(session.user)
            if prior and prior in self._sessions:
                raise HTTPException(409, "staging user already has an active session")
            self._sessions[session.session_id] = session
            self._user_session[session.user] = session.session_id

    async def consume(self, session_id: str, user: str) -> Session:
        async with self._lock:
            self.purge()
            value = self._sessions.pop(session_id, None)
            if value is None or value.user != user:
                raise HTTPException(404, "session not found")
            self._user_session.pop(user, None)
            return value

    async def restore(self, session: Session) -> None:
        async with self._lock:
            self._sessions[session.session_id] = session
            self._user_session[session.user] = session.session_id

    def purge(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [
            key for key, value in self._sessions.items() if value.expires_at <= now
        ]
        for key in expired:
            value = self._sessions.pop(key)
            self._user_session.pop(value.user, None)


SESSIONS = SessionRegistry()


def _attribute(attributes: dict, name: str) -> str | None:
    value = attributes.get(name)
    if isinstance(value, list):
        value = value[0] if value else None
    return value if isinstance(value, str) and value else None


async def _keycloak_user(subject: str, client: httpx.AsyncClient) -> dict:
    secret_path = Path(settings.provisioning_service_client_secret_file)
    try:
        secret = secret_path.read_text().strip()
    except OSError as exc:
        raise HTTPException(503, "identity service unavailable") from exc
    try:
        token_response = await client.post(
            settings.provisioning_service_token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.provisioning_service_client_id,
                "client_secret": secret,
            },
            timeout=8,
        )
        token_response.raise_for_status()
        service_token = token_response.json()["access_token"]
        user_response = await client.get(
            settings.keycloak_userinfo_url.format(subject=subject),
            headers={"Authorization": f"Bearer {service_token}"},
            timeout=8,
        )
        user_response.raise_for_status()
        user = user_response.json()
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise HTTPException(503, "identity service unavailable") from exc
    if not isinstance(user, dict):
        raise HTTPException(503, "identity service unavailable")
    return user


async def _odoo_identity(
    employee_id: str, client: httpx.AsyncClient, campaign_id: str | None = None, endpoint: int | None = None
) -> dict:
    if (
        not settings.odoo_identity_lookup_url
        or not settings.odoo_identity_lookup_hmac_file
    ):
        raise HTTPException(503, "identity service unavailable")
    try:
        secret = Path(settings.odoo_identity_lookup_hmac_file).read_text().strip()
    except OSError as exc:
        raise HTTPException(503, "identity service unavailable") from exc
    query = {
        key: value
        for key, value in {
            "campaign_id": campaign_id,
            "endpoint": str(endpoint) if endpoint is not None else None,
        }.items()
        if value is not None
    }
    url = (
        f"{settings.odoo_identity_lookup_url.rstrip('/')}/{quote(employee_id, safe='')}"
    )
    if query:
        url += "?" + urlencode(query)
    parts = urlsplit(url)
    canonical = str(int(time.time())) + "." + parts.path
    if parts.query:
        canonical += "?" + parts.query
    timestamp = canonical.split(".", 1)[0]
    signature = hmac.new(
        secret.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    try:
        response = await client.get(
            url,
            headers={
                "X-Codestra-Identity-Timestamp": timestamp,
                "X-Codestra-Identity-Signature": f"sha256={signature}",
            },
            timeout=8,
        )
        if response.status_code >= 400:
            raise HTTPException(
                response.status_code if response.status_code in {401, 403} else 503,
                "employee identity not authorized",
            )
        payload = response.json()
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(503, "identity service unavailable") from exc
    if not isinstance(payload, dict):
        raise HTTPException(503, "invalid identity response")
    return payload


async def browser_identity(
    request: Request | WebSocket,
    campaign_id: str | None = None,
    requested_endpoint: int | None = None,
) -> BrowserIdentity:
    if not settings.webphone_staging_provisioning_enabled:
        raise HTTPException(503, "staging provisioning disabled")
    if settings.webphone_keycloak_enabled:
        origin_ok = request.headers.get("origin") == EXPECTED_ORIGIN
        if getattr(request, "method", "GET") == "GET" and not origin_ok:
            referer = request.headers.get("referer", "")
            referer_parts = urlsplit(referer)
            origin_ok = request.headers.get("sec-fetch-site") == "same-origin" and (
                not referer
                or (
                    referer_parts.scheme == "https"
                    and referer_parts.netloc == urlsplit(EXPECTED_ORIGIN).netloc
                )
            )
        if (
            not origin_ok
            or request.headers.get("x-forwarded-proto") != "https"
            or request.headers.get("sec-fetch-site") != "same-origin"
        ):
            raise HTTPException(403, "webphone origin rejected")
        authorization = request.headers.get("authorization", "")
        forwarded_id_token = request.headers.get("x-forwarded-id-token", "")
        forwarded_access_token = request.headers.get(
            "x-forwarded-access-token", ""
        ) or request.headers.get("x-auth-request-access-token", "")
        try:
            if forwarded_id_token.strip():
                scheme, separator, token = "Bearer", " ", forwarded_id_token
            elif forwarded_access_token.strip():
                scheme, separator, token = "Bearer", " ", forwarded_access_token
            else:
                scheme, separator, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not separator or not token.strip():
                raise JWTAuthError("bearer authorization required")
            validator = KeycloakValidator(**identity_validator_kwargs(settings.identity))
            claims = validator.validate(token.strip())
            if claims.get("typ") not in {"ID", "Bearer"}:
                raise JWTAuthError("browser identity token required")
            logger.info(
                "webphone_identity_token_validated",
                extra={
                    "token_type": claims.get("typ"),
                    "subject_present": isinstance(claims.get("sub"), str),
                    "authorized_party": claims.get("azp"),
                    "audience": claims.get("aud"),
                },
            )
            logger.warning(
                "webphone_identity_token_shape keys=%s subject_type=%s subject_present=%s source=%s",
                sorted(str(key) for key in claims.keys()),
                type(claims.get("sub")).__name__,
                bool(claims.get("sub")),
                "id-forwarded"
                if forwarded_id_token.strip()
                else (
                    "forwarded" if forwarded_access_token.strip() else "authorization"
                ),
            )
        except JWTAuthError as exc:
            raise HTTPException(401, "identity token rejected") from exc
        roles = set(claims.get("realm_access", {}).get("roles", []))
        roles.update(claims.get("roles", []))
        if not roles.intersection(
            {"codestra_agent", "codestra_closer", "codestra_supervisor"}
        ):
            raise HTTPException(403, "agent role required")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            proxy_subject = (
                request.headers.get("x-forwarded-user", "")
                or request.headers.get("x-auth-request-user", "")
            ).strip()
            if proxy_subject:
                subject = proxy_subject
        if not isinstance(subject, str) or not subject:
            raise HTTPException(401, "identity subject missing")
        user = await _keycloak_user(subject, get_provisioning_http_client(cast(Request, request)))
        attributes = user.get("attributes")
        if not isinstance(attributes, dict) or user.get("enabled") is not True:
            raise HTTPException(403, "active employee identity required")
        lifecycle = _attribute(attributes, "lifecycle_state")
        if lifecycle != "active":
            raise HTTPException(403, "active employment required")
        required_attributes = (
            "company_id",
            "business_unit_id",
            "department_id",
            "team_id",
            "supervisor_id",
            "agent_desktop_roles",
        )
        if any(not _attribute(attributes, name) for name in required_attributes):
            raise HTTPException(403, "identity claims incomplete")
        employee_id = _attribute(attributes, "employee_id")
        role = _attribute(attributes, "role_template")
        odoo_employee_id = _attribute(attributes, "odoo_employee_id") or employee_id
        username = _attribute(attributes, "vicidial_username") or user.get("username")
        campaigns = attributes.get("campaign_ids")
        if (
            not employee_id
            or not role
            or not odoo_employee_id
            or not isinstance(username, str)
            or not username
        ):
            raise HTTPException(403, "employee identity incomplete")
        if not isinstance(campaigns, list) or not all(
            isinstance(item, str) for item in campaigns
        ):
            raise HTTPException(403, "campaign authorization incomplete")
        endpoint_value = _attribute(attributes, "endpoint")
        endpoint = (
            int(endpoint_value) if endpoint_value and endpoint_value.isdigit() else None
        )
        authoritative = await _odoo_identity(
            employee_id,
            get_http_client(cast(Request, request)),
            campaign_id or (campaigns[0] if campaigns else None),
            requested_endpoint
            if requested_endpoint is not None
            else (endpoint or int(ENDPOINT)),
        )
        if authoritative.get("keycloak_subject") != subject:
            raise HTTPException(403, "identity subject mismatch")
        if authoritative.get("employee_id") != employee_id:
            raise HTTPException(403, "employee identity mismatch")
        authoritative_role = authoritative.get("role_template")
        authoritative_campaigns = authoritative.get("campaign_ids")
        authoritative_endpoint = authoritative.get("endpoint")
        if (
            not isinstance(authoritative_role, str)
            or not isinstance(authoritative_campaigns, list)
            or not all(isinstance(item, str) for item in authoritative_campaigns)
            or not isinstance(authoritative_endpoint, str)
            or not authoritative_endpoint.isdigit()
        ):
            raise HTTPException(403, "authoritative identity incomplete")
        if authoritative_role != role or not set(campaigns).issubset(
            set(authoritative_campaigns)
        ):
            raise HTTPException(403, "identity privilege mismatch")
        return BrowserIdentity(
            subject,
            employee_id,
            authoritative.get("odoo_employee_id") or odoo_employee_id,
            authoritative.get("vicidial_username") or username,
            authoritative_role,
            frozenset(authoritative_campaigns),
            int(authoritative_endpoint),
            str(authoritative.get("company_id") or _attribute(attributes, "company_id")),
            str(
                authoritative.get("business_unit_id")
                or _attribute(attributes, "business_unit_id")
            ),
            str(authoritative.get("agent_id") or employee_id),
        )
    if (
        request.headers.get("x-webphone-gateway") != "caddy-basic-auth"
        or request.headers.get("x-webphone-user") != EXPECTED_USER
        or request.headers.get("origin") != EXPECTED_ORIGIN
        or request.headers.get("x-forwarded-proto") != "https"
        or request.headers.get("sec-fetch-site") != "same-origin"
    ):
        raise HTTPException(403, "webphone identity rejected")
    return BrowserIdentity(
        EXPECTED_USER,
        EXPECTED_USER,
        EXPECTED_USER,
        EXPECTED_USER,
        "AGENT",
        frozenset({CAMPAIGN}),
        int(ENDPOINT),
        "TST",
        "TST",
        EXPECTED_USER,
    )


async def _provisioning_call(
    request: Request,
    method: str,
    path: str,
    body: dict | None = None,
    query: dict[str, str] | None = None,
) -> dict:
    secret = Path(settings.provisioning_service_client_secret_file).read_text().strip()
    client = get_provisioning_http_client(request)
    try:
        token_response = await client.post(
            settings.provisioning_service_token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.provisioning_service_client_id,
                "client_secret": secret,
            },
            timeout=12,
        )
        token_response.raise_for_status()
        service_token = token_response.json()["access_token"]
        response = await client.request(
            method,
            f"{settings.provisioning_service_url.rstrip('/')}/{path.lstrip('/')}",
            params=query,
            json=body,
            headers={"Authorization": f"Bearer {service_token}"},
            timeout=12,
        )
    except (OSError, httpx.HTTPError, KeyError, ValueError) as exc:
        raise HTTPException(503, "provisioning service unavailable") from exc
    if response.status_code >= 400:
        detail = "provisioning request denied"
        try:
            payload = response.json()
            if isinstance(payload, dict) and isinstance(payload.get("detail"), str):
                detail = payload["detail"]
        except ValueError:
            pass
        raise HTTPException(response.status_code, detail)
    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(503, "invalid provisioning response") from exc
    if not isinstance(payload, dict):
        raise HTTPException(503, "invalid provisioning response")
    return payload


def _desktop_response(payload: dict) -> dict:
    expiration = payload.get("expiration")
    turn_username = payload.get("temporary_turn_username")
    turn_credential = payload.get("temporary_turn_credential")
    approved_turn_url = payload.get("approved_turn_url")
    raw_role = payload.get("role")
    role = (
        {"AGENT": "SETTER", "CLOSER": "CLOSER", "SUPERVISOR": "SUPERVISOR"}.get(
            raw_role, raw_role
        )
        if isinstance(raw_role, str)
        else None
    )
    if not all(
        isinstance(value, str) and value
        for value in (
            payload.get("session_id"),
            payload.get("temporary_sip_credential"),
            payload.get("sip_uri"),
            payload.get("approved_wss_url"),
            expiration,
            turn_username,
            turn_credential,
            approved_turn_url,
            role,
        )
    ):
        raise HTTPException(503, "invalid provisioning response")
    return {
        "session_id": payload["session_id"],
        "binding_id": payload["browser_session_binding"],
        "sip_uri": payload["sip_uri"],
        "authorization_username": payload["temporary_sip_authorization_username"],
        "ephemeral_password": payload["temporary_sip_credential"],
        "websocket_url": payload["approved_wss_url"],
        "ice_servers": [
            {
                "urls": [approved_turn_url],
                "username": turn_username,
                "credential": turn_credential,
            }
        ],
        "expires_at": expiration,
        "role": role,
        "campaign_id": payload["campaign"],
        "endpoint": str(payload["endpoint"]),
        "environment": "STAGING",
        "permitted_call_scope": ["6000"],
    }


def validate_browser_session(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "invalid browser session") from exc
    if parsed.version != 4:
        raise HTTPException(422, "invalid browser session")
    return str(parsed)


def _ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=settings.vicidial_ca_file)
    context.load_cert_chain(
        settings.vicidial_client_cert_file,
        settings.vicidial_client_key_file,
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _endpoint_request(
    method: str,
    path: str,
    request_id: str,
    idempotency_key: str,
    body: dict | None = None,
) -> dict:
    if not settings.webphone_endpoint_adapter_url:
        raise RuntimeError("endpoint adapter unavailable")
    encoded = (
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        if body is not None
        else None
    )
    headers = {
        "Content-Type": "application/json",
        "X-Service-Role": "webphone_staging_provisioner",
        "X-Business-Unit": "TST",
        "X-Campaign": CAMPAIGN,
        "X-Request-ID": request_id,
        "X-Correlation-ID": request_id,
        "Idempotency-Key": idempotency_key,
    }
    request = urllib.request.Request(
        settings.webphone_endpoint_adapter_url + path,
        data=encoded,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(
            request, context=_ssl_context(), timeout=8
        ) as response:
            return json.loads(response.read(16384))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("endpoint adapter request failed") from exc


async def endpoint_request(*args, **kwargs) -> dict:
    return await asyncio.to_thread(_endpoint_request, *args, **kwargs)


def response_document(session: Session, password: str, turn: dict) -> dict:
    return {
        "session_id": session.session_id,
        "binding_id": session.binding_id,
        "sip_uri": "sip:6101@dialer.codestra.agency",
        "authorization_username": "6101",
        "ephemeral_password": password,
        "websocket_url": "wss://wss.codestra.agency:8089/ws",
        "ice_servers": [turn],
        "expires_at": session.expires_at.isoformat().replace("+00:00", "Z"),
        "role": "SETTER",
        "campaign_id": CAMPAIGN,
        "endpoint": ENDPOINT,
        "environment": "STAGING",
        "permitted_call_scope": ["6000"],
    }


async def issue(user: str, browser_session_id: str) -> dict:
    credential_id = str(uuid4())
    session_id = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=TTL_SECONDS)
    password = secrets.token_urlsafe(48)
    binding_id = hashlib.sha256(
        f"{user}:{browser_session_id}:{session_id}".encode()
    ).hexdigest()
    session = Session(
        session_id=session_id,
        credential_id=credential_id,
        binding_id=binding_id,
        user=user,
        expires_at=expires_at,
    )
    await SESSIONS.reserve(session)
    request_id = "webphone-" + uuid4().hex
    try:
        result = await endpoint_request(
            "POST",
            f"/v1/endpoint/{ENDPOINT}/issue",
            request_id,
            "webphone-" + session_id,
            {
                "endpoint": ENDPOINT,
                "credential_id": credential_id,
                "password": password,
                "expires_at": expires_at.isoformat(),
            },
        )
        turn = result["turn"]
        if set(turn) != {"urls", "username", "credential"} or turn["urls"] != [
            "turns:dialer.codestra.agency:5349?transport=tcp"
        ]:
            raise RuntimeError("invalid endpoint adapter response")
        return response_document(session, password, turn)
    except Exception as exc:
        await SESSIONS.consume(session_id, user)
        try:
            await endpoint_request(
                "DELETE",
                f"/v1/endpoint/{ENDPOINT}/{credential_id}",
                "webphone-" + uuid4().hex,
                "webphone-compensate-" + uuid4().hex,
            )
        except Exception:
            pass
        raise HTTPException(503, "staging provisioning unavailable") from exc


@router.post("/provision")
async def provision(value: ProvisionRequest, request: Request) -> dict:
    if settings.webphone_keycloak_enabled:
        raise HTTPException(410, "legacy provisioning route disabled")
    identity = await browser_identity(request)
    user = identity.subject
    browser_session_id = validate_browser_session(value.browser_session_id)
    return await issue(user, browser_session_id)


@router.post("/provision/{session_id}/refresh")
async def refresh(session_id: str, request: Request) -> dict:
    if settings.webphone_keycloak_enabled:
        raise HTTPException(410, "legacy provisioning route disabled")
    identity = await browser_identity(request)
    user = identity.subject
    try:
        session_id = str(UUID(session_id))
    except ValueError as exc:
        raise HTTPException(404, "session not found") from exc
    old = await SESSIONS.consume(session_id, user)
    try:
        await endpoint_request(
            "DELETE",
            f"/v1/endpoint/{ENDPOINT}/{old.credential_id}",
            "webphone-" + uuid4().hex,
            "webphone-revoke-" + uuid4().hex,
        )
        return await issue(user, str(uuid4()))
    except Exception as exc:
        raise HTTPException(503, "credential refresh failed") from exc


@router.post("/provision/{session_id}/revoke")
async def revoke(session_id: str, request: Request) -> dict:
    if settings.webphone_keycloak_enabled:
        raise HTTPException(410, "legacy provisioning route disabled")
    identity = await browser_identity(request)
    user = identity.subject
    try:
        session_id = str(UUID(session_id))
    except ValueError as exc:
        raise HTTPException(404, "session not found") from exc
    session = await SESSIONS.consume(session_id, user)
    try:
        await endpoint_request(
            "DELETE",
            f"/v1/endpoint/{ENDPOINT}/{session.credential_id}",
            "webphone-" + uuid4().hex,
            "webphone-revoke-" + uuid4().hex,
        )
    except Exception as exc:
        await SESSIONS.restore(session)
        raise HTTPException(503, "credential revocation failed") from exc
    return {"status": "revoked"}


@router.post("/session")
async def create_session(value: ProvisionRequest, request: Request) -> dict:
    identity = await browser_identity(request, value.campaign_id, int(value.endpoint))
    if value.campaign_id not in identity.campaigns:
        raise HTTPException(403, "campaign denied")
    if identity.endpoint is not None and identity.endpoint != int(value.endpoint):
        raise HTTPException(403, "endpoint denied")
    payload = await _provisioning_call(
        request,
        "POST",
        "/session",
        {
            "employee_id": identity.employee_id,
            "keycloak_subject": identity.subject,
            "odoo_employee_id": identity.odoo_employee_id,
            "vicidial_username": identity.vicidial_username,
            "endpoint": int(value.endpoint),
            "campaign": value.campaign_id,
            "role": identity.role,
            "browser_session_binding": validate_browser_session(
                value.browser_session_id
            ),
        },
    )
    return _desktop_response(payload)


@router.post("/renew")
async def renew_session(value: SessionAction, request: Request) -> dict:
    await browser_identity(request)
    payload = await _provisioning_call(request, "POST", "/renew", value.model_dump())
    return _desktop_response(payload)


@router.get("/config")
async def session_config(
    request: Request, session_id: str, browser_session_binding: str
) -> dict:
    await browser_identity(request)
    return await _provisioning_call(
        request,
        "GET",
        "/config",
        query={
            "session_id": session_id,
            "browser_session_binding": browser_session_binding,
        },
    )


@router.post("/revoke")
async def revoke_session(value: SessionAction, request: Request) -> dict:
    await browser_identity(request)
    return await _provisioning_call(request, "POST", "/revoke", value.model_dump())
