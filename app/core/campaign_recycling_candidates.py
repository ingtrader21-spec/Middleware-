"""Synthetic-only MCR candidate authority and tenant-bound paging.

This module is deliberately incapable of serving production tenants.  It exists
so the MCR decision/read APIs can be exercised end-to-end against the frozen
contracts while real Klyrow/Telnexa/WhatsApp candidate authority remains
blocked by config/campaign-recycling-candidate-authority.v1.json.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Iterable

from app.core.campaign_recycling import Candidate, Channel

SYNTHETIC_TENANT = "TEST_SYN_TENANT"
SYNTHETIC_CAMPAIGN_ID = "klyrow:test-syn-mcr"
SYNTHETIC_CAMPAIGN_VERSION = 1
SYNTHETIC_READBACK_VERSION = "test-syn-candidate-authority-v1"
SYNTHETIC_SENDER_ID = "00000000-0000-4000-8000-000000000111"


class CandidateAuthorityError(RuntimeError):
    pass


class CandidateAuthorityNotFound(CandidateAuthorityError):
    pass


class CandidateCursorError(CandidateAuthorityError):
    pass


@dataclass(frozen=True)
class SyntheticMembership:
    lead_id: str
    address_refs: dict[Channel, str]


class SyntheticCandidateAuthority:
    tenant_id = SYNTHETIC_TENANT
    readback_version = SYNTHETIC_READBACK_VERSION

    _memberships = (
        SyntheticMembership(
            lead_id="100-L-00000001",
            address_refs={"email": "addrref:test-syn:lead-00000001:email"},
        ),
        SyntheticMembership(
            lead_id="100-L-00000002",
            address_refs={"email": "addrref:test-syn:lead-00000002:email"},
        ),
    )

    def _assert_tenant(self, tenant_id: str) -> None:
        if tenant_id != self.tenant_id:
            raise CandidateAuthorityError("synthetic authority tenant mismatch")

    def membership(self, tenant_id: str, lead_id: str) -> SyntheticMembership | None:
        self._assert_tenant(tenant_id)
        return next((item for item in self._memberships if item.lead_id == lead_id), None)

    def candidates_for_lead(
        self,
        *,
        tenant_id: str,
        lead_id: str,
        campaign_id: str | None = None,
        campaign_version: int | None = None,
        channels: Iterable[str] | None = None,
    ) -> tuple[tuple[Candidate, ...], dict[Channel, str]]:
        membership = self.membership(tenant_id, lead_id)
        if membership is None:
            return (), {}
        if campaign_id is not None and campaign_id != SYNTHETIC_CAMPAIGN_ID:
            return (), membership.address_refs
        if campaign_version is not None and campaign_version != SYNTHETIC_CAMPAIGN_VERSION:
            return (), membership.address_refs
        channel_filter = set(channels or ())
        if channel_filter and "email" not in channel_filter:
            return (), membership.address_refs
        candidate = Candidate(
            campaign_id=SYNTHETIC_CAMPAIGN_ID,
            campaign_version=SYNTHETIC_CAMPAIGN_VERSION,
            channel="email",
            priority=10,
            touch_index=1,
            sender_identity_id=SYNTHETIC_SENDER_ID,
            active=True,
            version_approved=True,
            consent_granted=True,
            sender_authorized=True,
            dialing_eligible=False,
        )
        return (candidate,), membership.address_refs

    def campaign_members(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        campaign_version: int,
        channel: str | None,
    ) -> tuple[SyntheticMembership, ...]:
        self._assert_tenant(tenant_id)
        if campaign_id != SYNTHETIC_CAMPAIGN_ID:
            raise CandidateAuthorityNotFound("campaign not found")
        if campaign_version != SYNTHETIC_CAMPAIGN_VERSION:
            raise CandidateAuthorityNotFound("campaign version not found")
        if channel is not None and channel != "email":
            return ()
        return self._memberships


def candidate_authority_for_tenant(tenant_id: str) -> SyntheticCandidateAuthority | None:
    if tenant_id == SYNTHETIC_TENANT:
        return SyntheticCandidateAuthority()
    return None


def _cursor_binding(
    tenant_id: str,
    campaign_id: str,
    campaign_version: int,
    channel: str | None,
    limit: int,
) -> str:
    return hashlib.sha256(
        json.dumps(
            [tenant_id, campaign_id, campaign_version, channel, limit],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def encode_candidate_cursor(
    key: str,
    *,
    tenant_id: str,
    campaign_id: str,
    campaign_version: int,
    channel: str | None,
    limit: int,
    offset: int,
) -> str:
    if len(key.encode()) < 32:
        raise CandidateCursorError("cursor signing key unavailable")
    body = json.dumps(
        {
            "q": _cursor_binding(
                tenant_id, campaign_id, campaign_version, channel, limit
            ),
            "o": offset,
        },
        separators=(",", ":"),
    ).encode()
    mac = hmac.new(key.encode(), b"mcr-candidate-v1\0" + body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + mac).decode().rstrip("=")


def decode_candidate_cursor(
    key: str,
    cursor: str,
    *,
    tenant_id: str,
    campaign_id: str,
    campaign_version: int,
    channel: str | None,
    limit: int,
) -> int:
    if len(key.encode()) < 32:
        raise CandidateCursorError("cursor signing key unavailable")
    try:
        raw = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
        )
        if len(raw) <= 32:
            raise ValueError()
        body, supplied = raw[:-32], raw[-32:]
        expected = hmac.new(
            key.encode(), b"mcr-candidate-v1\0" + body, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, supplied):
            raise ValueError()
        value = json.loads(body)
        if set(value) != {"q", "o"}:
            raise ValueError()
        if value["q"] != _cursor_binding(
            tenant_id, campaign_id, campaign_version, channel, limit
        ):
            raise ValueError()
        offset = value["o"]
        if type(offset) is not int or offset < 0:
            raise ValueError()
        return offset
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise CandidateCursorError("invalid cursor") from exc
