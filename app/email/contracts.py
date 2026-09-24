from __future__ import annotations

import html
import re
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    Attachment,
    CaseEvent,
    CaseMessage,
    Department,
    EmailCase,
    EmailTenant,
    ServiceIdentityMapping,
    utcnow,
)

SCHEMA_VERSION = "codestra.email.v1"
BEYVRA_TENANT_ID = "49f847e4-9d0c-53af-9871-1abc7ff1b8cf"
BEYVRA_ACCOUNT_ID = "edc90db9-6f89-56dc-986c-d96c244c5f55"
PROVIDER_SERVICE = "klyrow-email-provider"
MAX_BODY_BYTES = 2 * 1024 * 1024

DEPARTMENTS = {
    name + "@beyvra.com": name
    for name in (
        "support", "complaints", "onboarding", "kyc", "compliance", "aml", "fraud", "risk",
        "trading", "tradeops", "payments", "billing", "finance", "legal", "privacy", "dpo",
        "security", "abuse", "partners", "institutional", "press", "careers",
    )
}

EVENT_TYPES = {
    "INBOUND_MESSAGE", "DELIVERY_ACCEPTED", "DELIVERY_SENT", "DELIVERY_DELIVERED",
    "DELIVERY_DEFERRED", "BOUNCE_SOFT", "BOUNCE_HARD", "COMPLAINT", "FAILED", "SUPPRESSED",
}

MESSAGE_ID = re.compile(r"^<[^<>\r\n]{1,996}>$")


def seed_control_plane(db: Session) -> None:
    if not db.get(EmailTenant, BEYVRA_TENANT_ID):
        db.add(EmailTenant(tenant_id=BEYVRA_TENANT_ID, account_id=BEYVRA_ACCOUNT_ID, slug="beyvra",
                           name="Beyvra", environment="production", service_scope="email", active=True))
    mapping = db.get(ServiceIdentityMapping, PROVIDER_SERVICE)
    if not mapping:
        db.add(ServiceIdentityMapping(service_name=PROVIDER_SERVICE, tenant_id=BEYVRA_TENANT_ID,
                                      environment="production", allowed_scopes=["email.inbound", "email.delivery_event"], active=True))
    for address, slug in DEPARTMENTS.items():
        existing = db.scalar(select(Department).where(Department.tenant_id == BEYVRA_TENANT_ID, Department.address == address))
        if not existing:
            db.add(Department(tenant_id=BEYVRA_TENANT_ID, address=address, slug=slug, active=True))
    db.commit()


def authoritative_tenant(db: Session, service_name: str) -> EmailTenant:
    mapping = db.get(ServiceIdentityMapping, service_name)
    if not mapping or not mapping.active or mapping.environment != "production":
        raise ValueError("service_identity_not_mapped")
    tenant = db.get(EmailTenant, mapping.tenant_id)
    if not tenant or not tenant.active or tenant.environment != "production":
        raise ValueError("tenant_not_active")
    return tenant


def validate_event(body: dict, expected_type: str | None = None) -> None:
    required = {"schema_version", "event_id", "event_type", "occurred_at", "provider"}
    if missing := sorted(required - body.keys()):
        raise ValueError("missing_event_fields:" + ",".join(missing))
    if body["schema_version"] != SCHEMA_VERSION or body["event_type"] not in EVENT_TYPES:
        raise ValueError("unsupported_event_contract")
    if expected_type and body["event_type"] != expected_type:
        raise ValueError("unexpected_event_type")
    if body["provider"] != "klyrow-postal":
        raise ValueError("invalid_provider")
    datetime.fromisoformat(str(body["occurred_at"]).replace("Z", "+00:00"))
    # Tenant/account fields may be echoed for correlation but never select authority.
    if body.get("tenant_id") not in (None, BEYVRA_TENANT_ID) or body.get("account_id") not in (None, BEYVRA_ACCOUNT_ID):
        raise ValueError("tenant_override_denied")


def ingest_inbound(db: Session, service_name: str, body: dict, payload_digest: str) -> tuple[EmailCase, CaseMessage, bool]:
    validate_event(body, "INBOUND_MESSAGE")
    tenant = authoritative_tenant(db, service_name)
    existing = db.scalar(select(CaseMessage).where(CaseMessage.provider_event_id == str(body["event_id"])))
    if existing:
        return db.get(EmailCase, existing.case_id), existing, True  # type: ignore[return-value]
    recipient = str(body.get("recipient", "")).strip().lower()
    department = db.scalar(select(Department).where(Department.tenant_id == tenant.tenant_id,
                                                     Department.address == recipient, Department.active.is_(True)))
    if not department:
        raise ValueError("unknown_recipient")
    message_id = str(body.get("message_id", ""))
    if not MESSAGE_ID.fullmatch(message_id):
        raise ValueError("invalid_message_id")
    references = [str(value) for value in body.get("references", [])]
    thread_key = str(body.get("in_reply_to") or (references[-1] if references else message_id))
    case = db.scalar(select(EmailCase).where(EmailCase.tenant_id == tenant.tenant_id, EmailCase.thread_key == thread_key))
    if not case:
        case = EmailCase(tenant_id=tenant.tenant_id, department_id=department.id, thread_key=thread_key,
                         subject=str(body.get("subject", ""))[:998])
        db.add(case)
        db.flush()
    text_body = body.get("text_body")
    html_body = body.get("html_body")
    if html_body is not None:
        # Store inert escaped HTML until a dedicated sanitizer/renderer approves it.
        html_body = html.escape(str(html_body))
    message = CaseMessage(case_id=case.id, provider_event_id=str(body["event_id"]),
                          provider_message_id=_optional(body.get("provider_message_id")), message_id=message_id,
                          in_reply_to=_optional(body.get("in_reply_to")), references=references,
                          sender=str(body.get("sender", ""))[:320], recipients=[recipient],
                          cc=[str(value)[:320] for value in body.get("cc", [])], subject=str(body.get("subject", ""))[:998],
                          message_date=_date(body.get("date")), text_body=_optional(text_body), html_body=_optional(html_body),
                          payload_digest=payload_digest)
    db.add(message)
    db.flush()
    for item in body.get("attachments", []):
        db.add(Attachment(message_id=message.id, filename=str(item.get("filename", "attachment"))[:255],
                          content_type=str(item.get("content_type", "application/octet-stream"))[:255],
                          size_bytes=max(0, int(item.get("size_bytes", 0))),
                          content_digest=str(item.get("sha256", ""))[:64], scan_status="PENDING"))
    db.add(CaseEvent(case_id=case.id, event_type="INBOUND_MESSAGE", actor_subject=service_name,
                     event_metadata={"event_id": body["event_id"], "schema_version": SCHEMA_VERSION}))
    case.updated_at = utcnow()
    db.commit()
    return case, message, False


def _optional(value: object) -> str | None:
    return None if value is None else str(value)


def _date(value: object) -> datetime | None:
    return None if value is None else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
