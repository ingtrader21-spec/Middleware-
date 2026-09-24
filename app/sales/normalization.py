from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException


LEGAL_SUFFIXES = frozenset(
    {
        "co",
        "company",
        "corp",
        "corporation",
        "gmbh",
        "inc",
        "incorporated",
        "llc",
        "llp",
        "ltd",
        "limited",
        "plc",
        "sa",
        "sarl",
        "srl",
    }
)
ROLE_EMAIL_LOCALS = frozenset(
    {"admin", "contact", "hello", "info", "office", "sales", "support"}
)
COMMON_SECOND_LEVEL_SUFFIXES = frozenset(
    {"co.uk", "com.au", "com.br", "com.do", "com.mx", "co.nz", "co.za"}
)


def _text(value: str | None) -> str:
    normalized = unicodedata.normalize("NFKC", value or "").casefold()
    normalized = re.sub(r"[^\w\s]", " ", normalized, flags=re.UNICODE)
    return " ".join(normalized.split())


def normalized_company_name(value: str) -> str:
    words = _text(value).split()
    while words and words[-1] in LEGAL_SUFFIXES:
        words.pop()
    return " ".join(words)


def normalized_person_name(value: str | None) -> str:
    return _text(value)


def normalized_address_component(value: str | None) -> str:
    return _text(value)


def normalized_domain(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value if "://" in value else f"//{value}"
    host = (urlsplit(candidate).hostname or "").rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    try:
        return host.encode("idna").decode("ascii") or None
    except UnicodeError as exc:
        raise ValueError("domain cannot be normalized with IDNA") from exc


def registrable_domain(value: str | None) -> str | None:
    host = normalized_domain(value)
    if not host:
        return None
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix2 in COMMON_SECOND_LEVEL_SUFFIXES else suffix2


def normalized_email(value: str | None) -> str | None:
    if not value:
        return None
    local, separator, domain = value.strip().rpartition("@")
    if not separator or not local or not domain:
        raise ValueError("email is malformed")
    normalized_host = normalized_domain(domain)
    if not normalized_host:
        raise ValueError("email domain is malformed")
    return f"{local}@{normalized_host}".casefold()


def role_email(value: str | None) -> bool:
    normalized = normalized_email(value)
    return bool(normalized and normalized.split("@", 1)[0] in ROLE_EMAIL_LOCALS)


@dataclass(frozen=True)
class NormalizedPhone:
    e164: str
    extension: str | None


def normalized_phone(
    value: str | None, country_code: str | None
) -> NormalizedPhone | None:
    if not value:
        return None
    try:
        parsed = phonenumbers.parse(value, country_code)
    except NumberParseException as exc:
        raise ValueError("telephone number is ambiguous or invalid") from exc
    if not phonenumbers.is_valid_number(parsed):
        raise ValueError("telephone number is ambiguous or invalid")
    if not value.lstrip().startswith("+") and not country_code:
        raise ValueError("telephone country context is required")
    extension = parsed.extension or None
    parsed.extension = None
    return NormalizedPhone(
        phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        extension,
    )
