from __future__ import annotations

import math
import re
from dataclasses import dataclass


E164 = re.compile(r"^\+[1-9][0-9]{5,18}$")
SMS_SENDER = re.compile(r"^(?:\+[1-9][0-9]{5,18}|[A-Za-z0-9]{1,20})$")
STOP_KEYWORDS = frozenset(
    {"STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"}
)
HELP_KEYWORDS = frozenset({"HELP"})

GSM_BASIC = frozenset(
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM_EXTENSION = frozenset("^{}\\[~]|€")


@dataclass(frozen=True)
class SmsSegments:
    encoding: str
    characters: int
    segments: int
    encoded_units: int


def normalize_e164(value: str) -> str:
    normalized = value.strip()
    if not E164.fullmatch(normalized):
        raise ValueError("SMS recipient must be an E.164 phone number")
    return normalized


def normalize_sms_sender(value: str) -> str:
    normalized = value.strip()
    if not SMS_SENDER.fullmatch(normalized):
        raise ValueError(
            "SMS sender must be an approved E.164 number or 1-20 character alphanumeric identity"
        )
    return normalized


def sms_segments(text: str) -> SmsSegments:
    if not text:
        raise ValueError("SMS content.text is required")
    if len(text) > 5_000:
        raise ValueError("SMS content.text exceeds 5000 characters")
    is_gsm = all(character in GSM_BASIC or character in GSM_EXTENSION for character in text)
    if is_gsm:
        units = sum(2 if character in GSM_EXTENSION else 1 for character in text)
        segment_count = 1 if units <= 160 else math.ceil(units / 153)
        return SmsSegments("GSM-7", len(text), segment_count, units)
    units = len(text.encode("utf-16-be")) // 2
    segment_count = 1 if units <= 70 else math.ceil(units / 67)
    return SmsSegments("UCS-2", len(text), segment_count, units)


def compliance_keyword(text: str) -> str | None:
    keyword = text.strip().upper()
    if keyword in STOP_KEYWORDS:
        return "stop"
    if keyword in HELP_KEYWORDS:
        return "help"
    return None
