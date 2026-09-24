"""Monotonic telephony lifecycle helpers."""

from dataclasses import dataclass

RANK = {"STARTED": 1, "CONNECTED": 2, "ENDED": 3}


def base_local(value: str) -> str:
    return value.rsplit(";", 1)[0] if value.endswith((";1", ";2")) else value


def correlation_id(linked_id: str | None, unique_id: str) -> str:
    return f"asterisk:{base_local(linked_id or unique_id)}"


def advances(current: str, incoming: str) -> bool:
    return RANK[incoming] > RANK[current]


@dataclass(frozen=True)
class Transition:
    previous: str | None
    incoming: str
    resulting: str
    applied: bool


def transition(current: str | None, incoming: str) -> Transition:
    if current is None or advances(current, incoming):
        return Transition(current, incoming, incoming, True)
    return Transition(current, incoming, current, False)
