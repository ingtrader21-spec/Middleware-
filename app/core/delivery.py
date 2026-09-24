"""Target retry, concurrency, ordering and backpressure primitives."""

import random
from dataclasses import dataclass
from enum import StrEnum


class FailureCategory(StrEnum):
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    AMBIGUOUS = "ambiguous"


def classify_failure(
    *,
    status_code: int | None = None,
    network_before_response: bool = False,
    timeout_duplicate_safe: bool = False,
    temporary_db_lock: bool = False,
    ambiguous_after_transmission: bool = False,
) -> FailureCategory:
    if ambiguous_after_transmission:
        return FailureCategory.AMBIGUOUS
    if network_before_response or timeout_duplicate_safe or temporary_db_lock:
        return FailureCategory.TRANSIENT
    if status_code in {429, 502, 503, 504}:
        return FailureCategory.TRANSIENT
    return FailureCategory.PERMANENT


RETRY_SCHEDULE_SECONDS = (30, 120, 600, 1800)


def retry_delay(attempt: int, rng: random.Random | None = None) -> float:
    if attempt < 1 or attempt > len(RETRY_SCHEDULE_SECONDS):
        raise ValueError("retry attempt outside configured schedule")
    return (rng or random).uniform(0, RETRY_SCHEDULE_SECONDS[attempt - 1])


@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    failures: int = 0
    open: bool = False

    def success(self) -> None:
        self.failures = 0
        self.open = False

    def failure(self) -> None:
        self.failures += 1
        self.open = self.failures >= self.failure_threshold


TARGET_CONCURRENCY = {"odoo": 4, "n8n": 8, "recording": 2, "reconciliation": 1}
