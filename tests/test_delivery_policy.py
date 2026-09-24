import random
from app.core.delivery import (
    CircuitBreaker,
    FailureCategory,
    classify_failure,
    retry_delay,
)


def test_retry_classification_is_narrow():
    for code in (429, 502, 503, 504):
        assert classify_failure(status_code=code) is FailureCategory.TRANSIENT
    for code in (400, 401, 403, 404, 409, 422):
        assert classify_failure(status_code=code) is FailureCategory.PERMANENT
    assert (
        classify_failure(ambiguous_after_transmission=True) is FailureCategory.AMBIGUOUS
    )


def test_full_jitter_and_circuit_breaker():
    assert 0 <= retry_delay(4, random.Random(1)) <= 1800
    breaker = CircuitBreaker(failure_threshold=2)
    breaker.failure()
    breaker.failure()
    assert breaker.open
    breaker.success()
    assert not breaker.open
