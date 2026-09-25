from datetime import datetime,timezone,timedelta
import pytest
from app.core.command_reliability import *

def test_reservation_returns_original_for_exact_duplicate():
 r=IdempotencyRegistry(); h=request_hash({"tenant_id":"t","payload":{"x":1}})
 first,dup=r.reserve(tenant_id="t",idempotency_key="abcdefgh",command_id="c1",request_sha256=h)
 second,dup2=r.reserve(tenant_id="t",idempotency_key="abcdefgh",command_id="c2",request_sha256=h)
 assert not dup and dup2 and second.command_id=="c1"

def test_reservation_rejects_hash_conflict():
 r=IdempotencyRegistry(); r.reserve(tenant_id="t",idempotency_key="abcdefgh",command_id="c1",request_sha256="a"*64)
 with pytest.raises(IdempotencyConflict): r.reserve(tenant_id="t",idempotency_key="abcdefgh",command_id="c2",request_sha256="b"*64)

def test_request_hash_ignores_transport_identity_but_not_payload():
 assert request_hash({"command_id":"1","payload":{"x":1}})==request_hash({"command_id":"2","payload":{"x":1}})
 assert request_hash({"payload":{"x":1}})!=request_hash({"payload":{"x":2}})

def test_retry_backoff_is_deterministic_and_capped():
 p=RetryPolicy(max_attempts=9,base_seconds=2,max_seconds=10)
 assert [p.delay(i) for i in range(1,6)]==[2,4,8,10,10]

def test_retryable_failure_schedules_next_attempt():
 now=datetime(2026,1,1,tzinfo=timezone.utc)
 d=decide_retry(attempt=2,error_code="timeout",now=now)
 assert d.state=="retry" and d.next_attempt_at==now+timedelta(seconds=4)

def test_permanent_and_exhausted_failures_dead_letter():
 assert decide_retry(attempt=1,error_code="forbidden").reason=="non_retryable"
 assert decide_retry(attempt=5,error_code="timeout").reason=="max_attempts_exhausted"
 assert classify_failure("unknown",http_status=503)=="retryable"
 assert classify_failure("unknown")=="permanent"

def test_redrive_requires_unresolved_unblocked_dead_letter():
 assert redrive_eligible({"state":"dead_lettered","resolved_at":None,"redrive_blocked":False})
 assert not redrive_eligible({"state":"failed","resolved_at":None})
 assert not redrive_eligible({"state":"dead_lettered","resolved_at":"2026-01-01"})
