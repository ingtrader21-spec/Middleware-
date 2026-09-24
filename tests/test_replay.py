from __future__ import annotations

from app.replay import RedisReplayGuard


def test_redis_lock_key_has_unambiguous_tuple_encoding() -> None:
    guard = RedisReplayGuard(client=None)  # type: ignore[arg-type]
    assert guard._key("a:b", "c") != guard._key("a", "b:c")
    assert guard._key("tenant", "event") == guard._key("tenant", "event")
