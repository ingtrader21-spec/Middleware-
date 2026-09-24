from app.core.call_lifecycle import base_local, correlation_id, transition


def test_linked_id_primary_and_unique_id_fallback():
    assert correlation_id("linked-1", "unique-1") == "asterisk:linked-1"
    assert correlation_id(None, "unique-1") == "asterisk:unique-1"


def test_local_channel_pairs_collapse():
    assert base_local("Local/6198@cs-synth-6198;1") == ("Local/6198@cs-synth-6198")
    assert base_local("Local/6198@cs-synth-6198;2") == ("Local/6198@cs-synth-6198")


def test_monotonic_lifecycle_and_terminal_immutability():
    assert transition(None, "STARTED").resulting == "STARTED"
    assert transition("STARTED", "CONNECTED").resulting == "CONNECTED"
    assert transition("CONNECTED", "ENDED").resulting == "ENDED"
    assert transition("STARTED", "ENDED").resulting == "ENDED"
    stale = transition("ENDED", "CONNECTED")
    assert stale.resulting == "ENDED"
    assert stale.applied is False
