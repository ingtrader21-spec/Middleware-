import time

import pytest

from app.core.realtime import (
    FEATURE_FLAGS,
    LAZY_CONTEXT_ORDER,
    REDIS_KEY_TTLS,
    ConversationState,
    FeaturePolicy,
    ReplayBuffer,
    RealtimeDenied,
    ScreenPop,
    SocketScope,
    TraceRecorder,
    VAD_THRESHOLDS_MS,
    authorize_socket,
    failure_degradation,
    webrtc_ready,
)


def event(sequence=1, user="agent-1", unit="TL", campaign="TL-TEST"):
    return ScreenPop(
        sequence,
        "SYNTH-CALL-1",
        user,
        unit,
        campaign,
        "***0001",
        "Synthetic Co",
        "lead-1",
        "customer-1",
        "en",
        "support",
        False,
        "Synthetic summary",
    )


def scope():
    return SocketScope(
        "agent-1",
        "user-session-1",
        "TL",
        frozenset({"TL-TEST"}),
        "SYNTH-CALL-1",
        "endpoint-1",
    )


def test_socket_scope_rejects_cross_agent_unit_campaign_and_call():
    authorize_socket(scope(), event())
    for denied in (
        event(user="agent-2"),
        event(unit="DEV"),
        event(campaign="TL-OTHER"),
        ScreenPop(**{**event().__dict__, "uniqueid": "SYNTH-CALL-2"}),
    ):
        with pytest.raises(RealtimeDenied):
            authorize_socket(scope(), denied)


def test_duplicate_prevention_reconnect_and_replay():
    buffer = ReplayBuffer()
    assert buffer.publish(event(1))
    assert not buffer.publish(event(1))
    assert buffer.publish(event(2))
    assert [row.sequence for row in buffer.replay("SYNTH-CALL-1", 1)] == [2]


def test_every_redis_key_has_a_positive_ttl():
    assert len(REDIS_KEY_TTLS) == 11
    assert all(value > 0 for value in REDIS_KEY_TTLS.values())


def test_minimal_pop_and_lazy_order():
    assert event().masked_customer_reference.startswith("***")
    assert LAZY_CONTEXT_ORDER[0] == "basic_card"
    assert LAZY_CONTEXT_ORDER[-1] == "full_history_on_request"


def test_compact_conversation_state_is_bounded():
    state = ConversationState("TL", "TL-TEST", "***0001")
    state.recent_turns.extend(str(i) for i in range(100))
    state.objections.extend(str(i) for i in range(100))
    assert len(state.recent_turns) == 12
    assert len(state.objections) == 10


def test_scp_vad_is_more_patient():
    assert (
        VAD_THRESHOLDS_MS["SCP"]["end_silence"]
        > VAD_THRESHOLDS_MS["default"]["end_silence"]
    )


def test_ready_requires_all_confirmations():
    assert webrtc_ready(
        registered=True, audio_device=True, websocket=True, campaign_authorized=True
    )
    assert not webrtc_ready(
        registered=False, audio_device=True, websocket=True, campaign_authorized=True
    )


@pytest.mark.parametrize(
    "dependency", ["stt", "llm", "tts", "redis", "odoo", "websocket"]
)
def test_failures_never_block_telephony(dependency):
    assert failure_degradation(dependency)["telephony_continues"] is True


def test_n8n_is_not_a_realtime_dependency():
    for dependency in ("stt", "llm", "tts", "redis", "odoo", "websocket"):
        assert "n8n" not in str(failure_degradation(dependency)).lower()


def test_unknown_dependency_fails_closed():
    with pytest.raises(ValueError, match="unknown dependency"):
        failure_degradation("unknown")


def test_all_feature_flags_default_false():
    policy = FeaturePolicy()
    assert all(
        not policy.enabled(flag, "staging", "TL", "TL-TEST") for flag in FEATURE_FLAGS
    )


def test_synthetic_server_processing_latency():
    scope_value = scope()
    durations = []
    for sequence in range(1, 5001):
        recorder = TraceRecorder(f"trace-{sequence}", f"corr-{sequence}")
        start = time.perf_counter_ns()
        recorder.measure("campaign_resolved", lambda: "TL-TEST")
        recorder.measure("agent_resolved", lambda: "agent-1")
        recorder.measure(
            "websocket_authorized",
            lambda: authorize_socket(scope_value, event(sequence)),
        )
        durations.append((time.perf_counter_ns() - start) / 1_000_000)
    durations.sort()
    assert durations[int(len(durations) * 0.95)] < 50
