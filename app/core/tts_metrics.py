"""Bounded-cardinality, content-free text-to-speech metrics."""

from prometheus_client import Counter, Gauge, Histogram

REQUESTS = Counter(
    "elevenlabs_tts_requests_total", "Governed TTS requests", ("outcome",)
)
FAILURES = Counter(
    "elevenlabs_tts_failures_total", "Governed TTS failures", ("failure_class",)
)
ACTIVE_STREAMS = Gauge("elevenlabs_tts_active_streams", "Active TTS streams")
REJECTED = Counter(
    "elevenlabs_tts_rejected_total", "Locally rejected TTS requests", ("reason",)
)
AUDIO_BYTES = Counter("elevenlabs_tts_audio_bytes_total", "TTS audio bytes")
CHARACTERS = Counter("elevenlabs_tts_characters_total", "Submitted TTS characters")
TIME_TO_FIRST_AUDIO = Histogram(
    "elevenlabs_tts_time_to_first_audio_seconds", "Time to first TTS audio byte"
)
STREAM_DURATION = Histogram(
    "elevenlabs_tts_stream_duration_seconds", "TTS stream duration"
)
PROVIDER_STATUS = Counter(
    "elevenlabs_tts_provider_status_total", "TTS provider HTTP status", ("status",)
)
CLIENT_CANCELLATIONS = Counter(
    "elevenlabs_tts_client_cancellations_total", "Cancelled TTS client streams"
)
