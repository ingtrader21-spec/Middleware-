from app.core.transcription import TranscriptSegment, validate_segment

CAPTURE_WINDOW_MS = 500
CHUNK_SECONDS = (2, 5)
ROLLING_CONTEXT_SECONDS = (10, 30)

__all__ = ["TranscriptSegment", "validate_segment"]
