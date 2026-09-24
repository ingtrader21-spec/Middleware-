# Codestra Transcription Services

The staging deployment may combine these modules, but each owns a separate
interface and queue:

- `audio_gateway.py`: consent, checksum, retention, and secure media references.
- `live.py`: bounded synthetic stream segments using Faster-Whisper.
- `batch.py`: post-call Faster-Whisper final jobs (`large-v3` GPU profile,
  `small/int8` CPU staging fallback).
- `alignment.py`: post-call-only WhisperX jobs.
- `diarization.py`: Asterisk channel identity first, NeMo fallback only.
- `redaction.py`: operational transcript redaction.
- `speech_analytics.py`: schema-constrained advisory results.
- `websocket_gateway.py`: authenticated user/unit/campaign/session delivery.

Every production feature flag defaults to false. This package never fetches
customer media or exposes permanent object-storage URLs.
