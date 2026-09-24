# Codestra Real-Time Boundaries

Source boundaries:

- API gateway
- call-state service
- WebSocket gateway
- screen-pop service
- AI conversation service
- live STT
- LLM router
- streaming TTS
- call control
- transfer service
- event persistence
- reconciliation worker

The staging package combines only domain contracts. Redis state always has a
TTL and is never durable business truth. PostgreSQL inbox/outbox remains the
durable path. n8n is absent from call control, RTP, VAD, STT, LLM, TTS,
screen-pop, and transfer execution.
