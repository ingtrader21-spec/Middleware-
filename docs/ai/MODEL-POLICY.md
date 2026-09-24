# Model policy

Callers select logical profiles, never endpoints. Profiles are `fast-chat`, `quality-chat`, `coding-default`, `coding-large`, `crm-analysis`, `voice-summary`, and `embedding-default`. Server B maps only to locally installed approved models. A missing capability fails closed; it does not trigger a model download.
