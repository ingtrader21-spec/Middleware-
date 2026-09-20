FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
ARG VCS_REF
ARG SOURCE_URL=https://github.com/ingtrader21-spec/Middleware-
ARG VERSION
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION
# Debian security update for libpcre2-8-0 (CVE-2026-86145, CVE-2026-89157,
# CVE-2026-89161); the same pin Dockerfile.runtime applies in patched-final-base.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcre2-8-0=10.42-1+deb12u1 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/codestra
COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir -r /tmp/requirements.lock && useradd --system --uid 12001 --home /nonexistent codestra
COPY app /srv/codestra/app
USER 12001
ENV PYTHONPATH=/srv/codestra PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.email.runtime:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
