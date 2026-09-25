# Python 3.12.14 / Alpine 3.24 (Docker Official Image).
ARG PYTHON_BASE=docker.io/library/python@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31
ARG CHAINGUARD_PYTHON_DEV=cgr.dev/chainguard/python@sha256:4bf7e945777010672b8ccd5d2ae2c41c91ad6d3478878347c731ae536d506bef
ARG CHAINGUARD_PYTHON_RUNTIME=cgr.dev/chainguard/python@sha256:1f6779775c9f466890da563e411cb677045a6c20b6a65160eefad1deffb5012c
ARG VCS_REF=unknown
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
ARG IMAGE_VERSION=unreleased
ARG SOURCE_TREE_SHA256=unknown

FROM ${PYTHON_BASE} AS python-builder
USER root
ARG PYTHON_SOURCE_SHA256=5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a
WORKDIR /usr/src
RUN apk add --no-cache \
      build-base=0.5-r4 \
      bzip2-dev=1.0.8-r6 \
      curl=8.22.0-r0 \
      expat-dev=2.8.5-r0 \
      gdbm-dev=1.26-r0 \
      libffi-dev=3.5.2-r1 \
      linux-headers=7.0.0-r1 \
      ncurses-dev=6.6_p20260516-r0 \
      libcrypto3=3.5.8-r0 \
      libssl3=3.5.8-r0 \
      openssl-dev=3.5.8-r0 \
      readline-dev=8.3.3-r1 \
      tar=1.35-r5 \
      xz-dev=5.8.4-r0 \
      zlib-dev=1.3.2-r0
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      --output /tmp/sqlite.apk \
      https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/sqlite-3.53.4-r0.apk \
 && curl --fail --location --proto '=https' --tlsv1.2 \
      --output /tmp/sqlite-dev.apk \
      https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/sqlite-dev-3.53.4-r0.apk \
 && apk add --no-cache /tmp/sqlite.apk /tmp/sqlite-dev.apk \
 && rm /tmp/sqlite.apk /tmp/sqlite-dev.apk
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      --output Python-3.12.14.tar.xz \
      https://www.python.org/ftp/python/3.12.14/Python-3.12.14.tar.xz \
 && echo "${PYTHON_SOURCE_SHA256}  Python-3.12.14.tar.xz" | sha256sum -c - \
 && tar -xJf Python-3.12.14.tar.xz \
 && cd Python-3.12.14 \
 && ./configure \
      --enable-loadable-sqlite-extensions \
      --enable-option-checking=fatal \
      --enable-shared \
      --with-ensurepip \
      --with-system-expat \
 && make -j"$(nproc)" \
 && make install
RUN python -c 'import html.parser,http.cookies,inspect,pyexpat,sys,tarfile; assert sys.version_info[:3] == (3,12,14); assert "unfiltered.replace" in inspect.getsource(tarfile.TarFile.makelink_with_filter); assert "_pending_len" in inspect.getsource(html.parser.HTMLParser.feed); assert "_has_control_character" in inspect.getsource(http.cookies.Morsel.update); assert pyexpat.EXPAT_VERSION == "expat_2.8.5"'

FROM ${PYTHON_BASE} AS verified-python
USER root
RUN apk add --no-cache expat=2.8.5-r0
RUN rm -rf /usr/local/*
COPY --from=python-builder /usr/local /usr/local

FROM verified-python AS builder
ARG VCS_REF
ARG BUILD_REVISION
ARG BUILD_CREATED
LABEL org.opencontainers.image.source="https://github.com/ingtrader21-spec/Middleware-" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_CREATED}" \
      io.codestra.build.revision="${BUILD_REVISION}" \
      io.codestra.python.base.repository="docker.io/library/python" \
      io.codestra.python.base.digest="sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31" \
      io.codestra.python.version="3.12.14"
USER root
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.lock requirements-test.lock ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes -r requirements.lock

FROM builder AS test
RUN apk add --no-cache bash=5.3.9-r1 git=2.54.0-r0 openssl=3.5.8-r0
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes -r requirements-test.lock
WORKDIR /app
COPY --chown=10001:10001 . /app
ENV PYTHONPATH=/app
USER 10001:10001
ENTRYPOINT ["pytest"]

FROM ${CHAINGUARD_PYTHON_DEV} AS runtime-builder
USER root
WORKDIR /build
COPY requirements.lock ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/python -m pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes -r requirements.lock \
 && /opt/venv/bin/python -m pip uninstall -y pip setuptools wheel

FROM ${CHAINGUARD_PYTHON_RUNTIME} AS runtime
ARG VCS_REF
ARG BUILD_REVISION
ARG BUILD_CREATED
ARG IMAGE_VERSION
ARG SOURCE_TREE_SHA256
LABEL org.opencontainers.image.source="https://github.com/ingtrader21-spec/Middleware-" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.created="${BUILD_CREATED}" \
      codestra.source_tree.sha256="${SOURCE_TREE_SHA256}" \
      io.codestra.build.revision="${BUILD_REVISION}" \
      io.codestra.python.base.repository="cgr.dev/chainguard/python" \
      io.codestra.python.base.digest="sha256:1f6779775c9f466890da563e411cb677045a6c20b6a65160eefad1deffb5012c" \
      io.codestra.python.version="3.14.7"
COPY --from=runtime-builder /opt/venv /opt/venv
# Production Compose uses a fail-closed admission wrapper mounted with a
# /bin/sh shebang. Keep the runtime otherwise distroless while projecting the
# pinned Chainguard busybox implementation required to execute that wrapper.
COPY --from=runtime-builder /bin/busybox /bin/busybox
COPY --from=runtime-builder /bin/sh /bin/sh
COPY --from=runtime-builder /usr/lib/libcrypt.so.1.1.0 /usr/lib/libcrypt.so.1.1.0
COPY --from=runtime-builder /usr/lib/libcrypt.so.1 /usr/lib/libcrypt.so.1
WORKDIR /app
COPY --chown=10001:10001 alembic.ini app.py ./
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 migrations ./migrations
COPY --chown=10001:10001 schemas ./schemas
COPY --chown=10001:10001 scripts ./scripts
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8095
ENTRYPOINT []
CMD ["/opt/venv/bin/python", "-m", "app.entrypoints.integration_api"]

FROM verified-python AS qwen-auth-verifier-runtime
ARG VCS_REF
ARG BUILD_REVISION
LABEL org.opencontainers.image.title="Codestra Qwen Authentication Verifier" \
      org.opencontainers.image.description="Read-only private mTLS and HMAC authentication verifier" \
      org.opencontainers.image.source="https://github.com/ingtrader21-spec/Middleware-" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="1.0.0-rc1" \
      io.codestra.build.revision="${BUILD_REVISION}" \
      io.codestra.python.base.repository="docker.io/library/python" \
      io.codestra.python.base.digest="sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31" \
      io.codestra.python.version="3.12.14"
USER root
RUN grep -q '^app:' /etc/group || addgroup -S -g 10001 app \
 && grep -q '^app:' /etc/passwd || adduser -S -D -H -u 10001 -G app app
COPY --from=builder /opt/venv /opt/venv
RUN /opt/venv/bin/python -m pip uninstall -y \
      alembic asyncpg greenlet httpcore httpx mako markupsafe prometheus-client \
      pyjwt python-dotenv redis sqlalchemy pydantic-settings \
 && /opt/venv/bin/python -m pip uninstall -y pip setuptools
WORKDIR /app
COPY --chown=10001:10001 app/qwen_auth_verifier.py /app/app/qwen_auth_verifier.py
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8095
CMD ["uvicorn", "app.qwen_auth_verifier:create_app", "--factory", "--host", "0.0.0.0", "--port", "8095", "--no-server-header", "--no-date-header"]
