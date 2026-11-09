# syntax=docker/dockerfile:1.7
# Home Control Hub — ALLES-IN-ÉÉN image (PostgreSQL 16 + API/statuspagina + worker in één container).
#
#   docker build -f deploy/allinone/Dockerfile [--secret id=ca_bundle,src=<ca.crt>] -t home-control-hub:dev .
#
# Installatie uitsluitend als standaard TrueNAS Custom App (zie deploy/truenas/CUSTOM_APP.md): image + tag,
# één poort 30420 → 30420, één opslag → /appdata. Geen YAML, geen wachtwoorden, geen verplichte variabelen.
# PostgreSQL draait binnen de container op een unix-socket (geen netwerkpoort, geen wachtwoord).
# Start als root alleen om /appdata aan 568:568 te geven; daarna draait alles — ook PID 1 — als 568 (TrueNAS 'apps'),
# zonder capabilities en met zelf gezette PR_SET_NO_NEW_PRIVS (het Custom App-formulier zet die niet; contract 1.2
# §2.2). De procesbewaker is zelf PID 1 en ruimt zombies op: geen dumb-init/tini die als root blijft draaien.
# Basisimages staan op exacte versie + sha256-digest (contract §1). De optionele BuildKit-secret 'ca_bundle' is
# alleen voor bouwomgevingen achter een TLS-proxy; zonder die secret bouwt de image schoon (bv. in GitHub Actions).

ARG PYTHON_IMAGE=mirror.gcr.io/library/python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ARG POSTGRES_IMAGE=mirror.gcr.io/library/postgres:16.15-bookworm@sha256:5264710be20f409750ac6dc4e5706dcef929c87e241605463f0f9aefa932a8d9

# ---------------------------------------------------------------- PostgreSQL 16 server + client
FROM ${POSTGRES_IMAGE} AS pg
RUN set -eu; mkdir -p /out/lib /out/pg; \
    rm -f /usr/lib/postgresql/16/lib/llvmjit*.so; rm -rf /usr/lib/postgresql/16/lib/bitcode; \
    for f in /usr/lib/postgresql/16/bin/* /usr/lib/postgresql/16/lib/*.so; do ldd "$f" 2>/dev/null || true; done \
      | awk '/=>/ {print $3}' | sort -u \
      | grep -vE '/(libc|libm|libdl|libpthread|librt|libresolv|ld-linux[^/]*)\.so' \
      | while read -r lib; do cp -L "$lib" /out/lib/; done; \
    cp -rL /usr/lib/postgresql/16 /out/pg/lib; cp -rL /usr/share/postgresql/16 /out/pg/share; \
    test -f /out/pg/share/postgresql.conf.sample

# ---------------------------------------------------------------- Python-dienst
FROM ${PYTHON_IMAGE} AS core
WORKDIR /src
COPY apps/api/requirements.lock apps/api/pyproject.toml ./
COPY apps/api/src ./src
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi; \
    pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore --prefix=/install \
        -r requirements.lock \
    && pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore --prefix=/install \
        --no-deps .

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE}
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="home-control-hub" \
      org.opencontainers.image.description="Home Control Hub — integratiedienst (netwerk, Node-RED, Authentik/SSO, energie), alles-in-één" \
      org.opencontainers.image.source="https://github.com/lvos04/home-control-hub" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=pg /out/pg/lib /usr/lib/postgresql/16
COPY --from=pg /out/pg/share /usr/share/postgresql/16
COPY --from=pg /out/lib /opt/pglibs
COPY --from=core /install /usr/local
COPY apps/api/alembic /usr/local/lib/hch/alembic
COPY deploy/allinone/supervisor.py /usr/local/lib/hch/supervisor.py
COPY deploy/allinone/healthcheck.py /usr/local/lib/hch/healthcheck.py
# statuspagina (GET /): versie-gepinde kopie van het Peil-sjabloon (ONTWERPTAAL §13.2, O-14; tools/peil_kopie.py)
COPY design/ontwerptaal/statuspagina.html /usr/local/lib/hch/ontwerptaal/statuspagina.html
RUN set -eu; \
    for b in postgres initdb pg_ctl pg_isready psql pg_dump pg_restore; do \
      printf '#!/bin/sh\nLD_LIBRARY_PATH=/opt/pglibs exec /usr/lib/postgresql/16/bin/%s "$@"\n' "$b" > /usr/local/bin/$b; \
      chmod 0755 /usr/local/bin/$b; \
    done; \
    postgres --version | grep -q ' 16\.'; pg_dump --version | grep -q ' 16\.'; \
    groupadd -g 568 apps; useradd -u 568 -g 568 -M -d /tmp -s /usr/sbin/nologin apps; \
    mkdir -p /appdata; chown 568:568 /appdata; \
    find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true; \
    python -c "import integrations.app, psycopg, uvicorn, cryptography"; \
    python -c "import pathlib, sys; from integrations.peil import lees; \
t = lees(pathlib.Path('/usr/local/lib/hch/ontwerptaal/statuspagina.html')); \
sys.exit(0 if t.intact else 'Peil-sjabloon wijkt af van de herkomstkop (sha256)')"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    HCH_DATA_DIR=/appdata HCH_PORT=30420 HCH_ALEMBIC_DIR=/usr/local/lib/hch/alembic \
    HCH_PEIL_DIR=/usr/local/lib/hch/ontwerptaal \
    HCH_DATABASE_URL="postgresql+psycopg://hch@/hch?host=/tmp/hch-pg" HCH_VERSION=${VERSION}
VOLUME ["/appdata"]
EXPOSE 30420
HEALTHCHECK --interval=30s --timeout=8s --start-period=90s --retries=3 \
  CMD ["python", "/usr/local/lib/hch/healthcheck.py"]
ENTRYPOINT ["python", "/usr/local/lib/hch/supervisor.py"]
