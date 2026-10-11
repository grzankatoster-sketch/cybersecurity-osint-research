# syntax=docker/dockerfile:1
# osint-toolbox: odtwarzalne srodowisko OSINT (defensywne, tylko wlasne domeny/zgoda).
# Build context = katalog OSINT/ (compose: context: ..). Patrz osint-env/README.md.

ARG PYTHON_IMAGE=python:3.14-slim
# theHarvester: przypiety commit (klon w narzedzia/theharvester-src byl na tym commicie, 5.0.0)
ARG THEHARVESTER_REPO=https://github.com/laramies/theHarvester.git
ARG THEHARVESTER_REF=49a38f8d33c32336bbf6a111ea723ea223116265

# ---------------------------------------------------------------- builder
FROM ${PYTHON_IMAGE} AS builder
ARG THEHARVESTER_REPO
ARG THEHARVESTER_REF
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates build-essential \
 && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# theHarvester z przypietego commita (bez historii)
RUN git init /src/theharvester \
 && git -C /src/theharvester remote add origin "$THEHARVESTER_REPO" \
 && git -C /src/theharvester fetch --depth 1 origin "$THEHARVESTER_REF" \
 && git -C /src/theharvester checkout --detach FETCH_HEAD \
 && pip install /src/theharvester

# Wlasne projekty (zrodla z build contextu; .dockerignore odcina .venv, wyniki, sekrety)
COPY dns-audit/      /src/dns-audit/
COPY hibp-monitor/   /src/hibp-monitor/
COPY exif-map/       /src/exif-map/
COPY phone-check/    /src/phone-check/
COPY net-intel/      /src/net-intel/
COPY site-audit/     /src/site-audit/
RUN pip install /src/dns-audit /src/hibp-monitor /src/exif-map /src/phone-check /src/net-intel /src/site-audit

# username-engine: tryb edytowalny z /opt, bo CLI szuka data/sites.json wzgledem zrodel
COPY username-engine/ /opt/username-engine/
RUN pip install -e /opt/username-engine

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libimage-exiftool-perl dnsutils git ca-certificates less \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --home-dir /home/osint --shell /bin/bash osint \
 && mkdir -p /work && chown osint:osint /work
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/username-engine /opt/username-engine
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/osint
# kanoniczne polecenia: username-engine = python -m username_engine
RUN printf '#!/bin/sh\nexec python -m username_engine "$@"\n' > /usr/local/bin/username-engine \
 && chmod 0755 /usr/local/bin/username-engine
USER osint
WORKDIR /work
CMD ["bash"]

# ---------------------------------------------------------------- tests (docker build --target tests)
FROM runtime AS tests
USER root
RUN pip install --no-cache-dir "pytest>=8" "pytest-asyncio"
COPY --chown=osint:osint dns-audit/      /tests/dns-audit/
COPY --chown=osint:osint hibp-monitor/   /tests/hibp-monitor/
COPY --chown=osint:osint exif-map/       /tests/exif-map/
COPY --chown=osint:osint phone-check/    /tests/phone-check/
COPY --chown=osint:osint net-intel/      /tests/net-intel/
COPY --chown=osint:osint site-audit/     /tests/site-audit/
COPY --chown=osint:osint username-engine/ /tests/username-engine/
USER osint
WORKDIR /tests
COPY --chown=osint:osint osint-env/run-tests.sh /tests/run-tests.sh
CMD ["sh", "/tests/run-tests.sh"]

# domyslny cel (bez --target) = ostatni etap, dlatego runtime wskazuje compose jawnie
FROM runtime AS final
