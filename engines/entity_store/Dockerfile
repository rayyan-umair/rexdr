# =============================================================================
# REXDR - Entity Store Service
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-23
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR Entity Store Service - shared unified entity registry"
LABEL version="1.0.0"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY rexdr_core-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/rexdr_core-1.0.0-py3-none-any.whl

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./entity_store

RUN mkdir -p /data

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8008/health || exit 1

EXPOSE 8008

CMD ["python", "-m", "entity_store.main"]