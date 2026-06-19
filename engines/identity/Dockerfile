# =============================================================================
# REXDR - Active Directory Intelligence Engine
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-18
# Stage 1 : Build the Go collector binary
# Stage 2 : Python intelligence layer with rexdr_core wheel installed
# =============================================================================

FROM golang:1.21-alpine AS collector-builder

WORKDIR /build
COPY collector/go.mod collector/go.sum ./
RUN go mod download
COPY collector/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o rexdr-ad-collector .

FROM python:3.11-slim

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR Active Directory Intelligence Engine"
LABEL version="1.0.0"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY rexdr_core-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/rexdr_core-1.0.0-py3-none-any.whl

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=collector-builder /build/rexdr-ad-collector /usr/local/bin/rexdr-ad-collector
RUN chmod +x /usr/local/bin/rexdr-ad-collector

COPY . .

RUN mkdir -p /data /data/archive /config

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8004/health || exit 1

EXPOSE 8004 5558

CMD ["python", "-m", "identity.main"]