# =============================================================================
# REXDR - Windows Event Intelligence Engine
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-12
# Stage 1 : Build the Go harvester binary
# Stage 2 : Python intelligence layer with rexdr_core wheel installed
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 - Build Go harvester
# -----------------------------------------------------------------------------
FROM golang:1.21-alpine AS harvester-builder

WORKDIR /build

# Copy Go module files first for layer caching
COPY harvester/go.mod harvester/go.sum ./
RUN go mod download

# Copy harvester source and build
COPY harvester/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o rexdr-harvester .

# -----------------------------------------------------------------------------
# Stage 2 - Python intelligence layer
# -----------------------------------------------------------------------------
FROM python:3.11-slim

# Metadata
LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR Windows Event Intelligence Engine"
LABEL version="1.0.0"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install rexdr_core wheel first - it is the foundation
COPY /wheels/rexdr_core-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/rexdr_core-1.0.0-py3-none-any.whl

# Install engine dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Go harvester binary from builder stage
COPY --from=harvester-builder /build/rexdr-harvester /usr/local/bin/rexdr-harvester
RUN chmod +x /usr/local/bin/rexdr-harvester

# Copy engine source
COPY . .

# Create data directories
RUN mkdir -p /data /data/archive /config

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000 5555

CMD ["python", "-m", "windows_event.main"]