# =============================================================================
# REXDR - DNS Behavioral Intelligence Engine
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-23
# Stage 1 : Build the Go sniffer binary
# Stage 2 : Python intelligence layer with rexdr_core wheel installed
# =============================================================================

FROM golang:1.21-bookworm AS sniffer-builder

# gopacket's pcap bindings require cgo, which needs a C compiler and
# libpcap's development headers to link against. CGO_ENABLED=0 (used
# by the other Go binaries in this platform that don't touch pcap)
# would leave gopacket's cgo-defined symbols unresolved - this is the
# one Go build in REXDR that must run with cgo enabled.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpcap-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY sniffer/go.mod sniffer/go.sum ./
RUN go mod download
COPY sniffer/ ./
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o rexdr-dns-sniffer .

FROM python:3.11-slim

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR DNS Behavioral Intelligence Engine"
LABEL version="1.0.0"

WORKDIR /app

# libpcap (runtime shared library, not -dev) is required here since the
# sniffer binary copied in below is cgo-linked against it.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY rexdr_core-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/rexdr_core-1.0.0-py3-none-any.whl

COPY brain/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=sniffer-builder /build/rexdr-dns-sniffer /usr/local/bin/rexdr-dns-sniffer
RUN chmod +x /usr/local/bin/rexdr-dns-sniffer

COPY brain/ ./dns/
COPY intel/ /app/intel/

RUN mkdir -p /data /data/archive /config

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8003/health || exit 1

EXPOSE 8003 5557

CMD ["python", "-m", "dns.main"]