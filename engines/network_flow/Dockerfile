# =============================================================================
# REXDR - Network Flow Intelligence Engine
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-17
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR Network Flow Intelligence Engine"
LABEL version="1.0.0"

WORKDIR /app

# libpcap is required for scapy live packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY rexdr_core-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/rexdr_core-1.0.0-py3-none-any.whl

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./network_flow
COPY intel/known_bad.txt /app/intel/known_bad.txt

RUN mkdir -p /data /data/archive /config /app/intel

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

EXPOSE 8001

CMD ["python", "-m", "network_flow.main"]