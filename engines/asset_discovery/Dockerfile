# =============================================================================
# REXDR - Network Discovery Engine
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-19
# =============================================================================

FROM rexdr-base:1.0.0

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR Network Discovery Engine"
LABEL version="1.0.0"

WORKDIR /app

# nmap binary is required by python-nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./asset_discovery

RUN mkdir -p /data /data/archive /config

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8006/health || exit 1

EXPOSE 8006

CMD ["python", "-m", "asset_discovery.main"]