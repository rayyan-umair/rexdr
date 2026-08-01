# =============================================================================
# REXDR - SIEM Correlation Engine
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-15
# =============================================================================

FROM rexdr-base:1.0.0

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR SIEM Correlation Engine"
LABEL version="1.0.0"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./siem

RUN mkdir -p /data /data/archive /config/sigma_rules /app/replay

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

EXPOSE 8002

CMD ["python", "-m", "siem.main"]