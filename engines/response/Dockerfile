# =============================================================================
# REXDR - Incident Response Orchestration Engine
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-18
# =============================================================================

FROM rexdr-base:1.0.0

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR Incident Response Orchestration Engine"
LABEL version="1.0.0"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./response

RUN mkdir -p /data /data/archive /config/playbooks /cases

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8005/health || exit 1

EXPOSE 8005

CMD ["python", "-m", "response.main"]