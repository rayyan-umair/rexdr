# =============================================================================
# REXDR - Shared Core Base Image
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-08-01
# Purpose : Builds rexdr_core from source and installs it, producing the base
#           image every Python engine builds on. This replaces the previous
#           arrangement where a pre-built wheel was committed to the repo and
#           copied into each engine's build context by prepare_build - that
#           allowed the binary to drift from the source it was built from,
#           which silently downgraded rexdr_core across all nine engines and
#           took the platform down three times on 2026-07-31. Building from
#           source here makes that failure structurally impossible.
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR shared core library base image"
LABEL version="1.0.0"

WORKDIR /build

RUN pip install --no-cache-dir build

COPY pyproject.toml ./
COPY rexdr_core ./rexdr_core

RUN python -m build --wheel --outdir /wheels \
    && pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /build

WORKDIR /app