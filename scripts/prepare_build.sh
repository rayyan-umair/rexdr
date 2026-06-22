#!/usr/bin/env bash
# =============================================================================
# REXDR - Build Preparation Script
# prepare_build.sh
#
# Author  : Rayyan Umair
# Date    : 2026-06-21
# Purpose : Copies the rexdr_core wheel into every engine's Docker build
#           context. Docker build contexts cannot see files outside
#           themselves or runtime volume mounts, so the wheel must be
#           physically present in each engine folder before building.
#           Run this BEFORE every docker compose build.
#           Linux/macOS equivalent of scripts/prepare_build.ps1.
# =============================================================================

set -euo pipefail

WHEEL_SOURCE="dist/rexdr_core-1.0.0-py3-none-any.whl"

if [ ! -f "$WHEEL_SOURCE" ]; then
    echo -e "\033[31mERROR: Wheel not found at $WHEEL_SOURCE\033[0m"
    echo -e "\033[33mBuild it first: cd core-shared && python -m build\033[0m"
    exit 1
fi

ENGINES=(
    "engines/windows_event"
    "engines/network_flow"
    "engines/siem"
    "engines/dns"
    "engines/identity"
    "engines/response"
    "engines/asset_discovery"
    "engines/vulnerability"
)

echo -e "\033[36mCopying rexdr_core wheel to all engine build contexts...\033[0m"

for engine in "${ENGINES[@]}"; do
    if [ -d "$engine" ]; then
        cp "$WHEEL_SOURCE" "$engine/"
        echo -e "\033[32m  Copied to $engine\033[0m"
    else
        echo -e "\033[33m  WARNING: $engine not found, skipping\033[0m"
    fi
done

echo -e "\033[36mDone. Ready to run: docker compose build\033[0m"