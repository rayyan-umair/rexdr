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

if [ -f "$WHEEL_SOURCE" ]; then
    NEWER=$(find core-shared/rexdr_core -name "*.py" -newer "$WHEEL_SOURCE" | head -1)
    if [ -n "$NEWER" ]; then
        echo -e "\033[31mERROR: wheel is older than source ($NEWER).\033[0m"
        echo -e "\033[33mRebuild it: cd core-shared && python3 -m build --wheel\033[0m"
        exit 1
    fi
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
    "engines/entity_store"
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