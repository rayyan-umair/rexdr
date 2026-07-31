#!/usr/bin/env bash
# =============================================================================
# REXDR - Build Preparation Script
# prepare_build.sh
#
# Author  : Rayyan Umair
# Date    : 2026-06-21
# Updated : 2026-07-31 - WHEEL_SOURCE now points at core-shared/dist/, which
#           is where `python -m build` actually writes. It previously read
#           from the repo-root dist/, so a freshly built wheel was never
#           picked up and every engine silently shipped a stale rexdr_core -
#           surviving `docker compose build --no-cache`, since the file
#           handed to Docker was itself unchanged. Also refuses to run when
#           the wheel is older than the source it was built from, and
#           resolves the repo root itself rather than assuming the caller's
#           working directory.
# Purpose : Copies the rexdr_core wheel into every engine's Docker build
#           context. Docker build contexts cannot see files outside
#           themselves or runtime volume mounts, so the wheel must be
#           physically present in each engine folder before building.
#           Run this BEFORE every docker compose build.
#           Linux/macOS equivalent of scripts/prepare_build.ps1.
# =============================================================================

set -euo pipefail

# Resolve the repo root from this script's own location so it behaves the
# same however it is invoked - from the root, from scripts/, or by the
# launcher with an arbitrary working directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WHEEL_SOURCE="core-shared/dist/rexdr_core-1.0.0-py3-none-any.whl"

if [ ! -f "$WHEEL_SOURCE" ]; then
    echo -e "\033[31mERROR: Wheel not found at $WHEEL_SOURCE\033[0m"
    echo -e "\033[33mBuild it first: cd core-shared && python3 -m build --wheel\033[0m"
    exit 1
fi

# A wheel older than the source it was built from is the failure mode that
# took down every engine on 2026-07-31 - the stale binary was copied happily
# and only surfaced as an unrelated TypeError at container startup. Refuse
# to distribute it rather than let it propagate silently.
NEWER_SOURCE=$(find core-shared/rexdr_core -name "*.py" -newer "$WHEEL_SOURCE" | head -1)
if [ -n "$NEWER_SOURCE" ]; then
    echo -e "\033[31mERROR: wheel is older than source ($NEWER_SOURCE).\033[0m"
    echo -e "\033[33mRebuild it: cd core-shared && python3 -m build --wheel\033[0m"
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