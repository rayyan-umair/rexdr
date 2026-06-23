# =============================================================================
# REXDR - Build Preparation Script
# prepare_build.ps1
#
# Author  : Rayyan Umair
# Date    : 2026-06-18
# Purpose : Copies the rexdr_core wheel into every engine's Docker build
#           context. Docker build contexts cannot see files outside
#           themselves or runtime volume mounts, so the wheel must be
#           physically present in each engine folder before building.
#           Run this BEFORE every docker compose build.
# =============================================================================

$wheelSource = "dist\rexdr_core-1.0.0-py3-none-any.whl"

if (-not (Test-Path $wheelSource)) {
    Write-Host "ERROR: Wheel not found at $wheelSource" -ForegroundColor Red
    Write-Host "Build it first: cd core-shared && python -m build" -ForegroundColor Yellow
    exit 1
}

$engines = @(
    "engines\entity_store",
    "engines\windows_event",
    "engines\network_flow",
    "engines\siem",
    "engines\dns",
    "engines\identity",
    "engines\response",
    "engines\asset_discovery",
    "engines\vulnerability"
)

Write-Host "Copying rexdr_core wheel to all engine build contexts..." -ForegroundColor Cyan

foreach ($engine in $engines) {
    if (Test-Path $engine) {
        Copy-Item $wheelSource -Destination $engine -Force
        Write-Host "  Copied to $engine" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: $engine not found, skipping" -ForegroundColor Yellow
    }
}

Write-Host "Done. Ready to run: docker compose build" -ForegroundColor Cyan