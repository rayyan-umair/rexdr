# =============================================================================
# REXDR - Build Preparation Script
# prepare_build.ps1
#
# Author  : Rayyan Umair
# Date    : 2026-06-18
# Updated : 2026-07-31 - $wheelSource now points at core-shared\dist\, which
#           is where `python -m build` actually writes. It previously read
#           from the repo-root dist\, so a freshly built wheel was never
#           picked up and every engine silently shipped a stale rexdr_core -
#           surviving even `docker compose build --no-cache`, since the file
#           handed to Docker was itself unchanged. Also refuses to run when
#           the wheel is older than the source it was built from, and
#           resolves the repo root itself rather than assuming the caller's
#           working directory.
# Purpose : Copies the rexdr_core wheel into every engine's Docker build
#           context. Docker build contexts cannot see files outside
#           themselves or runtime volume mounts, so the wheel must be
#           physically present in each engine folder before building.
#           Run this BEFORE every docker compose build.
# =============================================================================

$ErrorActionPreference = "Stop"

# Resolve the repo root from this script's own location so it behaves the
# same however it is invoked - from the root, from scripts\, or by the
# launcher with an arbitrary working directory.
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$wheelSource = "core-shared\dist\rexdr_core-1.0.0-py3-none-any.whl"

if (-not (Test-Path $wheelSource)) {
    Write-Host "ERROR: Wheel not found at $wheelSource" -ForegroundColor Red
    Write-Host "Build it first: cd core-shared; python -m build --wheel" -ForegroundColor Yellow
    exit 1
}

# A wheel older than the source it was built from is the failure mode that
# took down every engine on 2026-07-31 - the stale binary was copied happily
# and only surfaced as an unrelated TypeError at container startup. Refuse
# to distribute it rather than let it propagate silently.
$wheelTime = (Get-Item $wheelSource).LastWriteTime
$newerSource = Get-ChildItem -Path "core-shared\rexdr_core" -Filter *.py -Recurse |
    Where-Object { $_.LastWriteTime -gt $wheelTime } |
    Select-Object -First 1

if ($newerSource) {
    Write-Host "ERROR: wheel is older than source ($($newerSource.FullName))." -ForegroundColor Red
    Write-Host "Rebuild it: cd core-shared; python -m build --wheel" -ForegroundColor Yellow
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