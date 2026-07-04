"""
rexdr - Network Discovery Engine
main.py - Engine entry point and scan pipeline

Author  : Rayyan Umair
Date    : 2026-06-19
Purpose : Entry point for the Network Discovery engine. Runs the
          scheduled scan loop as a background task alongside the
          FastAPI server. Every scan cycle scans all configured zones,
          upserts the asset inventory, runs new-device detection, and
          updates entity observations.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Map the terrain before the enemy does."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

# -- Third Party -------------------------------------------------------------
import uvicorn

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from asset_discovery.api import create_app
from asset_discovery.config import settings
from asset_discovery.database import AssetDiscoveryDatabase
from asset_discovery.detections import AssetDiscoveryDetections
from asset_discovery.entity import AssetDiscoveryEntityManager
from asset_discovery.scanner import NetworkScanner

# ============================================================================

logging.basicConfig(level=settings.log_level, format=settings.log_format)
logger = logging.getLogger(__name__)

db           = AssetDiscoveryDatabase(data_dir=settings.data_dir)
entity_store  = EntityStoreClient(base_url="http://localhost:8008")
scanner      = NetworkScanner()
detector     = AssetDiscoveryDetections()
entity_mgr   = AssetDiscoveryEntityManager(db=db, entity_store=entity_store)

_app_instance = None

def _get_app():
    return _app_instance


async def run_scan_loop() -> None:
    """The core scan loop - runs continuously as a background task."""
    logger.info("Scan pipeline started")

    while True:
        try:
            await _run_scan_cycle()
        except Exception as e:
            logger.error("Scan cycle error - error=%s", str(e))

        await asyncio.sleep(settings.scan_interval_minutes * 60)


async def _run_scan_cycle() -> None:
    """Execute a single full scan cycle across all configured zones."""
    logger.info("Scan cycle starting")

    loop = asyncio.get_event_loop()
    assets = await loop.run_in_executor(None, scanner.scan_all_zones)

    new_count = 0
    detection_count = 0

    for asset in assets:
        ip_address = asset.get("ip_address")
        is_new = db.upsert_asset(
            ip_address     = ip_address,
            hostname       = asset.get("hostname"),
            mac_address    = asset.get("mac_address"),
            os_fingerprint = asset.get("os_fingerprint"),
            open_ports     = asset.get("open_ports", []),
            services       = asset.get("services", {}),
            network_zone   = asset.get("network_zone"),
        )

        db.insert_scan_record(
            scan_id        = str(uuid.uuid4()),
            ip_address     = ip_address,
            open_ports     = asset.get("open_ports", []),
            services       = asset.get("services", {}),
            os_fingerprint = asset.get("os_fingerprint"),
        )

        if is_new:
            new_count += 1

        detections = detector.run(asset, is_new)

        for detection in detections:
            db.insert_detection(detection)
            detection_count += 1
            await _broadcast_detection(detection.model_dump(mode="json"))

        entity_mgr.process(asset, detections)
        await _broadcast_asset(asset)

    logger.info(
        "Scan cycle complete - hosts=%d new=%d detections=%d",
        len(assets), new_count, detection_count,
    )


async def _broadcast_detection(detection_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type": "detection", "engine": "asset_discovery",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": detection_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


async def _broadcast_asset(asset_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type": "asset", "engine": "asset_discovery",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": asset_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


@asynccontextmanager
async def lifespan(app):
    global _app_instance
    _app_instance = app

    logger.info("=== REXDR Network Discovery Engine starting ===")

    db.connect()
    entity_store.connect()

    scan_task = asyncio.create_task(run_scan_loop())

    logger.info("=== Asset Discovery engine ready - api=http://0.0.0.0:%d ===", settings.api_port)

    yield

    logger.info("Asset Discovery engine shutting down")
    scan_task.cancel()
    try:
        await scan_task
    except asyncio.CancelledError:
        pass

    entity_store.close()
    db.close()
    logger.info("=== Asset Discovery engine stopped ===")


def main() -> None:
    app = create_app(db=db)
    app.router.lifespan_context = lifespan
    uvicorn.run(
        app,
        host      = settings.api_host,
        port      = settings.api_port,
        workers   = settings.api_workers,
        log_level = settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()