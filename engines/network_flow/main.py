"""
rexdr - Network Flow Intelligence Engine
main.py - Engine entry point and intelligence pipeline

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Entry point for the Network Flow Intelligence engine.
          Initializes all components, starts the packet capture
          pipeline as a background thread, and runs the FastAPI server.
          Every completed flow passes through inspection, detection,
          and entity observation in a single pipeline cycle. ZeroMQ
          is not used by this engine in publisher mode since it has
          no downstream subscribers in the current build - SIEM reads
          flow data via DuckDB ATTACH directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from queue import Queue, Empty

# -- Third Party -------------------------------------------------------------
import uvicorn

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from network_flow.api import create_app
from network_flow.capture import PacketCapture
from network_flow.config import settings
from network_flow.database import NetworkFlowDatabase
from network_flow.detections import NetworkFlowDetections
from network_flow.entity import NetworkFlowEntityManager
from network_flow.inspector import FlowInspector

# ============================================================================

logging.basicConfig(
    level  = settings.log_level,
    format = settings.log_format,
)
logger = logging.getLogger(__name__)

# ============================================================================
# Global component instances
# ============================================================================

db            = NetworkFlowDatabase(data_dir=settings.data_dir)
entity_store  = EntityStoreClient(base_url="http://entity-store:8008")
inspector     = FlowInspector()
detector      = NetworkFlowDetections(db=db)
entity_mgr    = NetworkFlowEntityManager(db=db, entity_store=entity_store)

# Thread-safe queue bridging the capture thread and the async pipeline
flow_queue: Queue = Queue(maxsize=10000)

# App reference for WebSocket broadcasting
_app_instance = None

def _get_app():
    return _app_instance


# ============================================================================
# Capture thread
# ============================================================================

def capture_worker() -> None:
    """
    Runs packet capture in a dedicated thread since scapy's sniff()
    is a blocking call. Completed flows are pushed onto flow_queue
    via callback as they expire, since sniff() itself never returns
    in live mode.
    """
    logger.info("Capture worker thread started")
    capture = PacketCapture()

    def on_flow(flow: dict) -> None:
        try:
            flow_queue.put_nowait(flow)
        except Exception:
            logger.warning("Flow queue full - dropping flow")

    try:
        capture.run(on_flow)
    except Exception as e:
        logger.error("Capture worker error - error=%s", str(e))


# ============================================================================
# Intelligence pipeline
# ============================================================================

async def run_pipeline() -> None:
    """
    The core intelligence pipeline loop.
    Consumes completed flows from flow_queue, runs them through
    inspection, detection, and entity observation.
    """
    logger.info("Intelligence pipeline started")

    while True:
        try:
            await _pipeline_cycle()
        except Exception as e:
            logger.error("Pipeline cycle error - error=%s", str(e))

        await asyncio.sleep(1)


async def _pipeline_cycle() -> None:
    """Process all currently queued flows in a single cycle."""
    flows_processed = 0
    detections_fired = 0

    while True:
        try:
            flow = flow_queue.get_nowait()
        except Empty:
            break

        try:
            # -- Step 1: Inspect and enrich ---------------------------------
            enriched_flow = inspector.inspect(flow)

            # -- Step 2: Write flow record -----------------------------------
            db.insert_flow_record(enriched_flow)

            # -- Step 3: Normalize and write -----------------------------------
            payload = inspector.to_normalized_payload(enriched_flow)
            db.insert_normalized_flow(payload)

            # -- Step 4: Run detections ----------------------------------------
            detections = detector.run(enriched_flow)

            for detection in detections:
                db.insert_detection(detection)
                detections_fired += 1
                await _broadcast_detection(detection.model_dump(mode="json"))

            # -- Step 5: Update entity observations -----------------------------
            entity_mgr.process(enriched_flow, detections)

            # -- Step 6: Broadcast flow to WebSocket clients ---------------------
            await _broadcast_flow(enriched_flow)

            flows_processed += 1

        except Exception as e:
            logger.error("Pipeline error processing flow - error=%s", str(e))

    if flows_processed > 0:
        logger.info(
            "Pipeline cycle complete - flows=%d detections=%d",
            flows_processed,
            detections_fired,
        )


async def _broadcast_detection(detection_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type":      "detection",
                "engine":    "network_flow",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data":      detection_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


async def _broadcast_flow(flow_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            safe_flow = {k: v for k, v in flow_data.items() if k != "raw_data"}
            await app.state.ws_manager.broadcast({
                "type":      "flow",
                "engine":    "network_flow",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data":      safe_flow,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


# ============================================================================
# Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app):
    """FastAPI lifespan context manager - handles startup and shutdown."""
    global _app_instance
    _app_instance = app

    logger.info("=== REXDR Network Flow Intelligence Engine starting ===")

    db.connect()
    logger.info("Database connected")

    entity_store.connect()
    logger.info("Entity store connected")

    # Start the packet capture thread
    capture_thread = threading.Thread(target=capture_worker, daemon=True)
    capture_thread.start()
    logger.info("Capture worker thread started")

    # Start the intelligence pipeline as a background task
    pipeline_task = asyncio.create_task(run_pipeline())
    logger.info("Intelligence pipeline started")

    logger.info(
        "=== Network Flow engine ready - api=http://0.0.0.0:%d ===",
        settings.api_port,
    )

    yield

    logger.info("Network Flow engine shutting down")

    pipeline_task.cancel()
    try:
        await pipeline_task
    except asyncio.CancelledError:
        pass

    entity_store.close()
    db.close()

    logger.info("=== Network Flow engine stopped ===")


# ============================================================================
# Entry point
# ============================================================================

def main() -> None:
    """Start the Network Flow Intelligence engine."""
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