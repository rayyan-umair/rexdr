"""
rexdr - Windows Event Intelligence Engine
main.py - Engine entry point and intelligence pipeline

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Entry point for the Windows Event Intelligence engine.
          Initializes all components, starts the intelligence pipeline,
          and runs the FastAPI server. The pipeline runs as a background
          asyncio task alongside the API server. Every normalized event
          passes through normalization, detection, and entity observation
          in a single pipeline cycle. ZeroMQ publishes detections to the
          SIEM correlation engine and the response engine.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import os
import json
import subprocess
import threading
import logging
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

# -- Third Party -------------------------------------------------------------
import uvicorn
import zmq
import zmq.asyncio

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from rexdr_core.identity import ENGINE_ZMQ_TOPICS, EngineID
from windows_event.api import create_app
from windows_event.config import settings
from windows_event.database import WindowsEventDatabase
from windows_event.detections import WindowsEventDetections
from windows_event.entity import WindowsEventEntityManager
from windows_event.normalizer import WindowsEventNormalizer

# ============================================================================

logging.basicConfig(
    level  = settings.log_level,
    format = settings.log_format,
)
logger = logging.getLogger(__name__)

# ============================================================================
# Global component instances
# ============================================================================

db            = WindowsEventDatabase(data_dir=settings.data_dir)
entity_store  = EntityStoreClient(base_url="http://entity-store:8008")
normalizer    = WindowsEventNormalizer()
detector      = WindowsEventDetections(db=db)
entity_mgr    = WindowsEventEntityManager(db=db, entity_store=entity_store)

# ZeroMQ context and publisher socket
zmq_context:   zmq.asyncio.Context | None = None
zmq_publisher: zmq.asyncio.Socket | None  = None


# ============================================================================
# ZeroMQ publisher
# ============================================================================

async def init_zmq() -> None:
    """Initialize the ZeroMQ PUB socket for broadcasting detections."""
    global zmq_context, zmq_publisher

    zmq_context   = zmq.asyncio.Context()
    zmq_publisher = zmq_context.socket(zmq.PUB)
    zmq_publisher.bind(
        f"tcp://{settings.zmq_host}:{settings.zmq_publisher_port}"
    )
    logger.info(
        "ZeroMQ publisher bound - port=%d",
        settings.zmq_publisher_port,
    )


async def publish_detection(detection_data: dict) -> None:
    """
    Publish a detection to the ZeroMQ PUB socket.
    SIEM and response engines subscribe to this topic.
    """
    if not zmq_publisher:
        return

    topic   = ENGINE_ZMQ_TOPICS[EngineID.WINDOWS_EVENT]
    payload = json.dumps(detection_data, default=str).encode("utf-8")

    await zmq_publisher.send_multipart([topic, payload])
    logger.debug(
        "Detection published via ZeroMQ - topic=%s",
        topic.decode(),
    )


# ============================================================================
# Intelligence pipeline
# ============================================================================

async def run_pipeline() -> None:
    """
    The core intelligence pipeline loop.
    Runs continuously as a background asyncio task.

    Each cycle:
    1. Pulls unprocessed raw events from the database
    2. Normalizes each event into a NormalizedTelemetryPayload
    3. Runs all detection algorithms
    4. Updates entity observations in local db and shared entity store
    5. Publishes detections via ZeroMQ
    6. Broadcasts to WebSocket clients
    7. Marks raw events as processed

    The harvester writes raw events to the database asynchronously.
    The pipeline processes them on its own cycle independent of collection.
    """
    logger.info("Intelligence pipeline started")

    while True:
        try:
            await _pipeline_cycle()
        except Exception as e:
            logger.error("Pipeline cycle error - error=%s", str(e))

        # Pipeline cycle interval - process every 2 seconds
        await asyncio.sleep(2)


async def _pipeline_cycle() -> None:
    """Execute a single pipeline processing cycle."""
    raw_events = db.get_unprocessed_raw_events(limit=500)

    if not raw_events:
        return

    logger.debug("Pipeline cycle - processing %d raw events", len(raw_events))

    processed_count  = 0
    detection_count  = 0

    for raw_event in raw_events:
        event_id = raw_event.get("id")

        try:
            # -- Step 1: Normalize -------------------------------------------
            payload = normalizer.normalize(raw_event)

            if payload is None:
                db.mark_raw_event_processed(event_id)
                continue

            # -- Step 2: Write normalized event ------------------------------
            db.insert_normalized_event(payload)

            # -- Step 3: Run detections --------------------------------------
            detections = detector.run(payload)

            # -- Step 4: Write detections ------------------------------------
            for detection in detections:
                db.insert_detection(detection)
                detection_count += 1

                # -- Step 5: Publish via ZeroMQ ------------------------------
                await publish_detection(detection.model_dump(mode="json"))

                # -- Step 6: Broadcast to WebSocket clients ------------------
                await _broadcast_detection(detection.model_dump(mode="json"))

            # -- Step 7: Update entity observations -------------------------
            await entity_mgr.process(payload, detections)

            # -- Step 8: Broadcast event to WebSocket clients ---------------
            await _broadcast_event(payload.model_dump(mode="json"))

            # -- Step 9: Mark raw event as processed ------------------------
            db.mark_raw_event_processed(event_id)
            processed_count += 1

        except Exception as e:
            logger.error(
                "Pipeline error processing event - event_id=%s error=%s",
                event_id,
                str(e),
            )
            # Still mark as processed to avoid infinite retry on bad events
            db.mark_raw_event_processed(event_id)

    if processed_count > 0:
        logger.info(
            "Pipeline cycle complete - processed=%d detections=%d",
            processed_count,
            detection_count,
        )


async def _broadcast_detection(detection_data: dict) -> None:
    """Broadcast a detection to all connected WebSocket clients."""
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type":      "detection",
                "engine":    EngineID.WINDOWS_EVENT.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data":      detection_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


async def _broadcast_event(event_data: dict) -> None:
    """Broadcast a normalized event to all connected WebSocket clients."""
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type":      "event",
                "engine":    EngineID.WINDOWS_EVENT.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data":      event_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


# App reference for WebSocket broadcasting
_app_instance = None

def _get_app():
    return _app_instance

def harvester_worker() -> None:
    """
    Launches the Go WinRM harvester as a subprocess and reads its
    stdout line by line. Each line is a JSON-encoded raw event written
    by the harvester binary. Runs on a dedicated background thread since
    the subprocess read loop blocks.
    """
    logger.info("Starting WinRM harvester subprocess")

    env = os.environ.copy()

    process = subprocess.Popen(
        ["/usr/local/bin/rexdr-harvester"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    def read_stderr():
        for line in process.stderr:
            logger.info("[harvester] %s", line.rstrip())

    threading.Thread(target=read_stderr, daemon=True).start()

    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            db.insert_raw_event(event)
        except json.JSONDecodeError:
            logger.warning("Harvester produced non-JSON line - line=%s", line[:200])
        except Exception as e:
            logger.error("Failed to insert harvester event - error=%s", str(e))

    process.wait()
    logger.error(
        "Harvester subprocess exited - return_code=%d",
        process.returncode,
    )

# ============================================================================
# Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app):
    """
    FastAPI lifespan context manager.
    Handles startup and shutdown of all engine components.
    """
    global _app_instance
    _app_instance = app

    logger.info("=== REXDR Windows Event Intelligence Engine starting ===")

    # -- Startup -------------------------------------------------------------
    db.connect()
    logger.info("Database connected")

    await entity_store.connect()
    logger.info("Entity store connected")

    harvester_thread = threading.Thread(target=harvester_worker, daemon=True)
    harvester_thread.start()
    logger.info("Harvester subprocess thread started")

    await init_zmq()

    # Start the intelligence pipeline as a background task
    pipeline_task = asyncio.create_task(run_pipeline())
    logger.info("Intelligence pipeline started")

    logger.info(
        "=== Windows Event engine ready - api=http://0.0.0.0:%d ===",
        settings.api_port,
    )

    yield

    # -- Shutdown ------------------------------------------------------------
    logger.info("Windows Event engine shutting down")

    pipeline_task.cancel()
    try:
        await pipeline_task
    except asyncio.CancelledError:
        pass

    if zmq_publisher:
        zmq_publisher.close()
    if zmq_context:
        zmq_context.term()

    await entity_store.close()
    db.close()

    logger.info("=== Windows Event engine stopped ===")


# ============================================================================
# Entry point
# ============================================================================

def main() -> None:
    """Start the Windows Event Intelligence engine."""
    app = create_app(db=db)

    # Attach lifespan to the app
    app.router.lifespan_context = lifespan

    uvicorn.run(
        app,
        host    = settings.api_host,
        port    = settings.api_port,
        workers = settings.api_workers,
        log_level = settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()