"""
rexdr - DNS Behavioral Intelligence Engine
main.py - Engine entry point and intelligence pipeline

Author  : Rayyan Umair
Date    : 2026-06-16
Purpose : Entry point for the DNS Behavioral Intelligence engine.
          Reads raw queries written by the Go sniffer subprocess,
          normalizes, runs detections, updates entity observations,
          and publishes detections via ZeroMQ to SIEM.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Hunt the whisper."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import subprocess
import threading
import os
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

# -- Third Party -------------------------------------------------------------
import uvicorn
import zmq
import zmq.asyncio

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from dns.api import create_app
from dns.config import settings
from dns.database import DnsDatabase
from dns.detections import DnsDetections
from dns.entity import DnsEntityManager
from dns.inspector import DnsInspector

# ============================================================================

logging.basicConfig(level=settings.log_level, format=settings.log_format)
logger = logging.getLogger(__name__)

db           = DnsDatabase(data_dir=settings.data_dir)
entity_store  = EntityStoreClient(base_url="http://localhost:8008")
inspector    = DnsInspector()
detector     = DnsDetections(db=db)
entity_mgr   = DnsEntityManager(db=db, entity_store=entity_store)

zmq_context:   zmq.asyncio.Context | None = None
zmq_publisher: zmq.asyncio.Socket | None  = None

_app_instance = None

def _get_app():
    return _app_instance


async def init_zmq() -> None:
    global zmq_context, zmq_publisher
    zmq_context   = zmq.asyncio.Context()
    zmq_publisher = zmq_context.socket(zmq.PUB)
    zmq_publisher.bind(f"tcp://{settings.zmq_host}:{settings.zmq_publisher_port}")
    logger.info("ZeroMQ publisher bound - port=%d", settings.zmq_publisher_port)


async def publish_detection(detection_data: dict) -> None:
    if not zmq_publisher:
        return
    topic = ENGINE_ZMQ_TOPICS[EngineID.DNS]
    payload = json.dumps(detection_data, default=str).encode("utf-8")
    await zmq_publisher.send_multipart([topic, payload])


async def run_pipeline() -> None:
    logger.info("Intelligence pipeline started")
    while True:
        try:
            await _pipeline_cycle()
        except Exception as e:
            logger.error("Pipeline cycle error - error=%s", str(e))
        await asyncio.sleep(2)


async def _pipeline_cycle() -> None:
    raw_queries = db.get_unprocessed_raw_queries(limit=500)
    if not raw_queries:
        return

    processed_count = 0
    detection_count = 0

    for raw_query in raw_queries:
        query_id = raw_query.get("id")
        try:
            enriched = inspector.inspect(raw_query)
            db.insert_raw_query(enriched)

            payload = inspector.to_normalized_payload(enriched)
            db.insert_normalized_query(payload)

            detections = detector.run(enriched)
            for detection in detections:
                db.insert_detection(detection)
                detection_count += 1
                await publish_detection(detection.model_dump(mode="json"))
                await _broadcast_detection(detection.model_dump(mode="json"))

            entity_mgr.process(enriched, detections)
            await _broadcast_query(payload.model_dump(mode="json"))

            db.mark_raw_query_processed(query_id)
            processed_count += 1

        except Exception as e:
            logger.error("Pipeline error processing query - query_id=%s error=%s", query_id, str(e))
            db.mark_raw_query_processed(query_id)

    if processed_count > 0:
        logger.info("Pipeline cycle complete - processed=%d detections=%d", processed_count, detection_count)


async def _broadcast_detection(detection_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type": "detection", "engine": "dns",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": detection_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


async def _broadcast_query(query_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type": "query", "engine": "dns",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": query_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))

def sniffer_worker() -> None:
    """
    Launches the Go DNS sniffer as a subprocess and reads its stdout
    line by line. Each line is a JSON-encoded raw DNS query. Runs on
    a dedicated background thread since the read loop blocks.
    """
    logger.info("Starting DNS sniffer subprocess")

    env = os.environ.copy()

    process = subprocess.Popen(
        ["/usr/local/bin/rexdr-dns-sniffer"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    def read_stderr():
        for line in process.stderr:
            logger.info("[sniffer] %s", line.rstrip())

    threading.Thread(target=read_stderr, daemon=True).start()

    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            query = json.loads(line)
            db.insert_raw_query(query)
        except json.JSONDecodeError:
            logger.warning("Sniffer produced non-JSON line - line=%s", line[:200])
        except Exception as e:
            logger.error("Failed to insert sniffer query - error=%s", str(e))

    process.wait()
    logger.error(
        "Sniffer subprocess exited - return_code=%d",
        process.returncode,
    )

@asynccontextmanager
async def lifespan(app):
    global _app_instance
    _app_instance = app

    logger.info("=== REXDR DNS Behavioral Intelligence Engine starting ===")

    db.connect()
    entity_store.connect()
    await init_zmq()

    sniffer_thread = threading.Thread(target=sniffer_worker, daemon=True)
    sniffer_thread.start()
    logger.info("Sniffer subprocess thread started")

    pipeline_task = asyncio.create_task(run_pipeline())

    logger.info("=== DNS engine ready - api=http://0.0.0.0:%d ===", settings.api_port)

    yield

    logger.info("DNS engine shutting down")
    pipeline_task.cancel()
    try:
        await pipeline_task
    except asyncio.CancelledError:
        pass

    if zmq_publisher:
        zmq_publisher.close()
    if zmq_context:
        zmq_context.term()

    entity_store.close()
    db.close()
    logger.info("=== DNS engine stopped ===")


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