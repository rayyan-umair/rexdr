"""
rexdr - SIEM Correlation Engine
main.py - Engine entry point and correlation pipeline

Author  : Rayyan Umair
Date    : 2026-06-15
Purpose : Entry point for the SIEM Correlation engine. Initializes
          all components, attaches to every other engine's database
          for cross-engine SQL correlation, subscribes to ZeroMQ
          publishers, and runs two background tasks - the Sigma
          matching pipeline and the chain correlation pass.
          This is the engine where REXDR's core differentiator
          comes to life - detections from isolated engines become
          unified attack chains here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

# -- Third Party -------------------------------------------------------------
import uvicorn
import zmq
import zmq.asyncio

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store import EntityStore
from siem.api import create_app
from siem.config import settings
from siem.correlation import ChainBuilder
from siem.database import SiemDatabase
from siem.replay import ReplayEngine
from siem.sigma_engine import SigmaEngine

# ============================================================================

logging.basicConfig(
    level  = settings.log_level,
    format = settings.log_format,
)
logger = logging.getLogger(__name__)

# ============================================================================
# Global component instances
# ============================================================================

db             = SiemDatabase(data_dir=settings.data_dir)
entity_store   = EntityStore(data_dir=settings.data_dir)
sigma_engine   = SigmaEngine()
chain_builder  = ChainBuilder(db=db, entity_store=entity_store)
replay_engine  = ReplayEngine(sigma_engine=sigma_engine)

# ZeroMQ context and subscriber socket
zmq_context:    zmq.asyncio.Context | None = None
zmq_subscriber: zmq.asyncio.Socket | None  = None

# App reference for WebSocket broadcasting
_app_instance = None

def _get_app():
    return _app_instance


# ============================================================================
# ZeroMQ subscriber
# ============================================================================

async def init_zmq() -> None:
    """
    Initialize the ZeroMQ SUB socket and connect to all publisher engines.
    SIEM subscribes to windows_event, dns, and identity - the three
    engines that publish via ZeroMQ PUB sockets.
    """
    global zmq_context, zmq_subscriber

    zmq_context    = zmq.asyncio.Context()
    zmq_subscriber = zmq_context.socket(zmq.SUB)

    publisher_hosts = {
        5555: "windows-event",
        5557: "dns",
        5558: "identity",
    }

    for port in settings.zmq_subscriber_ports:
        host = publisher_hosts.get(port, "localhost")
        zmq_subscriber.connect(f"tcp://{host}:{port}")
        logger.info("ZeroMQ subscriber connected - host=%s port=%d", host, port)

    # Subscribe to all topics
    zmq_subscriber.setsockopt(zmq.SUBSCRIBE, b"")


async def listen_for_detections() -> None:
    """
    Background task that listens for incoming detections published
    by other engines via ZeroMQ. Stores Sigma matches when a detection
    matches a loaded rule. The chain builder operates independently
    via the DuckDB ATTACH cross-engine queries, not directly from this
    stream - this stream is for Sigma rule matching only.
    """
    if not zmq_subscriber:
        return

    logger.info("Listening for cross-engine detections via ZeroMQ")

    while True:
        try:
            topic, payload = await zmq_subscriber.recv_multipart()
            detection_data = json.loads(payload.decode("utf-8"))

            # Run the detection event through Sigma matching as well
            matches = sigma_engine.match_event(detection_data)
            for match in matches:
                db.insert_sigma_match(match)
                await _broadcast_sigma_match(match)

        except Exception as e:
            logger.error("ZeroMQ listener error - error=%s", str(e))
            await asyncio.sleep(1)


# ============================================================================
# Correlation pipeline
# ============================================================================

async def run_correlation_loop() -> None:
    """
    The core correlation pipeline loop. Runs the chain builder's
    correlation pass on chain_check_interval_seconds. This is where
    cross-engine attack chains are formed - REXDR's primary
    differentiating output.
    """
    logger.info("Correlation pipeline started")

    while True:
        try:
            sigma_engine.maybe_reload()
            new_chains = chain_builder.run_correlation_pass()

            for chain in new_chains:
                await _broadcast_chain(chain.model_dump(mode="json"))

        except Exception as e:
            logger.error("Correlation pass error - error=%s", str(e))

        await asyncio.sleep(settings.chain_check_interval_seconds)


async def _broadcast_chain(chain_data: dict) -> None:
    """Broadcast a newly formed attack chain to WebSocket clients."""
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type":      "attack_chain",
                "engine":    "siem",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data":      chain_data,
            })
            logger.info(
                "Attack chain broadcast - title=%s severity=%s",
                chain_data.get("title"),
                chain_data.get("severity"),
            )
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


async def _broadcast_sigma_match(match_data: dict) -> None:
    """Broadcast a Sigma rule match to WebSocket clients."""
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type":      "sigma_match",
                "engine":    "siem",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data":      match_data,
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

    logger.info("=== REXDR SIEM Correlation Engine starting ===")

    db.connect()
    logger.info("Database connected")

    # Attach all other engine databases for cross-engine correlation
    db.attach_all_engines()
    logger.info("Cross-engine databases attached")

    entity_store.connect()
    logger.info("Entity store connected")

    await init_zmq()

    zmq_task = asyncio.create_task(listen_for_detections())
    correlation_task = asyncio.create_task(run_correlation_loop())

    logger.info(
        "=== SIEM engine ready - rules=%d api=http://0.0.0.0:%d ===",
        sigma_engine.rule_count(),
        settings.api_port,
    )

    yield

    logger.info("SIEM engine shutting down")

    zmq_task.cancel()
    correlation_task.cancel()

    for task in [zmq_task, correlation_task]:
        try:
            await task
        except asyncio.CancelledError:
            pass

    if zmq_subscriber:
        zmq_subscriber.close()
    if zmq_context:
        zmq_context.term()

    entity_store.close()
    db.close()

    logger.info("=== SIEM engine stopped ===")


# ============================================================================
# Entry point
# ============================================================================

def main() -> None:
    """Start the SIEM Correlation engine."""
    app = create_app(db=db, sigma_engine=sigma_engine, replay_engine=replay_engine)
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