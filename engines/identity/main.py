"""
rexdr - Active Directory Intelligence Engine
main.py - Engine entry point and intelligence pipeline

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Entry point for the Active Directory Intelligence engine.
          Runs three concurrent background tasks - the event
          normalization pipeline (reads raw events written by the Go
          collector), the domain snapshot loop (LDAP polling on a
          fixed interval), and the FastAPI server. Publishes detections
          via ZeroMQ to SIEM and the response engine.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import json
import logging
import yaml
from contextlib import asynccontextmanager
from datetime import datetime, timezone

# -- Third Party -------------------------------------------------------------
import uvicorn
import zmq
import zmq.asyncio

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from rexdr_core.identity import ENGINE_ZMQ_TOPICS, EngineID
from identity.api import create_app
from identity.config import settings
from identity.database import IdentityDatabase
from identity.detections import IdentityDetections
from identity.domain_snapshot import DomainSnapshotEngine
from identity.entity import IdentityEntityManager

# ============================================================================

logging.basicConfig(level=settings.log_level, format=settings.log_format)
logger = logging.getLogger(__name__)

db            = IdentityDatabase(data_dir=settings.data_dir)
entity_store  = EntityStoreClient(base_url="http://entity-store:8008")
detector      = IdentityDetections(db=db)
entity_mgr    = IdentityEntityManager(db=db, entity_store=entity_store)
snapshot_engine = DomainSnapshotEngine(db=db)

zmq_context:   zmq.asyncio.Context | None = None
zmq_publisher: zmq.asyncio.Socket | None  = None

_app_instance = None

def _get_app():
    return _app_instance


# ============================================================================
# Normalization - reuses the same Windows Event ID mapping approach
# since AD events arrive through the same WinRM/Security log pipeline
# ============================================================================

from rexdr_core.schemas import AlertSeverity, NormalizedTelemetryPayload

AD_EVENT_MAP = {
    4768: ("kerberos_tgt_request",      "Kerberos TGT requested",            AlertSeverity.INFO),
    4769: ("kerberos_service_ticket",    "Kerberos service ticket requested", AlertSeverity.INFO),
    4771: ("kerberos_pre_auth_failed",   "Kerberos pre-authentication failed", AlertSeverity.LOW),
    4670: ("permissions_changed",        "Permissions on object changed",     AlertSeverity.MEDIUM),
    4704: ("user_right_assigned",        "User right assigned",               AlertSeverity.MEDIUM),
    4705: ("user_right_removed",         "User right removed",                AlertSeverity.MEDIUM),
    4719: ("audit_policy_changed",       "System audit policy changed",       AlertSeverity.HIGH),
    4624: ("successful_logon",           "Successful account logon",          AlertSeverity.INFO),
}


def normalize_ad_event(raw: dict) -> NormalizedTelemetryPayload | None:
    """Normalize a raw AD security event into a NormalizedTelemetryPayload."""
    event_id = raw.get("event_id")
    mapping = AD_EVENT_MAP.get(event_id)
    if not mapping:
        return None

    event_type, description, severity = mapping

    return NormalizedTelemetryPayload(
        engine_id         = EngineID.IDENTITY,
        timestamp         = raw.get("time_created", datetime.now(timezone.utc)),
        destination_host  = raw.get("computer") or raw.get("target_host"),
        username          = raw.get("username") or raw.get("target_username"),
        event_type        = event_type,
        event_code        = str(event_id),
        description       = f"{description} | user={raw.get('username', 'unknown')}",
        raw_data          = raw,
        severity          = severity,
    )


# ============================================================================
# ZeroMQ
# ============================================================================

async def init_zmq() -> None:
    global zmq_context, zmq_publisher
    zmq_context   = zmq.asyncio.Context()
    zmq_publisher = zmq_context.socket(zmq.PUB)
    zmq_publisher.bind(f"tcp://{settings.zmq_host}:{settings.zmq_publisher_port}")
    logger.info("ZeroMQ publisher bound - port=%d", settings.zmq_publisher_port)


async def publish_detection(detection_data: dict) -> None:
    if not zmq_publisher:
        return
    topic = ENGINE_ZMQ_TOPICS[EngineID.IDENTITY]
    payload = json.dumps(detection_data, default=str).encode("utf-8")
    await zmq_publisher.send_multipart([topic, payload])


# ============================================================================
# Event pipeline
# ============================================================================

async def run_event_pipeline() -> None:
    logger.info("Event pipeline started")
    while True:
        try:
            await _event_pipeline_cycle()
        except Exception as e:
            logger.error("Event pipeline cycle error - error=%s", str(e))
        await asyncio.sleep(settings.event_poll_interval_seconds)


async def _event_pipeline_cycle() -> None:
    raw_events = db.get_unprocessed_raw_events(limit=500)
    if not raw_events:
        return

    processed_count = 0
    detection_count = 0

    for raw_event in raw_events:
        event_id = raw_event.get("id")
        try:
            payload = normalize_ad_event(raw_event)
            if payload is None:
                db.mark_raw_event_processed(event_id)
                continue

            db.insert_normalized_event(payload)
            detections = detector.run(payload)

            for detection in detections:
                db.insert_detection(detection)
                detection_count += 1
                await publish_detection(detection.model_dump(mode="json"))
                await _broadcast_detection(detection.model_dump(mode="json"))

            entity_mgr.process(payload, detections)
            db.mark_raw_event_processed(event_id)
            processed_count += 1

        except Exception as e:
            logger.error("Event pipeline error - event_id=%s error=%s", event_id, str(e))
            db.mark_raw_event_processed(event_id)

    if processed_count > 0:
        logger.info("Event pipeline cycle complete - processed=%d detections=%d", processed_count, detection_count)


# ============================================================================
# Domain snapshot loop
# ============================================================================

async def run_snapshot_loop() -> None:
    """
    Periodically takes domain group membership snapshots against
    each configured domain controller target and runs AD-002 against
    any diffs found.
    """
    logger.info("Domain snapshot loop started")
    while True:
        try:
            await _snapshot_cycle()
        except Exception as e:
            logger.error("Snapshot cycle error - error=%s", str(e))

        await asyncio.sleep(settings.domain_snapshot_interval_minutes * 60)


async def _snapshot_cycle() -> None:
    targets = _load_dc_targets()
    if not targets:
        logger.warning("No domain controller targets configured for snapshot")
        return

    for target_ip in targets:
        diffs = snapshot_engine.take_snapshot(target_ip)

        for diff in diffs:
            detections = detector.run_group_diff(diff)
            for detection in detections:
                db.insert_detection(detection)
                entity_mgr.process_detection_only(detection)
                await publish_detection(detection.model_dump(mode="json"))
                await _broadcast_detection(detection.model_dump(mode="json"))


def _load_dc_targets() -> list[str]:
    """Load domain controller IPs from targets.yaml."""
    if not settings.winrm_targets_path.exists():
        return []

    with open(settings.winrm_targets_path, "r") as f:
        data = yaml.safe_load(f) or {}

    targets = data.get("targets", [])
    return [
        t["ip"] for t in targets
        if t.get("enabled") and "DC" in t.get("name", "").upper()
    ]


# ============================================================================
# Broadcasting
# ============================================================================

async def _broadcast_detection(detection_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type": "detection", "engine": "identity",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": detection_data,
            })
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


# ============================================================================
# Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app):
    global _app_instance
    _app_instance = app

    logger.info("=== REXDR Active Directory Intelligence Engine starting ===")

    db.connect()
    entity_store.connect()
    await init_zmq()

    event_task    = asyncio.create_task(run_event_pipeline())
    snapshot_task = asyncio.create_task(run_snapshot_loop())

    logger.info("=== Identity engine ready - api=http://0.0.0.0:%d ===", settings.api_port)

    yield

    logger.info("Identity engine shutting down")

    event_task.cancel()
    snapshot_task.cancel()

    for task in [event_task, snapshot_task]:
        try:
            await task
        except asyncio.CancelledError:
            pass

    if zmq_publisher:
        zmq_publisher.close()
    if zmq_context:
        zmq_context.term()

    entity_store.close()
    db.close()
    logger.info("=== Identity engine stopped ===")


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