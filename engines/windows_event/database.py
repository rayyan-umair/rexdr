"""
rexdr - Windows Event Intelligence Engine
database.py - DuckDB database layer for the Windows Event engine

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Extends BaseDatabase with the Windows Event engine schema.
          Owns the windows_event.duckdb file. Defines all tables for
          raw events, normalized payloads, detections, and entity state.
          Provides all read and write methods this engine needs.
          No other engine writes to this database.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

# -- Internal ----------------------------------------------------------------
from rexdr_core.database import BaseDatabase
from rexdr_core.identity import EngineID
from rexdr_core.schemas import (
    AlertSeverity,
    Detection,
    DetectionStatus,
    EntityType,
    NormalizedTelemetryPayload,
)

# ============================================================================

logger = logging.getLogger(__name__)


class WindowsEventDatabase(BaseDatabase):
    """
    DuckDB database layer for the Windows Event Intelligence engine.
    Extends BaseDatabase and implements schema_init().
    Owns windows_event.duckdb exclusively - no other engine writes here.
    """

    def __init__(self, data_dir) -> None:
        super().__init__(EngineID.WINDOWS_EVENT, data_dir)

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def schema_init(self) -> None:
        """
        Create all tables for the Windows Event engine.
        Called automatically by BaseDatabase.connect().
        """

        # Raw events as received from the harvester before normalization
        self.execute("""
            CREATE TABLE IF NOT EXISTS raw_events (
                id              VARCHAR PRIMARY KEY,
                target_host     VARCHAR NOT NULL,
                target_ip       VARCHAR NOT NULL,
                log_name        VARCHAR NOT NULL,
                event_id        INTEGER NOT NULL,
                time_created    TIMESTAMP NOT NULL,
                level           VARCHAR,
                provider_name   VARCHAR,
                computer        VARCHAR,
                user_id         VARCHAR,
                message         TEXT,
                raw_xml         TEXT,
                received_at     TIMESTAMP NOT NULL,
                processed       BOOLEAN DEFAULT FALSE
            )
        """)

        # Normalized telemetry payloads ready for intelligence processing
        self.execute("""
            CREATE TABLE IF NOT EXISTS normalized_events (
                event_id        VARCHAR PRIMARY KEY,
                engine_id       VARCHAR NOT NULL,
                timestamp       TIMESTAMP NOT NULL,
                source_ip       VARCHAR,
                destination_ip  VARCHAR,
                source_host     VARCHAR,
                destination_host VARCHAR,
                username        VARCHAR,
                event_type      VARCHAR NOT NULL,
                event_code      VARCHAR,
                description     TEXT NOT NULL,
                raw_data        JSON,
                zone_source     VARCHAR,
                zone_destination VARCHAR,
                is_cross_zone   BOOLEAN DEFAULT FALSE,
                tags            JSON DEFAULT '[]',
                severity        VARCHAR NOT NULL,
                created_at      TIMESTAMP NOT NULL
            )
        """)

        # Detections produced by the intelligence layer
        self.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                detection_id        VARCHAR PRIMARY KEY,
                detection_code      VARCHAR NOT NULL,
                engine_id           VARCHAR NOT NULL,
                timestamp           TIMESTAMP NOT NULL,
                severity            VARCHAR NOT NULL,
                title               VARCHAR NOT NULL,
                description         TEXT NOT NULL,
                entity_id           VARCHAR NOT NULL,
                entity_type         VARCHAR NOT NULL,
                evidence            JSON DEFAULT '[]',
                mitre_tactic        VARCHAR,
                mitre_technique     VARCHAR,
                status              VARCHAR DEFAULT 'open',
                risk_contribution   DOUBLE DEFAULT 0.0,
                created_at          TIMESTAMP NOT NULL
            )
        """)

        # Entity observation state tracked by this engine
        self.execute("""
            CREATE TABLE IF NOT EXISTS entity_observations (
                entity_id           VARCHAR PRIMARY KEY,
                entity_type         VARCHAR NOT NULL,
                last_seen           TIMESTAMP NOT NULL,
                event_count         INTEGER DEFAULT 0,
                detection_count     INTEGER DEFAULT 0,
                risk_contribution   DOUBLE DEFAULT 0.0,
                behavioral_flags    JSON DEFAULT '[]',
                latest_detection    VARCHAR,
                failed_logon_count  INTEGER DEFAULT 0,
                last_logon_hosts    JSON DEFAULT '[]',
                updated_at          TIMESTAMP NOT NULL
            )
        """)

        logger.info("Windows Event engine schema initialized")

    # -------------------------------------------------------------------------
    # Raw event writes
    # -------------------------------------------------------------------------

    def insert_raw_event(self, event: dict) -> None:
        """Insert a raw event as received from the Go harvester."""
        self.execute("""
            INSERT INTO raw_events (
                id, target_host, target_ip, log_name, event_id,
                time_created, level, provider_name, computer,
                user_id, message, raw_xml, received_at, processed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING
        """, [
            event.get("id"),
            event.get("target_host"),
            event.get("target_ip"),
            event.get("log_name"),
            event.get("event_id"),
            event.get("time_created"),
            event.get("level"),
            event.get("provider_name"),
            event.get("computer"),
            event.get("user_id"),
            event.get("message"),
            event.get("raw_xml"),
            datetime.now(timezone.utc),
            False,
        ])

    def mark_raw_event_processed(self, event_id: str) -> None:
        """Mark a raw event as processed after normalization."""
        self.execute(
            "UPDATE raw_events SET processed = TRUE WHERE id = ?",
            [event_id]
        )

    # -------------------------------------------------------------------------
    # Normalized event writes
    # -------------------------------------------------------------------------

    def insert_normalized_event(self, payload: NormalizedTelemetryPayload) -> None:
        """Insert a normalized telemetry payload."""
        self.execute("""
            INSERT INTO normalized_events (
                event_id, engine_id, timestamp, source_ip,
                destination_ip, source_host, destination_host,
                username, event_type, event_code, description,
                raw_data, zone_source, zone_destination,
                is_cross_zone, tags, severity, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (event_id) DO NOTHING
        """, [
            str(payload.event_id),
            payload.engine_id.value,
            payload.timestamp,
            payload.source_ip,
            payload.destination_ip,
            payload.source_host,
            payload.destination_host,
            payload.username,
            payload.event_type,
            payload.event_code,
            payload.description,
            json.dumps(payload.raw_data, default=str),
            payload.zone_source,
            payload.zone_destination,
            payload.is_cross_zone,
            json.dumps(payload.tags),
            payload.severity.value,
            datetime.now(timezone.utc),
        ])

    # -------------------------------------------------------------------------
    # Detection writes
    # -------------------------------------------------------------------------

    def insert_detection(self, detection: Detection) -> None:
        """Insert a confirmed detection from the intelligence layer."""
        self.execute("""
            INSERT INTO detections (
                detection_id, detection_code, engine_id, timestamp,
                severity, title, description, entity_id, entity_type,
                evidence, mitre_tactic, mitre_technique, status,
                risk_contribution, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (detection_id) DO NOTHING
        """, [
            str(detection.detection_id),
            detection.detection_code,
            detection.engine_id.value,
            detection.timestamp,
            detection.severity.value,
            detection.title,
            detection.description,
            detection.entity_id,
            detection.entity_type.value,
            json.dumps([
                e.model_dump(mode="json") for e in detection.evidence
            ]),
            detection.mitre_tactic,
            detection.mitre_technique,
            detection.status.value,
            detection.risk_contribution,
            datetime.now(timezone.utc),
        ])
        logger.info(
            "Detection recorded - code=%s entity=%s severity=%s",
            detection.detection_code,
            detection.entity_id,
            detection.severity.value,
        )

    def update_detection_status(
        self,
        detection_id: str,
        status: DetectionStatus,
    ) -> None:
        """Update the status of an existing detection."""
        self.execute(
            "UPDATE detections SET status = ? WHERE detection_id = ?",
            [status.value, detection_id]
        )

    # -------------------------------------------------------------------------
    # Entity observation writes
    # -------------------------------------------------------------------------

    def upsert_entity_observation(
        self,
        entity_id: str,
        entity_type: EntityType,
        risk_contribution: float,
        behavioral_flags: list[str],
        latest_detection: str | None = None,
        failed_logon_increment: int = 0,
        logon_host: str | None = None,
    ) -> None:
        """
        Insert or update this engine's local observation of an entity.
        This is the engine-local record. The shared entity store is
        updated separately via EntityStore.update_observation().
        """
        now = datetime.now(timezone.utc)

        existing = self.query_one(
            "SELECT failed_logon_count, last_logon_hosts, event_count, detection_count "
            "FROM entity_observations WHERE entity_id = ?",
            [entity_id]
        )

        if existing:
            failed_logon_count = existing[0] + failed_logon_increment
            last_logon_hosts = json.loads(existing[1]) if isinstance(existing[1], str) else existing[1] or []
            event_count = existing[2] + 1
            detection_count = existing[3] + (1 if latest_detection else 0)

            if logon_host and logon_host not in last_logon_hosts:
                last_logon_hosts.append(logon_host)
                # Keep last 50 hosts only
                last_logon_hosts = last_logon_hosts[-50:]

            self.execute("""
                UPDATE entity_observations SET
                    last_seen           = ?,
                    event_count         = ?,
                    detection_count     = ?,
                    risk_contribution   = ?,
                    behavioral_flags    = ?,
                    latest_detection    = COALESCE(?, latest_detection),
                    failed_logon_count  = ?,
                    last_logon_hosts    = ?,
                    updated_at          = ?
                WHERE entity_id = ?
            """, [
                now,
                event_count,
                detection_count,
                risk_contribution,
                json.dumps(behavioral_flags),
                latest_detection,
                failed_logon_count,
                json.dumps(last_logon_hosts),
                now,
                entity_id,
            ])
        else:
            self.execute("""
                INSERT INTO entity_observations (
                    entity_id, entity_type, last_seen, event_count,
                    detection_count, risk_contribution, behavioral_flags,
                    latest_detection, failed_logon_count,
                    last_logon_hosts, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                entity_id,
                entity_type.value,
                now,
                1,
                1 if latest_detection else 0,
                risk_contribution,
                json.dumps(behavioral_flags),
                latest_detection,
                failed_logon_increment,
                json.dumps([logon_host] if logon_host else []),
                now,
            ])

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def get_recent_failed_logons(
        self,
        source_ip: str,
        window_minutes: int,
    ) -> int:
        """
        Count failed logon events from a source IP in the last window_minutes.
        Used by the brute force detection logic.
        """
        result = self.query_one("""
            SELECT COUNT(*) FROM normalized_events
            WHERE source_ip = ?
            AND event_type = 'failed_logon'
            AND timestamp >= NOW() - INTERVAL ? MINUTES
        """, [source_ip, window_minutes])
        return result[0] if result else 0

    def get_recent_logon_hosts(
        self,
        username: str,
        window_minutes: int,
    ) -> list[str]:
        """
        Get distinct destination hosts a username has logged into
        in the last window_minutes. Used for lateral movement detection.
        """
        rows = self.query_all("""
            SELECT DISTINCT destination_host FROM normalized_events
            WHERE username = ?
            AND event_type IN ('successful_logon', 'network_logon')
            AND timestamp >= NOW() - INTERVAL ? MINUTES
            AND destination_host IS NOT NULL
        """, [username, window_minutes])
        return [row[0] for row in rows]

    def get_recent_detections(
        self,
        limit: int = 50,
        severity: AlertSeverity | None = None,
    ) -> list[dict]:
        """Get recent detections, optionally filtered by severity."""
        query = "SELECT * FROM detections"
        params: list = []

        if severity:
            query += " WHERE severity = ?"
            params.append(severity.value)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.query_all(query, params)
        columns = [
            "detection_id", "detection_code", "engine_id", "timestamp",
            "severity", "title", "description", "entity_id", "entity_type",
            "evidence", "mitre_tactic", "mitre_technique", "status",
            "risk_contribution", "created_at"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_recent_events(self, limit: int = 100) -> list[dict]:
        """Get recent normalized events for the API and frontend."""
        rows = self.query_all("""
            SELECT * FROM normalized_events
            ORDER BY timestamp DESC
            LIMIT ?
        """, [limit])
        columns = [
            "event_id", "engine_id", "timestamp", "source_ip",
            "destination_ip", "source_host", "destination_host",
            "username", "event_type", "event_code", "description",
            "raw_data", "zone_source", "zone_destination",
            "is_cross_zone", "tags", "severity", "created_at"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_unprocessed_raw_events(self, limit: int = 500) -> list[dict]:
        """
        Get raw events that have not yet been normalized.
        Called by the normalization pipeline on each processing cycle.
        """
        rows = self.query_all("""
            SELECT * FROM raw_events
            WHERE processed = FALSE
            ORDER BY time_created ASC
            LIMIT ?
        """, [limit])

        columns = [
            "id", "target_host", "target_ip", "log_name", "event_id",
            "time_created", "level", "provider_name", "computer",
            "user_id", "message", "raw_xml", "received_at", "processed"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_stats(self) -> dict:
        """Return engine statistics for the health endpoint and dashboard."""
        total_events = self.query_one(
            "SELECT COUNT(*) FROM normalized_events"
        )[0]

        total_detections = self.query_one(
            "SELECT COUNT(*) FROM detections"
        )[0]

        open_detections = self.query_one(
            "SELECT COUNT(*) FROM detections WHERE status = 'open'"
        )[0]

        critical_detections = self.query_one(
            "SELECT COUNT(*) FROM detections WHERE severity = 'critical' AND status = 'open'"
        )[0]

        tracked_entities = self.query_one(
            "SELECT COUNT(*) FROM entity_observations"
        )[0]

        return {
            "total_events":       total_events,
            "total_detections":   total_detections,
            "open_detections":    open_detections,
            "critical_detections": critical_detections,
            "tracked_entities":   tracked_entities,
        }