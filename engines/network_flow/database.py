"""
rexdr - Network Flow Intelligence Engine
database.py - DuckDB database layer for the Network Flow engine

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Extends BaseDatabase with the Network Flow engine schema.
          Owns the network_flow.duckdb file. Defines all tables for
          raw packets, flow records, detections, and entity observations.
          Provides all read and write methods this engine needs.
          No other engine writes to this database.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.database import BaseDatabase
from rexdr_core.identity import EngineID
from rexdr_core.schemas import (
    AlertSeverity,
    Detection,
    EntityType,
    NormalizedTelemetryPayload,
)

# ============================================================================

logger = logging.getLogger(__name__)


class NetworkFlowDatabase(BaseDatabase):
    """
    DuckDB database layer for the Network Flow Intelligence engine.
    Extends BaseDatabase and implements schema_init().
    Owns network_flow.duckdb exclusively.
    """

    def __init__(self, data_dir) -> None:
        super().__init__(EngineID.NETWORK_FLOW, data_dir)

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def schema_init(self) -> None:
        """Create all tables for the Network Flow engine."""

        # Flow records - aggregated packet streams between two endpoints
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS flow_records (
                flow_id             VARCHAR PRIMARY KEY,
                src_ip              VARCHAR NOT NULL,
                dst_ip              VARCHAR NOT NULL,
                src_port            INTEGER,
                dst_port            INTEGER,
                protocol            VARCHAR,
                start_time          TIMESTAMP NOT NULL,
                end_time            TIMESTAMP,
                packet_count        INTEGER DEFAULT 0,
                bytes_sent          BIGINT DEFAULT 0,
                bytes_received      BIGINT DEFAULT 0,
                flags               VARCHAR,
                zone_source         VARCHAR,
                zone_destination    VARCHAR,
                is_cross_zone       BOOLEAN DEFAULT FALSE,
                is_external         BOOLEAN DEFAULT FALSE,
                threat_intel_match  BOOLEAN DEFAULT FALSE,
                matched_indicator   VARCHAR,
                created_at          TIMESTAMP NOT NULL
            )
        """)

        # Normalized telemetry payloads
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS normalized_flows (
                event_id            VARCHAR PRIMARY KEY,
                engine_id           VARCHAR NOT NULL,
                timestamp           TIMESTAMP NOT NULL,
                source_ip           VARCHAR,
                destination_ip      VARCHAR,
                source_host         VARCHAR,
                destination_host    VARCHAR,
                username            VARCHAR,
                event_type          VARCHAR NOT NULL,
                event_code          VARCHAR,
                description         TEXT NOT NULL,
                raw_data            JSON,
                zone_source         VARCHAR,
                zone_destination    VARCHAR,
                is_cross_zone       BOOLEAN DEFAULT FALSE,
                tags                JSON DEFAULT '[]',
                severity            VARCHAR NOT NULL,
                created_at          TIMESTAMP NOT NULL
            )
        """)

        # Detections produced by the strike engine
        self.conn.execute("""
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
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_observations (
                entity_id               VARCHAR PRIMARY KEY,
                entity_type             VARCHAR NOT NULL,
                last_seen               TIMESTAMP NOT NULL,
                event_count             INTEGER DEFAULT 0,
                detection_count         INTEGER DEFAULT 0,
                risk_contribution       DOUBLE DEFAULT 0.0,
                behavioral_flags        JSON DEFAULT '[]',
                latest_detection        VARCHAR,
                total_bytes_sent        BIGINT DEFAULT 0,
                total_bytes_received    BIGINT DEFAULT 0,
                distinct_destinations   JSON DEFAULT '[]',
                distinct_ports_scanned  JSON DEFAULT '[]',
                updated_at              TIMESTAMP NOT NULL
            )
        """)

        logger.info("Network Flow engine schema initialized")

    # -------------------------------------------------------------------------
    # Flow record writes
    # -------------------------------------------------------------------------

    def insert_flow_record(self, flow: dict) -> None:
        """Insert a network flow record."""
        self.conn.execute("""
            INSERT INTO flow_records (
                flow_id, src_ip, dst_ip, src_port, dst_port,
                protocol, start_time, end_time, packet_count,
                bytes_sent, bytes_received, flags,
                zone_source, zone_destination, is_cross_zone,
                is_external, threat_intel_match, matched_indicator,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (flow_id) DO UPDATE SET
                end_time            = excluded.end_time,
                packet_count        = excluded.packet_count,
                bytes_sent          = excluded.bytes_sent,
                bytes_received      = excluded.bytes_received,
                threat_intel_match  = excluded.threat_intel_match,
                matched_indicator   = excluded.matched_indicator
        """, [
            flow.get("flow_id"),
            flow.get("src_ip"),
            flow.get("dst_ip"),
            flow.get("src_port"),
            flow.get("dst_port"),
            flow.get("protocol"),
            flow.get("start_time"),
            flow.get("end_time"),
            flow.get("packet_count", 0),
            flow.get("bytes_sent", 0),
            flow.get("bytes_received", 0),
            flow.get("flags"),
            flow.get("zone_source"),
            flow.get("zone_destination"),
            flow.get("is_cross_zone", False),
            flow.get("is_external", False),
            flow.get("threat_intel_match", False),
            flow.get("matched_indicator"),
            datetime.now(timezone.utc),
        ])

    # -------------------------------------------------------------------------
    # Normalized flow writes
    # -------------------------------------------------------------------------

    def insert_normalized_flow(self, payload: NormalizedTelemetryPayload) -> None:
        """Insert a normalized flow payload."""
        self.conn.execute("""
            INSERT INTO normalized_flows (
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
            json.dumps(payload.tags, default=str),
            payload.severity.value,
            datetime.now(timezone.utc),
        ])

    # -------------------------------------------------------------------------
    # Detection writes
    # -------------------------------------------------------------------------

    def insert_detection(self, detection: Detection) -> None:
        """Insert a confirmed detection."""
        self.conn.execute("""
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
        bytes_sent: int = 0,
        bytes_received: int = 0,
        destination_ip: str | None = None,
        scanned_port: int | None = None,
    ) -> None:
        """Insert or update this engine's local observation of an entity."""
        now = datetime.now(timezone.utc)

        existing = self.conn.execute(
            "SELECT total_bytes_sent, total_bytes_received, "
            "distinct_destinations, distinct_ports_scanned, "
            "event_count, detection_count "
            "FROM entity_observations WHERE entity_id = ?",
            [entity_id]
        ).fetchone()

        if existing:
            total_bytes_sent     = existing[0] + bytes_sent
            total_bytes_received = existing[1] + bytes_received
            destinations         = json.loads(existing[2]) if isinstance(existing[2], str) else existing[2] or []
            ports_scanned        = json.loads(existing[3]) if isinstance(existing[3], str) else existing[3] or []
            event_count          = existing[4] + 1
            detection_count      = existing[5] + (1 if latest_detection else 0)

            if destination_ip and destination_ip not in destinations:
                destinations.append(destination_ip)
                destinations = destinations[-100:]

            if scanned_port and scanned_port not in ports_scanned:
                ports_scanned.append(scanned_port)
                ports_scanned = ports_scanned[-500:]

            self.conn.execute("""
                UPDATE entity_observations SET
                    last_seen               = ?,
                    event_count             = ?,
                    detection_count         = ?,
                    risk_contribution       = ?,
                    behavioral_flags        = ?,
                    latest_detection        = COALESCE(?, latest_detection),
                    total_bytes_sent        = ?,
                    total_bytes_received    = ?,
                    distinct_destinations   = ?,
                    distinct_ports_scanned  = ?,
                    updated_at              = ?
                WHERE entity_id = ?
            """, [
                now,
                event_count,
                detection_count,
                risk_contribution,
                json.dumps(behavioral_flags),
                latest_detection,
                total_bytes_sent,
                total_bytes_received,
                json.dumps(destinations),
                json.dumps(ports_scanned),
                now,
                entity_id,
            ])
        else:
            self.conn.execute("""
                INSERT INTO entity_observations (
                    entity_id, entity_type, last_seen, event_count,
                    detection_count, risk_contribution, behavioral_flags,
                    latest_detection, total_bytes_sent, total_bytes_received,
                    distinct_destinations, distinct_ports_scanned, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                entity_id,
                entity_type.value,
                now,
                1,
                1 if latest_detection else 0,
                risk_contribution,
                json.dumps(behavioral_flags),
                latest_detection,
                bytes_sent,
                bytes_received,
                json.dumps([destination_ip] if destination_ip else []),
                json.dumps([scanned_port] if scanned_port else []),
                now,
            ])

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def get_recent_flows(self, limit: int = 100) -> list[dict]:
        """Get recent flow records."""
        rows = self.conn.execute("""
            SELECT * FROM flow_records
            ORDER BY start_time DESC
            LIMIT ?
        """, [limit]).fetchall()

        columns = [
            "flow_id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "start_time", "end_time", "packet_count",
            "bytes_sent", "bytes_received", "flags",
            "zone_source", "zone_destination", "is_cross_zone",
            "is_external", "threat_intel_match", "matched_indicator",
            "created_at"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_port_scan_count(
        self,
        src_ip: str,
        window_seconds: int,
    ) -> int:
        """Count distinct destination ports from a source IP in the window."""
        result = self.conn.execute("""
            SELECT COUNT(DISTINCT dst_port) FROM flow_records
            WHERE src_ip = ?
            AND start_time >= NOW() - INTERVAL ? SECONDS
        """, [src_ip, window_seconds]).fetchone()
        return result[0] if result else 0

    def get_outbound_bytes(
        self,
        src_ip: str,
        window_seconds: int,
    ) -> int:
        """Get total outbound bytes from a source IP in the window."""
        result = self.conn.execute("""
            SELECT COALESCE(SUM(bytes_sent), 0) FROM flow_records
            WHERE src_ip = ?
            AND is_external = TRUE
            AND start_time >= NOW() - INTERVAL ? SECONDS
        """, [src_ip, window_seconds]).fetchone()
        return result[0] if result else 0

    def get_distinct_internal_destinations(
        self,
        src_ip: str,
        window_seconds: int,
    ) -> list[str]:
        """Get distinct internal destination IPs from a source in the window."""
        rows = self.conn.execute("""
            SELECT DISTINCT dst_ip FROM flow_records
            WHERE src_ip = ?
            AND is_external = FALSE
            AND start_time >= NOW() - INTERVAL ? SECONDS
        """, [src_ip, window_seconds]).fetchall()
        return [row[0] for row in rows]

    def get_connection_intervals(
        self,
        src_ip: str,
        dst_ip: str,
        limit: int = 20,
    ) -> list[float]:
        """
        Get the time intervals in seconds between connections
        from src_ip to dst_ip. Used for beaconing detection.
        """
        rows = self.conn.execute("""
            SELECT start_time FROM flow_records
            WHERE src_ip = ? AND dst_ip = ?
            ORDER BY start_time DESC
            LIMIT ?
        """, [src_ip, dst_ip, limit]).fetchall()

        if len(rows) < 2:
            return []

        timestamps = [row[0] for row in rows]
        intervals = []
        for i in range(len(timestamps) - 1):
            delta = abs((timestamps[i] - timestamps[i + 1]).total_seconds())
            intervals.append(delta)

        return intervals

    def get_recent_detections(
        self,
        limit: int = 50,
        severity: AlertSeverity | None = None,
    ) -> list[dict]:
        """Get recent detections, optionally filtered by severity."""
        query  = "SELECT * FROM detections"
        params: list = []

        if severity:
            query += " WHERE severity = ?"
            params.append(severity.value)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        columns = [
            "detection_id", "detection_code", "engine_id", "timestamp",
            "severity", "title", "description", "entity_id", "entity_type",
            "evidence", "mitre_tactic", "mitre_technique", "status",
            "risk_contribution", "created_at"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_stats(self) -> dict:
        """Return engine statistics."""
        total_flows = self.conn.execute(
            "SELECT COUNT(*) FROM flow_records"
        ).fetchone()[0]

        external_flows = self.conn.execute(
            "SELECT COUNT(*) FROM flow_records WHERE is_external = TRUE"
        ).fetchone()[0]

        threat_matches = self.conn.execute(
            "SELECT COUNT(*) FROM flow_records WHERE threat_intel_match = TRUE"
        ).fetchone()[0]

        total_detections = self.conn.execute(
            "SELECT COUNT(*) FROM detections"
        ).fetchone()[0]

        open_detections = self.conn.execute(
            "SELECT COUNT(*) FROM detections WHERE status = 'open'"
        ).fetchone()[0]
        critical_detections = self.conn.execute(
            "SELECT COUNT(*) FROM detections WHERE severity = 'critical' AND status = 'open'"
        ).fetchone()[0]
        return {
            "total_flows":          total_flows,
            "external_flows":       external_flows,
            "threat_matches":       threat_matches,
            "total_detections":     total_detections,
            "open_detections":      open_detections,
            "critical_detections":  critical_detections,
        }