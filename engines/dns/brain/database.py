"""
rexdr - DNS Behavioral Intelligence Engine
database.py - DuckDB database layer for the DNS engine

Author  : Rayyan Umair
Date    : 2026-06-16
Purpose : Extends BaseDatabase with the DNS engine schema. Owns the
          dns.duckdb file. Defines all tables for raw DNS queries,
          normalized payloads, detections, and entity observations.
          Provides all read and write methods this engine needs.
          No other engine writes to this database.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Hunt the whisper."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.database import BaseDatabase
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, Detection, EntityType, NormalizedTelemetryPayload

# ============================================================================

logger = logging.getLogger(__name__)


class DnsDatabase(BaseDatabase):
    """
    DuckDB database layer for the DNS Behavioral Intelligence engine.
    Extends BaseDatabase and implements schema_init().
    Owns dns.duckdb exclusively.
    """

    def __init__(self, data_dir) -> None:
        super().__init__(EngineID.DNS, data_dir)

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def schema_init(self) -> None:
        """Create all tables for the DNS engine."""

        # Raw DNS queries as received from the Go sniffer
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_queries (
                id              VARCHAR PRIMARY KEY,
                source_ip       VARCHAR NOT NULL,
                query_name      VARCHAR NOT NULL,
                query_type      VARCHAR NOT NULL,
                response_code   VARCHAR,
                resolved_ips    JSON DEFAULT '[]',
                entropy_score   DOUBLE DEFAULT 0.0,
                timestamp       TIMESTAMP NOT NULL,
                tld             VARCHAR,
                subdomain_depth INTEGER DEFAULT 0,
                received_at     TIMESTAMP NOT NULL,
                processed       BOOLEAN DEFAULT FALSE
            )
        """)

        # Normalized telemetry payloads
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS normalized_queries (
                event_id            VARCHAR PRIMARY KEY,
                engine_id            VARCHAR NOT NULL,
                timestamp            TIMESTAMP NOT NULL,
                source_ip            VARCHAR,
                destination_ip       VARCHAR,
                source_host          VARCHAR,
                destination_host     VARCHAR,
                username             VARCHAR,
                event_type           VARCHAR NOT NULL,
                event_code           VARCHAR,
                description          TEXT NOT NULL,
                raw_data             JSON,
                zone_source          VARCHAR,
                zone_destination     VARCHAR,
                is_cross_zone        BOOLEAN DEFAULT FALSE,
                tags                 JSON DEFAULT '[]',
                severity             VARCHAR NOT NULL,
                created_at           TIMESTAMP NOT NULL
            )
        """)

        # Detections produced by the intelligence layer
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
                entity_id           VARCHAR PRIMARY KEY,
                entity_type         VARCHAR NOT NULL,
                last_seen           TIMESTAMP NOT NULL,
                event_count         INTEGER DEFAULT 0,
                detection_count     INTEGER DEFAULT 0,
                risk_contribution   DOUBLE DEFAULT 0.0,
                behavioral_flags    JSON DEFAULT '[]',
                latest_detection    VARCHAR,
                nxdomain_count      INTEGER DEFAULT 0,
                queried_domains     JSON DEFAULT '[]',
                updated_at          TIMESTAMP NOT NULL
            )
        """)

        logger.info("DNS engine schema initialized")

    # -------------------------------------------------------------------------
    # Raw query writes
    # -------------------------------------------------------------------------

    def insert_raw_query(self, query: dict) -> None:
        """Insert a raw DNS query as received from the Go sniffer."""
        self.conn.execute("""
            INSERT INTO dns_queries (
                id, source_ip, query_name, query_type, response_code,
                resolved_ips, entropy_score, timestamp, tld,
                subdomain_depth, received_at, processed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING
        """, [
            query.get("id"),
            query.get("source_ip"),
            query.get("query_name"),
            query.get("query_type"),
            query.get("response_code"),
            json.dumps(query.get("resolved_ips", [])),
            query.get("entropy_score", 0.0),
            query.get("timestamp"),
            query.get("tld"),
            query.get("subdomain_depth", 0),
            datetime.now(timezone.utc),
            False,
        ])

    def mark_raw_query_processed(self, query_id: str) -> None:
        """Mark a raw query as processed after normalization."""
        self.conn.execute(
            "UPDATE dns_queries SET processed = TRUE WHERE id = ?",
            [query_id]
        )

    def get_unprocessed_raw_queries(self, limit: int = 500) -> list[dict]:
        """Get raw DNS queries that have not yet been normalized."""
        rows = self.conn.execute("""
            SELECT * FROM dns_queries
            WHERE processed = FALSE
            ORDER BY timestamp ASC
            LIMIT ?
        """, [limit]).fetchall()

        columns = [
            "id", "source_ip", "query_name", "query_type", "response_code",
            "resolved_ips", "entropy_score", "timestamp", "tld",
            "subdomain_depth", "received_at", "processed"
        ]
        return [dict(zip(columns, row)) for row in rows]

    # -------------------------------------------------------------------------
    # Normalized query writes
    # -------------------------------------------------------------------------

    def insert_normalized_query(self, payload: NormalizedTelemetryPayload) -> None:
        """Insert a normalized DNS query payload."""
        self.conn.execute("""
            INSERT INTO normalized_queries (
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
            json.dumps(payload.raw_data),
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
        nxdomain_increment: int = 0,
        queried_domain: str | None = None,
    ) -> None:
        """Insert or update this engine's local observation of an entity."""
        now = datetime.now(timezone.utc)

        existing = self.conn.execute(
            "SELECT nxdomain_count, queried_domains, event_count, detection_count "
            "FROM entity_observations WHERE entity_id = ?",
            [entity_id]
        ).fetchone()

        if existing:
            nxdomain_count   = existing[0] + nxdomain_increment
            queried_domains  = json.loads(existing[1]) if isinstance(existing[1], str) else existing[1] or []
            event_count      = existing[2] + 1
            detection_count  = existing[3] + (1 if latest_detection else 0)

            if queried_domain and queried_domain not in queried_domains:
                queried_domains.append(queried_domain)
                queried_domains = queried_domains[-100:]

            self.conn.execute("""
                UPDATE entity_observations SET
                    last_seen           = ?,
                    event_count         = ?,
                    detection_count     = ?,
                    risk_contribution   = ?,
                    behavioral_flags    = ?,
                    latest_detection    = COALESCE(?, latest_detection),
                    nxdomain_count      = ?,
                    queried_domains     = ?,
                    updated_at          = ?
                WHERE entity_id = ?
            """, [
                now,
                event_count,
                detection_count,
                risk_contribution,
                json.dumps(behavioral_flags),
                latest_detection,
                nxdomain_count,
                json.dumps(queried_domains),
                now,
                entity_id,
            ])
        else:
            self.conn.execute("""
                INSERT INTO entity_observations (
                    entity_id, entity_type, last_seen, event_count,
                    detection_count, risk_contribution, behavioral_flags,
                    latest_detection, nxdomain_count, queried_domains, updated_at
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
                nxdomain_increment,
                json.dumps([queried_domain] if queried_domain else []),
                now,
            ])

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def get_recent_nxdomain_count(self, source_ip: str, window_seconds: int) -> int:
        """Count NXDOMAIN responses from a source IP in the window."""
        result = self.conn.execute("""
            SELECT COUNT(*) FROM dns_queries
            WHERE source_ip = ?
            AND response_code = 'NXDOMAIN'
            AND timestamp >= NOW() - INTERVAL ? SECONDS
        """, [source_ip, window_seconds]).fetchone()
        return result[0] if result else 0

    def get_record_type_count(
        self,
        source_ip: str,
        record_type: str,
        window_seconds: int,
    ) -> int:
        """Count queries of a specific record type from a source IP in the window."""
        result = self.conn.execute("""
            SELECT COUNT(*) FROM dns_queries
            WHERE source_ip = ?
            AND query_type = ?
            AND timestamp >= NOW() - INTERVAL ? SECONDS
        """, [source_ip, record_type, window_seconds]).fetchone()
        return result[0] if result else 0

    def get_query_intervals(
        self,
        source_ip: str,
        query_name: str,
        limit: int = 20,
    ) -> list[float]:
        """Get time intervals in seconds between queries for beaconing detection."""
        rows = self.conn.execute("""
            SELECT timestamp FROM dns_queries
            WHERE source_ip = ? AND query_name = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, [source_ip, query_name, limit]).fetchall()

        if len(rows) < 2:
            return []

        timestamps = [row[0] for row in rows]
        intervals = []
        for i in range(len(timestamps) - 1):
            delta = abs((timestamps[i] - timestamps[i + 1]).total_seconds())
            intervals.append(delta)

        return intervals

    def get_recent_queries(self, limit: int = 100) -> list[dict]:
        """Get recent normalized DNS queries."""
        rows = self.conn.execute("""
            SELECT * FROM normalized_queries
            ORDER BY timestamp DESC
            LIMIT ?
        """, [limit]).fetchall()

        columns = [
            "event_id", "engine_id", "timestamp", "source_ip",
            "destination_ip", "source_host", "destination_host",
            "username", "event_type", "event_code", "description",
            "raw_data", "zone_source", "zone_destination",
            "is_cross_zone", "tags", "severity", "created_at"
        ]
        return [dict(zip(columns, row)) for row in rows]

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
        total_queries = self.conn.execute(
            "SELECT COUNT(*) FROM dns_queries"
        ).fetchone()[0]

        high_entropy = self.conn.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE entropy_score >= 4.2"
        ).fetchone()[0]

        total_detections = self.conn.execute(
            "SELECT COUNT(*) FROM detections"
        ).fetchone()[0]

        open_detections = self.conn.execute(
            "SELECT COUNT(*) FROM detections WHERE status = 'open'"
        ).fetchone()[0]

        return {
            "total_queries":      total_queries,
            "high_entropy_queries": high_entropy,
            "total_detections":   total_detections,
            "open_detections":    open_detections,
        }