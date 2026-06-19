"""
rexdr - Network Discovery Engine
database.py - DuckDB database layer for the Asset Discovery engine

Author  : Rayyan Umair
Date    : 2026-06-19
Purpose : Extends BaseDatabase with the Asset Discovery engine schema.
          Owns the asset_discovery.duckdb file. Defines tables for
          discovered assets, scan history, detections, and entity
          observations. Provides all read and write methods this
          engine needs.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Map the terrain before the enemy does."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.database import BaseDatabase
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, Detection, EntityType

# ============================================================================

logger = logging.getLogger(__name__)


class AssetDiscoveryDatabase(BaseDatabase):
    """
    DuckDB database layer for the Network Discovery engine.
    Extends BaseDatabase and implements schema_init().
    Owns asset_discovery.duckdb exclusively.
    """

    def __init__(self, data_dir) -> None:
        super().__init__(EngineID.ASSET_DISCOVERY, data_dir)

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def schema_init(self) -> None:
        """Create all tables for the Asset Discovery engine."""

        # Known asset inventory - the current state of every known device
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                ip_address       VARCHAR PRIMARY KEY,
                hostname         VARCHAR,
                mac_address      VARCHAR,
                os_fingerprint   VARCHAR,
                open_ports       JSON DEFAULT '[]',
                services         JSON DEFAULT '{}',
                network_zone     VARCHAR,
                first_seen       TIMESTAMP NOT NULL,
                last_seen        TIMESTAMP NOT NULL,
                is_known         BOOLEAN DEFAULT TRUE,
                scan_count       INTEGER DEFAULT 1
            )
        """)

        # Historical scan results - one row per scan per asset
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id          VARCHAR PRIMARY KEY,
                ip_address       VARCHAR NOT NULL,
                scanned_at       TIMESTAMP NOT NULL,
                open_ports       JSON DEFAULT '[]',
                services         JSON DEFAULT '{}',
                os_fingerprint   VARCHAR
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
                updated_at          TIMESTAMP NOT NULL
            )
        """)

        logger.info("Asset Discovery engine schema initialized")

    # -------------------------------------------------------------------------
    # Asset writes
    # -------------------------------------------------------------------------

    def upsert_asset(
        self,
        ip_address: str,
        hostname: str | None,
        mac_address: str | None,
        os_fingerprint: str | None,
        open_ports: list[int],
        services: dict,
        network_zone: str | None,
    ) -> bool:
        """
        Insert or update an asset record. Returns True if this is a
        newly discovered asset (first time seen), False if it already
        existed in the inventory.
        """
        now = datetime.now(timezone.utc)

        existing = self.conn.execute(
            "SELECT scan_count FROM assets WHERE ip_address = ?",
            [ip_address]
        ).fetchone()

        is_new = existing is None

        if is_new:
            self.conn.execute("""
                INSERT INTO assets (
                    ip_address, hostname, mac_address, os_fingerprint,
                    open_ports, services, network_zone, first_seen,
                    last_seen, is_known, scan_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                ip_address, hostname, mac_address, os_fingerprint,
                json.dumps(open_ports), json.dumps(services), network_zone,
                now, now, True, 1,
            ])
        else:
            self.conn.execute("""
                UPDATE assets SET
                    hostname        = COALESCE(?, hostname),
                    mac_address     = COALESCE(?, mac_address),
                    os_fingerprint  = COALESCE(?, os_fingerprint),
                    open_ports      = ?,
                    services        = ?,
                    network_zone    = COALESCE(?, network_zone),
                    last_seen       = ?,
                    scan_count      = scan_count + 1
                WHERE ip_address = ?
            """, [
                hostname, mac_address, os_fingerprint,
                json.dumps(open_ports), json.dumps(services), network_zone,
                now, ip_address,
            ])

        return is_new

    def insert_scan_record(
        self,
        scan_id: str,
        ip_address: str,
        open_ports: list[int],
        services: dict,
        os_fingerprint: str | None,
    ) -> None:
        """Record a single scan result in the historical scan log."""
        self.conn.execute("""
            INSERT INTO scan_history (
                scan_id, ip_address, scanned_at, open_ports,
                services, os_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, [
            scan_id, ip_address, datetime.now(timezone.utc),
            json.dumps(open_ports), json.dumps(services), os_fingerprint,
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
            json.dumps([e.model_dump(mode="json") for e in detection.evidence]),
            detection.mitre_tactic,
            detection.mitre_technique,
            detection.status.value,
            detection.risk_contribution,
            datetime.now(timezone.utc),
        ])
        logger.info(
            "Detection recorded - code=%s entity=%s severity=%s",
            detection.detection_code, detection.entity_id, detection.severity.value,
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
    ) -> None:
        now = datetime.now(timezone.utc)

        existing = self.conn.execute(
            "SELECT event_count, detection_count FROM entity_observations WHERE entity_id = ?",
            [entity_id]
        ).fetchone()

        if existing:
            self.conn.execute("""
                UPDATE entity_observations SET
                    last_seen           = ?,
                    event_count         = ?,
                    detection_count     = ?,
                    risk_contribution   = ?,
                    behavioral_flags    = ?,
                    latest_detection    = COALESCE(?, latest_detection),
                    updated_at          = ?
                WHERE entity_id = ?
            """, [
                now, existing[0] + 1, existing[1] + (1 if latest_detection else 0),
                risk_contribution, json.dumps(behavioral_flags), latest_detection,
                now, entity_id,
            ])
        else:
            self.conn.execute("""
                INSERT INTO entity_observations (
                    entity_id, entity_type, last_seen, event_count,
                    detection_count, risk_contribution, behavioral_flags,
                    latest_detection, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                entity_id, entity_type.value, now, 1,
                1 if latest_detection else 0, risk_contribution,
                json.dumps(behavioral_flags), latest_detection, now,
            ])

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def is_known_asset(self, ip_address: str) -> bool:
        """Check if an IP has been seen in a previous scan cycle."""
        result = self.conn.execute(
            "SELECT scan_count FROM assets WHERE ip_address = ?",
            [ip_address]
        ).fetchone()
        return result is not None and result[0] > 1

    def get_all_assets(self) -> list[dict]:
        """Get the full current asset inventory."""
        rows = self.conn.execute("""
            SELECT * FROM assets ORDER BY last_seen DESC
        """).fetchall()

        columns = [
            "ip_address", "hostname", "mac_address", "os_fingerprint",
            "open_ports", "services", "network_zone", "first_seen",
            "last_seen", "is_known", "scan_count"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_asset(self, ip_address: str) -> dict | None:
        """Get a single asset by IP address."""
        row = self.conn.execute(
            "SELECT * FROM assets WHERE ip_address = ?",
            [ip_address]
        ).fetchone()

        if not row:
            return None

        columns = [
            "ip_address", "hostname", "mac_address", "os_fingerprint",
            "open_ports", "services", "network_zone", "first_seen",
            "last_seen", "is_known", "scan_count"
        ]
        return dict(zip(columns, row))

    def get_recent_detections(self, limit: int = 50, severity: AlertSeverity | None = None) -> list[dict]:
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
        total_assets = self.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        total_detections = self.conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        open_detections = self.conn.execute(
            "SELECT COUNT(*) FROM detections WHERE status = 'open'"
        ).fetchone()[0]
        total_scans = self.conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]

        return {
            "total_assets":      total_assets,
            "total_detections":  total_detections,
            "open_detections":   open_detections,
            "total_scans":       total_scans,
        }