"""
rexdr - Active Directory Intelligence Engine
database.py - DuckDB database layer for the Identity engine

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Extends BaseDatabase with the Identity engine schema. Owns
          the identity.duckdb file. Defines tables for raw AD events,
          normalized payloads, domain group snapshots, detections, and
          entity observations. Provides all read and write methods
          this engine needs. No other engine writes to this database.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

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

# Named explicitly so reads never depend on physical column order - ALTER
# TABLE appends at the end while CREATE TABLE places a column mid-list, and
# a positional mismatch fails silently rather than loudly.
ENTITY_COLUMNS = [
    "entity_id", "entity_type", "last_seen", "event_count",
    "detection_count", "risk_contribution", "behavioral_flags",
    "latest_detection", "known_groups", "known_auth_hosts", "updated_at",
]

COMPUTER_COLUMNS = [
    "computer_name", "dns_hostname", "distinguished_name", "container_path",
    "operating_system", "operating_system_version", "user_account_control",
    "is_enabled", "is_domain_controller", "is_trusted_for_delegation",
    "uac_flags", "service_principal_names", "when_created", "last_logon",
    "first_seen", "last_synced",
]

RAW_EVENT_COLUMNS = [
    "id", "target_host", "target_ip", "event_id", "time_created",
    "computer", "username", "target_username", "service_name",
    "encryption_type", "message", "received_at", "processed",
]

SNAPSHOT_COLUMNS = ["snapshot_id", "taken_at", "group_name", "members", "member_count"]

DETECTION_COLUMNS = [
    "detection_id", "detection_code", "engine_id", "timestamp",
    "severity", "title", "description", "entity_id", "entity_type",
    "evidence", "mitre_tactic", "mitre_technique", "status",
    "risk_contribution", "created_at",
]

class IdentityDatabase(BaseDatabase):
    """
    DuckDB database layer for the Active Directory Intelligence engine.
    Extends BaseDatabase and implements schema_init().
    Owns identity.duckdb exclusively.
    """

    def __init__(self, data_dir) -> None:
        super().__init__(EngineID.IDENTITY, data_dir)

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def schema_init(self) -> None:
        """Create all tables for the Identity engine."""

        # Raw AD security events from the Go collector
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_events (
                id              VARCHAR PRIMARY KEY,
                target_host     VARCHAR NOT NULL,
                target_ip       VARCHAR NOT NULL,
                event_id        INTEGER NOT NULL,
                time_created    TIMESTAMP NOT NULL,
                computer        VARCHAR,
                username        VARCHAR,
                target_username VARCHAR,
                service_name    VARCHAR,
                encryption_type VARCHAR,
                message         TEXT,
                received_at     TIMESTAMP NOT NULL,
                processed       BOOLEAN DEFAULT FALSE
            )
        """)

        # Normalized telemetry payloads
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS normalized_events (
                event_id         VARCHAR PRIMARY KEY,
                engine_id        VARCHAR NOT NULL,
                timestamp        TIMESTAMP NOT NULL,
                source_ip        VARCHAR,
                destination_ip   VARCHAR,
                source_host      VARCHAR,
                destination_host VARCHAR,
                username         VARCHAR,
                event_type       VARCHAR NOT NULL,
                event_code       VARCHAR,
                description      TEXT NOT NULL,
                raw_data         JSON,
                zone_source      VARCHAR,
                zone_destination VARCHAR,
                is_cross_zone    BOOLEAN DEFAULT FALSE,
                tags             JSON DEFAULT '[]',
                severity         VARCHAR NOT NULL,
                created_at       TIMESTAMP NOT NULL
            )
        """)

        # Domain group membership snapshots - point in time
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_snapshots (
                snapshot_id   VARCHAR PRIMARY KEY,
                taken_at      TIMESTAMP NOT NULL,
                group_name    VARCHAR NOT NULL,
                members       JSON DEFAULT '[]',
                member_count  INTEGER DEFAULT 0
            )
        """)

        # Domain-joined computer objects. The authoritative list of managed
        # machines - what the directory says should be on the network, as
        # opposed to what network discovery actually finds there.
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_computers (
                computer_name              VARCHAR PRIMARY KEY,
                dns_hostname               VARCHAR,
                distinguished_name         VARCHAR NOT NULL,
                container_path             VARCHAR,
                operating_system           VARCHAR,
                operating_system_version   VARCHAR,
                user_account_control       INTEGER,
                is_enabled                 BOOLEAN DEFAULT TRUE,
                is_domain_controller       BOOLEAN DEFAULT FALSE,
                is_trusted_for_delegation  BOOLEAN DEFAULT FALSE,
                uac_flags                  JSON DEFAULT '[]',
                service_principal_names    JSON DEFAULT '[]',
                when_created               TIMESTAMP,
                last_logon                 TIMESTAMP,
                first_seen                 TIMESTAMP NOT NULL,
                last_synced                TIMESTAMP NOT NULL
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
                known_groups        JSON DEFAULT '[]',
                known_auth_hosts    JSON DEFAULT '[]',
                updated_at          TIMESTAMP NOT NULL
            )
        """)

        logger.info("Identity engine schema initialized")

    # -------------------------------------------------------------------------
    # Raw event writes
    # -------------------------------------------------------------------------

    def insert_raw_event(self, event: dict) -> None:
        """Insert a raw AD security event from the Go collector."""
        self.conn.execute("""
            INSERT INTO raw_events (
                id, target_host, target_ip, event_id, time_created,
                computer, username, target_username, service_name,
                encryption_type, message, received_at, processed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING
        """, [
            event.get("id"),
            event.get("target_host"),
            event.get("target_ip"),
            event.get("event_id"),
            event.get("time_created"),
            event.get("computer"),
            event.get("username"),
            event.get("target_username"),
            event.get("service_name"),
            event.get("encryption_type"),
            event.get("message"),
            datetime.now(timezone.utc),
            False,
        ])

    def mark_raw_event_processed(self, event_id: str) -> None:
        self.conn.execute(
            "UPDATE raw_events SET processed = TRUE WHERE id = ?",
            [event_id]
        )

    def get_unprocessed_raw_events(self, limit: int = 500) -> list[dict]:
        rows = self.conn.execute(f"""
            SELECT {', '.join(RAW_EVENT_COLUMNS)} FROM raw_events
            WHERE processed = FALSE
            ORDER BY time_created ASC
            LIMIT ?
        """, [limit]).fetchall()

        return [dict(zip(RAW_EVENT_COLUMNS, row)) for row in rows]

    # -------------------------------------------------------------------------
    # Normalized event writes
    # -------------------------------------------------------------------------

    def insert_normalized_event(self, payload: NormalizedTelemetryPayload) -> None:
        self.conn.execute("""
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
    # Domain snapshot writes
    # -------------------------------------------------------------------------

    def insert_snapshot(self, snapshot_id: str, group_name: str, members: list[str]) -> None:
        """Insert a point-in-time domain group membership snapshot."""
        self.conn.execute("""
            INSERT INTO domain_snapshots (
                snapshot_id, taken_at, group_name, members, member_count
            ) VALUES (?, ?, ?, ?, ?)
        """, [
            snapshot_id,
            datetime.now(timezone.utc),
            group_name,
            json.dumps(members),
            len(members),
        ])

    def get_latest_snapshot(self, group_name: str) -> dict | None:
        """Get the most recent snapshot for a group, or None if none exists."""
        row = self.conn.execute(f"""
            SELECT {', '.join(SNAPSHOT_COLUMNS)} FROM domain_snapshots
            WHERE group_name = ?
            ORDER BY taken_at DESC
            LIMIT 1
        """, [group_name]).fetchone()

        if not row:
            return None

        result = dict(zip(SNAPSHOT_COLUMNS, row))
        if isinstance(result["members"], str):
            result["members"] = json.loads(result["members"])
        return result

    def get_previous_snapshot(self, group_name: str) -> dict | None:
        """Get the second-most-recent snapshot for diffing against the latest."""
        rows = self.conn.execute(f"""
            SELECT {', '.join(SNAPSHOT_COLUMNS)} FROM domain_snapshots
            WHERE group_name = ?
            ORDER BY taken_at DESC
            LIMIT 2
        """, [group_name]).fetchall()

        if len(rows) < 2:
            return None

        result = dict(zip(SNAPSHOT_COLUMNS, rows[1]))
        if isinstance(result["members"], str):
            result["members"] = json.loads(result["members"])
        return result

    # -------------------------------------------------------------------------
    # Detection writes
    # -------------------------------------------------------------------------

    def insert_detection(self, detection: Detection) -> None:
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
            json.dumps([e.model_dump(mode="json") for e in detection.evidence], default=str),
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

    def update_detection_status(self, detection_id: str, status: str) -> bool:
        """
        Update a detection's lifecycle status. Returns False if the detection
        does not exist. Stats and list endpoints filter on status = 'open', so
        marking one false_positive removes it from every tally, the alert
        badge and the risk board without deleting the record.
        """
        existing = self.conn.execute(
            "SELECT COUNT(*) FROM detections WHERE detection_id = ?",
            [detection_id]
        ).fetchone()

        if not existing or existing[0] == 0:
            return False

        self.conn.execute(
            "UPDATE detections SET status = ? WHERE detection_id = ?",
            [status, detection_id]
        )
        logger.info("Detection status updated - id=%s status=%s", detection_id, status)
        return True

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
        new_group: str | None = None,
        new_auth_host: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)

        existing = self.conn.execute(
            "SELECT known_groups, known_auth_hosts, event_count, detection_count "
            "FROM entity_observations WHERE entity_id = ?",
            [entity_id]
        ).fetchone()

        if existing:
            known_groups     = json.loads(existing[0]) if isinstance(existing[0], str) else existing[0] or []
            known_auth_hosts = json.loads(existing[1]) if isinstance(existing[1], str) else existing[1] or []
            event_count      = existing[2] + 1
            detection_count  = existing[3] + (1 if latest_detection else 0)

            if new_group and new_group not in known_groups:
                known_groups.append(new_group)
            if new_auth_host and new_auth_host not in known_auth_hosts:
                known_auth_hosts.append(new_auth_host)
                known_auth_hosts = known_auth_hosts[-100:]

            self.conn.execute("""
                UPDATE entity_observations SET
                    last_seen           = ?,
                    event_count         = ?,
                    detection_count     = ?,
                    risk_contribution   = ?,
                    behavioral_flags    = ?,
                    latest_detection    = COALESCE(?, latest_detection),
                    known_groups        = ?,
                    known_auth_hosts    = ?,
                    updated_at          = ?
                WHERE entity_id = ?
            """, [
                now, event_count, detection_count, risk_contribution,
                json.dumps(behavioral_flags), latest_detection,
                json.dumps(known_groups), json.dumps(known_auth_hosts),
                now, entity_id,
            ])
        else:
            self.conn.execute("""
                INSERT INTO entity_observations (
                    entity_id, entity_type, last_seen, event_count,
                    detection_count, risk_contribution, behavioral_flags,
                    latest_detection, known_groups, known_auth_hosts, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                entity_id, entity_type.value, now, 1,
                1 if latest_detection else 0, risk_contribution,
                json.dumps(behavioral_flags), latest_detection,
                json.dumps([new_group] if new_group else []),
                json.dumps([new_auth_host] if new_auth_host else []),
                now,
            ])

    def upsert_computer(self, computer: dict) -> None:
        """Insert or refresh a domain computer object from an LDAP sync."""
        now = datetime.now(timezone.utc)
        self.conn.execute("""
            INSERT INTO domain_computers (
                computer_name, dns_hostname, distinguished_name, container_path,
                operating_system, operating_system_version, user_account_control,
                is_enabled, is_domain_controller, is_trusted_for_delegation,
                uac_flags, service_principal_names, when_created, last_logon,
                first_seen, last_synced
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (computer_name) DO UPDATE SET
                dns_hostname              = excluded.dns_hostname,
                distinguished_name        = excluded.distinguished_name,
                container_path            = excluded.container_path,
                operating_system          = excluded.operating_system,
                operating_system_version  = excluded.operating_system_version,
                user_account_control      = excluded.user_account_control,
                is_enabled                = excluded.is_enabled,
                is_domain_controller      = excluded.is_domain_controller,
                is_trusted_for_delegation = excluded.is_trusted_for_delegation,
                uac_flags                 = excluded.uac_flags,
                service_principal_names   = excluded.service_principal_names,
                last_logon                = excluded.last_logon,
                last_synced               = excluded.last_synced
        """, [
            computer.get("computer_name"),
            computer.get("dns_hostname"),
            computer.get("distinguished_name"),
            computer.get("container_path"),
            computer.get("operating_system"),
            computer.get("operating_system_version"),
            computer.get("user_account_control"),
            computer.get("is_enabled"),
            computer.get("is_domain_controller"),
            computer.get("is_trusted_for_delegation"),
            json.dumps(computer.get("uac_flags", [])),
            json.dumps(computer.get("service_principal_names", [])),
            computer.get("when_created"),
            computer.get("last_logon"),
            now,
            now,
        ])

    def get_computers(self, limit: int = 500) -> list[dict]:
        """Get all known domain computers, domain controllers first."""
        rows = self.conn.execute(f"""
            SELECT {', '.join(COMPUTER_COLUMNS)} FROM domain_computers
            ORDER BY is_domain_controller DESC, computer_name ASC
            LIMIT ?
        """, [limit]).fetchall()

        results = [dict(zip(COMPUTER_COLUMNS, row)) for row in rows]

        for computer in results:
            for field in ("uac_flags", "service_principal_names"):
                value = computer.get(field)
                if isinstance(value, str):
                    try:
                        computer[field] = json.loads(value)
                    except (ValueError, TypeError):
                        computer[field] = []
                elif value is None:
                    computer[field] = []

        return results

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def get_recent_tgs_requests(self, username: str, window_minutes: int) -> int:
        """Count Kerberos service ticket (TGS) requests for a user in the window."""
        result = self.conn.execute("""
            SELECT COUNT(*) FROM raw_events
            WHERE username = ?
            AND event_id = 4769
            AND time_created >= NOW() - INTERVAL '1 minute' * ?
        """, [username, window_minutes]).fetchone()
        return result[0] if result else 0

    def get_known_auth_hosts(self, username: str) -> list[str]:
        """Get the set of hosts a user has previously authenticated to."""
        row = self.conn.execute(
            "SELECT known_auth_hosts FROM entity_observations WHERE entity_id = ?",
            [username]
        ).fetchone()
        if not row:
            return []
        return json.loads(row[0]) if isinstance(row[0], str) else row[0] or []

    def get_recent_detections(self, limit: int = 50, severity: AlertSeverity | None = None) -> list[dict]:
        query = f"SELECT {', '.join(DETECTION_COLUMNS)} FROM detections"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity.value)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [dict(zip(DETECTION_COLUMNS, row)) for row in rows]

    def get_entities(self, limit: int = 200) -> list[dict]:
        """
        Get tracked entity observations, highest risk first. This is the
        Identity engine's equivalent of asset-discovery's inventory - the
        accounts the engine has actually seen, what groups they belong to,
        and where they have authenticated from.
        """
        rows = self.conn.execute(f"""
            SELECT {', '.join(ENTITY_COLUMNS)} FROM entity_observations
            ORDER BY risk_contribution DESC, last_seen DESC
            LIMIT ?
        """, [limit]).fetchall()

        results = [dict(zip(ENTITY_COLUMNS, row)) for row in rows]

        for entity in results:
            for field in ("behavioral_flags", "known_groups", "known_auth_hosts"):
                value = entity.get(field)
                if isinstance(value, str):
                    try:
                        entity[field] = json.loads(value)
                    except (ValueError, TypeError):
                        entity[field] = []
                elif value is None:
                    entity[field] = []

        return results

    def get_stats(self) -> dict:
        total_events = self.conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
        total_detections = self.conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        open_detections = self.conn.execute(
            "SELECT COUNT(*) FROM detections WHERE status = 'open'"
        ).fetchone()[0]
        total_snapshots = self.conn.execute("SELECT COUNT(*) FROM domain_snapshots").fetchone()[0]
        total_computers = self.conn.execute("SELECT COUNT(*) FROM domain_computers").fetchone()[0]

        return {
            "total_events":      total_events,
            "total_detections":  total_detections,
            "open_detections":   open_detections,
            "total_snapshots":   total_snapshots,
            "total_computers":   total_computers,
        }