"""
rexdr - SIEM Correlation Engine
database.py - DuckDB database layer for the SIEM engine

Author  : Rayyan Umair
Date    : 2026-06-23
Purpose : Extends BaseDatabase with the SIEM engine schema. Owns the
          siem.duckdb file - storing Sigma matches and attack chains.
          Cross-engine correlation data now comes from engine_client.py
          over HTTP rather than DuckDB ATTACH - DuckDB does not support
          safe concurrent multi-process access to a file another
          process holds open for writing, so this engine no longer
          attaches to any other engine's database file directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.database import BaseDatabase
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AttackChain, ChainSeverity, Detection

# ============================================================================

logger = logging.getLogger(__name__)


class SiemDatabase(BaseDatabase):
    """
    DuckDB database layer for the SIEM Correlation engine.
    Extends BaseDatabase and implements schema_init().
    Owns siem.duckdb exclusively - this engine no longer attaches to
    any other engine's database file. Cross-engine data is fetched via
    engine_client.py over HTTP instead.
    """

    def __init__(self, data_dir) -> None:
        super().__init__(EngineID.SIEM, data_dir)

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def schema_init(self) -> None:
        """Create all tables for the SIEM engine."""

        # Sigma rule matches
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS sigma_matches (
                match_id        VARCHAR PRIMARY KEY,
                rule_id         VARCHAR NOT NULL,
                rule_title      VARCHAR NOT NULL,
                source_engine   VARCHAR NOT NULL,
                source_event_id VARCHAR NOT NULL,
                severity        VARCHAR NOT NULL,
                entity_id       VARCHAR NOT NULL,
                timestamp       TIMESTAMP NOT NULL,
                matched_fields  JSON DEFAULT '{}',
                created_at      TIMESTAMP NOT NULL
            )
        """)

        # Cross-engine attack chains
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attack_chains (
                chain_id              VARCHAR PRIMARY KEY,
                created_at            TIMESTAMP NOT NULL,
                updated_at            TIMESTAMP NOT NULL,
                severity              VARCHAR NOT NULL,
                title                 VARCHAR NOT NULL,
                narrative             TEXT NOT NULL,
                entity_id             VARCHAR NOT NULL,
                contributing_engines  JSON DEFAULT '[]',
                detection_ids         JSON DEFAULT '[]',
                mitre_tactics         JSON DEFAULT '[]',
                mitre_techniques      JSON DEFAULT '[]',
                is_active             BOOLEAN DEFAULT TRUE,
                is_contained          BOOLEAN DEFAULT FALSE,
                case_file_id          VARCHAR
            )
        """)

        logger.info("SIEM engine schema initialized")

    # -------------------------------------------------------------------------
    # Sigma match writes
    # -------------------------------------------------------------------------

    def insert_sigma_match(self, match: dict) -> None:
        """Insert a Sigma rule match."""
        self.conn.execute("""
            INSERT INTO sigma_matches (
                match_id, rule_id, rule_title, source_engine,
                source_event_id, severity, entity_id, timestamp,
                matched_fields, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (match_id) DO NOTHING
        """, [
            match.get("match_id"),
            match.get("rule_id"),
            match.get("rule_title"),
            match.get("source_engine"),
            match.get("source_event_id"),
            match.get("severity"),
            match.get("entity_id"),
            match.get("timestamp"),
            json.dumps(match.get("matched_fields", {})),
            datetime.now(timezone.utc),
        ])

    # -------------------------------------------------------------------------
    # Attack chain writes
    # -------------------------------------------------------------------------

    def insert_chain(self, chain: AttackChain) -> None:
        """Insert a new cross-engine attack chain."""
        self.conn.execute("""
            INSERT INTO attack_chains (
                chain_id, created_at, updated_at, severity, title,
                narrative, entity_id, contributing_engines,
                detection_ids, mitre_tactics, mitre_techniques,
                is_active, is_contained, case_file_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            str(chain.chain_id),
            chain.created_at,
            chain.updated_at,
            chain.severity.value,
            chain.title,
            chain.narrative,
            chain.entity_id,
            json.dumps([e.value for e in chain.contributing_engines]),
            json.dumps([str(d.detection_id) for d in chain.detections]),
            json.dumps(chain.mitre_tactics),
            json.dumps(chain.mitre_techniques),
            chain.is_active,
            chain.is_contained,
            chain.case_file_id,
        ])
        logger.info(
            "Attack chain created - chain_id=%s entity=%s severity=%s engines=%d",
            chain.chain_id,
            chain.entity_id,
            chain.severity.value,
            len(chain.contributing_engines),
        )

    def update_chain_severity(self, chain_id: str, severity: ChainSeverity) -> None:
        """Escalate or update a chain's severity."""
        self.conn.execute("""
            UPDATE attack_chains SET
                severity   = ?,
                updated_at = ?
            WHERE chain_id = ?
        """, [severity.value, datetime.now(timezone.utc), chain_id])

    def mark_chain_contained(self, chain_id: str, case_file_id: str) -> None:
        """Mark a chain as contained after response action."""
        self.conn.execute("""
            UPDATE attack_chains SET
                is_active     = FALSE,
                is_contained  = TRUE,
                case_file_id  = ?,
                updated_at    = ?
            WHERE chain_id = ?
        """, [case_file_id, datetime.now(timezone.utc), chain_id])

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def get_recent_chains(self, limit: int = 50) -> list[dict]:
        """Get recent attack chains."""
        rows = self.conn.execute("""
            SELECT * FROM attack_chains
            ORDER BY created_at DESC
            LIMIT ?
        """, [limit]).fetchall()

        columns = [
            "chain_id", "created_at", "updated_at", "severity", "title",
            "narrative", "entity_id", "contributing_engines",
            "detection_ids", "mitre_tactics", "mitre_techniques",
            "is_active", "is_contained", "case_file_id"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_active_chains(self) -> list[dict]:
        """Get all currently active (uncontained) attack chains."""
        rows = self.conn.execute("""
            SELECT * FROM attack_chains
            WHERE is_active = TRUE
            ORDER BY severity DESC, created_at DESC
        """).fetchall()

        columns = [
            "chain_id", "created_at", "updated_at", "severity", "title",
            "narrative", "entity_id", "contributing_engines",
            "detection_ids", "mitre_tactics", "mitre_techniques",
            "is_active", "is_contained", "case_file_id"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def chain_exists_for_entity(self, entity_id: str) -> bool:
        """Check if an active chain already exists for this entity."""
        result = self.conn.execute("""
            SELECT COUNT(*) FROM attack_chains
            WHERE entity_id = ? AND is_active = TRUE
        """, [entity_id]).fetchone()
        return result[0] > 0 if result else False

    def get_stats(self) -> dict:
        """Return engine statistics."""
        total_chains = self.conn.execute(
            "SELECT COUNT(*) FROM attack_chains"
        ).fetchone()[0]

        active_chains = self.conn.execute(
            "SELECT COUNT(*) FROM attack_chains WHERE is_active = TRUE"
        ).fetchone()[0]

        critical_chains = self.conn.execute(
            "SELECT COUNT(*) FROM attack_chains WHERE severity = 'critical' AND is_active = TRUE"
        ).fetchone()[0]

        total_matches = self.conn.execute(
            "SELECT COUNT(*) FROM sigma_matches"
        ).fetchone()[0]

        return {
            "total_chains":     total_chains,
            "active_chains":    active_chains,
            "critical_chains":  critical_chains,
            "total_sigma_matches": total_matches,
        }