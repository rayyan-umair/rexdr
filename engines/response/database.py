"""
rexdr - Incident Response Orchestration Engine
database.py - DuckDB database layer for the Response engine

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Extends BaseDatabase with the Response engine schema. Owns
          the response.duckdb file. Defines tables for response actions,
          case file references, and entity observations. The actual
          immutable case file content lives as Markdown files on disk
          in cases_dir - this database tracks metadata and hash chains.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.database import BaseDatabase
from rexdr_core.identity import EngineID
from rexdr_core.schemas import CaseFile, ChainSeverity, EntityType

# ============================================================================

logger = logging.getLogger(__name__)


class ResponseDatabase(BaseDatabase):
    """
    DuckDB database layer for the Incident Response Orchestration engine.
    Extends BaseDatabase and implements schema_init().
    Owns response.duckdb exclusively.
    """

    def __init__(self, data_dir) -> None:
        super().__init__(EngineID.RESPONSE, data_dir)

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def schema_init(self) -> None:
        """Create all tables for the Response engine."""

        # Case file metadata and hash chain
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS case_files (
                case_id          VARCHAR PRIMARY KEY,
                created_at       TIMESTAMP NOT NULL,
                chain_id         VARCHAR NOT NULL,
                entity_id        VARCHAR NOT NULL,
                severity         VARCHAR NOT NULL,
                title            VARCHAR NOT NULL,
                analyst          VARCHAR DEFAULT 'REXDR Automated Response',
                actions_taken    JSON DEFAULT '[]',
                evidence_hashes  JSON DEFAULT '{}',
                chain_hash       VARCHAR NOT NULL,
                file_path        VARCHAR NOT NULL,
                is_closed        BOOLEAN DEFAULT FALSE,
                closed_at        TIMESTAMP,
                resolution       VARCHAR
            )
        """)

        # Response actions log - every containment action taken
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS response_actions (
                action_id        VARCHAR PRIMARY KEY,
                case_id          VARCHAR,
                chain_id         VARCHAR NOT NULL,
                entity_id        VARCHAR NOT NULL,
                action_type      VARCHAR NOT NULL,
                playbook_id      VARCHAR NOT NULL,
                status           VARCHAR NOT NULL,
                details          TEXT,
                executed_at      TIMESTAMP NOT NULL
            )
        """)

        # Chains already responded to - prevents duplicate response execution
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS responded_chains (
                chain_id      VARCHAR PRIMARY KEY,
                responded_at  TIMESTAMP NOT NULL,
                case_id       VARCHAR
            )
        """)

        # Entity observation state tracked by this engine
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_observations (
                entity_id           VARCHAR PRIMARY KEY,
                entity_type         VARCHAR NOT NULL,
                last_seen           TIMESTAMP NOT NULL,
                case_count          INTEGER DEFAULT 0,
                contained_count     INTEGER DEFAULT 0,
                updated_at          TIMESTAMP NOT NULL
            )
        """)

        logger.info("Response engine schema initialized")

    # -------------------------------------------------------------------------
    # Case file writes
    # -------------------------------------------------------------------------

    def insert_case_file(self, case: CaseFile, file_path: str) -> None:
        """Insert case file metadata after the Markdown file has been written."""
        self.conn.execute("""
            INSERT INTO case_files (
                case_id, created_at, chain_id, entity_id, severity,
                title, analyst, actions_taken, evidence_hashes,
                chain_hash, file_path, is_closed, closed_at, resolution
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            str(case.case_id),
            case.created_at,
            str(case.chain_id),
            case.entity_id,
            case.severity.value,
            case.title,
            case.analyst,
            json.dumps(case.actions_taken),
            json.dumps(case.evidence_hashes),
            case.chain_hash,
            file_path,
            case.is_closed,
            case.closed_at,
            case.resolution,
        ])
        logger.info(
            "Case file recorded - case_id=%s entity=%s severity=%s",
            case.case_id, case.entity_id, case.severity.value,
        )

    def mark_chain_responded(self, chain_id: str, case_id: str) -> None:
        """Record that a chain has been responded to, preventing duplicate response."""
        self.conn.execute("""
            INSERT INTO responded_chains (chain_id, responded_at, case_id)
            VALUES (?, ?, ?)
            ON CONFLICT (chain_id) DO NOTHING
        """, [chain_id, datetime.now(timezone.utc), case_id])

    def has_responded(self, chain_id: str) -> bool:
        """Check if a chain has already been responded to."""
        result = self.conn.execute(
            "SELECT COUNT(*) FROM responded_chains WHERE chain_id = ?",
            [chain_id]
        ).fetchone()
        return result[0] > 0 if result else False

    # -------------------------------------------------------------------------
    # Response action writes
    # -------------------------------------------------------------------------

    def insert_action(
        self,
        action_id: str,
        case_id: str | None,
        chain_id: str,
        entity_id: str,
        action_type: str,
        playbook_id: str,
        status: str,
        details: str,
    ) -> None:
        """Record a single response action taken during containment."""
        self.conn.execute("""
            INSERT INTO response_actions (
                action_id, case_id, chain_id, entity_id, action_type,
                playbook_id, status, details, executed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            action_id, case_id, chain_id, entity_id, action_type,
            playbook_id, status, details, datetime.now(timezone.utc),
        ])

    # -------------------------------------------------------------------------
    # Entity observation writes
    # -------------------------------------------------------------------------

    def upsert_entity_observation(
        self,
        entity_id: str,
        entity_type: EntityType,
        is_contained: bool = False,
    ) -> None:
        """Track response history per entity - case count and containment count."""
        now = datetime.now(timezone.utc)

        existing = self.conn.execute(
            "SELECT case_count, contained_count FROM entity_observations WHERE entity_id = ?",
            [entity_id]
        ).fetchone()

        if existing:
            case_count = existing[0] + 1
            contained_count = existing[1] + (1 if is_contained else 0)

            self.conn.execute("""
                UPDATE entity_observations SET
                    last_seen        = ?,
                    case_count       = ?,
                    contained_count  = ?,
                    updated_at       = ?
                WHERE entity_id = ?
            """, [now, case_count, contained_count, now, entity_id])
        else:
            self.conn.execute("""
                INSERT INTO entity_observations (
                    entity_id, entity_type, last_seen, case_count,
                    contained_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, [
                entity_id, entity_type.value, now, 1,
                1 if is_contained else 0, now,
            ])

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def get_recent_cases(self, limit: int = 50) -> list[dict]:
        """Get recent case files."""
        rows = self.conn.execute("""
            SELECT * FROM case_files
            ORDER BY created_at DESC
            LIMIT ?
        """, [limit]).fetchall()

        columns = [
            "case_id", "created_at", "chain_id", "entity_id", "severity",
            "title", "analyst", "actions_taken", "evidence_hashes",
            "chain_hash", "file_path", "is_closed", "closed_at", "resolution"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_recent_actions(self, limit: int = 100) -> list[dict]:
        """Get recent response actions."""
        rows = self.conn.execute("""
            SELECT * FROM response_actions
            ORDER BY executed_at DESC
            LIMIT ?
        """, [limit]).fetchall()

        columns = [
            "action_id", "case_id", "chain_id", "entity_id", "action_type",
            "playbook_id", "status", "details", "executed_at"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def get_stats(self) -> dict:
        """Return engine statistics."""
        total_cases = self.conn.execute("SELECT COUNT(*) FROM case_files").fetchone()[0]
        closed_cases = self.conn.execute(
            "SELECT COUNT(*) FROM case_files WHERE is_closed = TRUE"
        ).fetchone()[0]
        total_actions = self.conn.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0]
        failed_actions = self.conn.execute(
            "SELECT COUNT(*) FROM response_actions WHERE status = 'failed'"
        ).fetchone()[0]

        return {
            "total_cases":    total_cases,
            "closed_cases":   closed_cases,
            "open_cases":     total_cases - closed_cases,
            "total_actions":  total_actions,
            "failed_actions": failed_actions,
        }