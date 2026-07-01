"""
rexdr_core
entity_store.py - Shared entity registry for the REXDR platform

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Provides the canonical entity registry used by all eight engines.
          Every engine reads and writes entity state through this interface.
          No engine writes entity data directly to DuckDB - they all go
          through EntityStore. This is what makes the unified entity model
          possible - one identity, one risk score, across all eight engines.
          EntityStore owns the entity table in a dedicated entity.duckdb file
          shared across the platform via DuckDB ATTACH.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# -- Third Party -------------------------------------------------------------
import duckdb

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID
from rexdr_core.schemas import (
    Entity,
    EntityType,
    EngineObservation,
)
from rexdr_core.formula import calculate_entity_risk_score

# ============================================================================

logger = logging.getLogger(__name__)

ENTITY_DB_FILENAME = "entity_store.duckdb"


class EntityStore:
    """
    Shared entity registry for the REXDR platform.

    All eight engines use a single instance of this class to read
    and write entity state. EntityStore owns entity_store.duckdb -
    a dedicated database file that lives alongside the engine databases.

    Every engine that observes an entity calls update_observation().
    The risk score is recalculated automatically on every update.
    The SIEM correlation engine and frontend read entities via get()
    and list_by_risk().

    Thread safety: DuckDB is single-writer. EntityStore uses a simple
    write lock pattern. All writes are serialized through this class.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / ENTITY_DB_FILENAME
        self.conn: duckdb.DuckDBPyConnection | None = None

    # -------------------------------------------------------------------------
    # Connection management
    # -------------------------------------------------------------------------

    def connect(self) -> None:
        """Open the entity store database and initialize the schema."""
        self.conn = duckdb.connect(str(self.db_path))
        self._schema_init()
        logger.info("EntityStore connected - path=%s", self.db_path)

    def close(self) -> None:
        """Close the entity store database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.info("EntityStore closed")

    def __enter__(self) -> "EntityStore":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # Schema
    # -------------------------------------------------------------------------

    def _schema_init(self) -> None:
        """Create the entity store tables if they do not exist."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                entity_id           VARCHAR PRIMARY KEY,
                entity_type         VARCHAR NOT NULL,
                first_seen          TIMESTAMP NOT NULL,
                last_seen           TIMESTAMP NOT NULL,
                risk_score          DOUBLE DEFAULT 0.0,
                network_zone        VARCHAR,
                hostname            VARCHAR,
                mac_address         VARCHAR,
                os_info             VARCHAR,
                is_critical_asset   BOOLEAN DEFAULT FALSE,
                known_usernames     JSON DEFAULT '[]',
                known_ips           JSON DEFAULT '[]',
                active_chain_ids    JSON DEFAULT '[]',
                engine_observations JSON DEFAULT '{}',
                tags                JSON DEFAULT '[]',
                updated_at          TIMESTAMP NOT NULL
            )
        """)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_timeline (
                id              VARCHAR PRIMARY KEY,
                entity_id       VARCHAR NOT NULL,
                timestamp       TIMESTAMP NOT NULL,
                engine_id       VARCHAR NOT NULL,
                event_type      VARCHAR NOT NULL,
                description     VARCHAR NOT NULL,
                severity        VARCHAR NOT NULL,
                detection_code  VARCHAR,
                chain_id        VARCHAR,
                metadata        JSON DEFAULT '{}'
            )
        """)

        logger.debug("EntityStore schema initialized")

    # -------------------------------------------------------------------------
    # Write operations
    # -------------------------------------------------------------------------

    def upsert(self, entity: Entity) -> None:
        """
        Insert or update an entity in the store.
        Recalculates the risk score before writing.
        Called by update_observation() - engines should not call this directly.
        """
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")

        entity.risk_score = calculate_entity_risk_score(entity)
        entity.last_seen = datetime.now(timezone.utc)

        self.conn.execute("""
            INSERT INTO entities (
                entity_id, entity_type, first_seen, last_seen,
                risk_score, network_zone, hostname, mac_address,
                os_info, is_critical_asset, known_usernames,
                known_ips, active_chain_ids, engine_observations,
                tags, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (entity_id) DO UPDATE SET
                last_seen           = excluded.last_seen,
                risk_score          = excluded.risk_score,
                network_zone        = excluded.network_zone,
                hostname            = COALESCE(excluded.hostname, entities.hostname),
                mac_address         = COALESCE(excluded.mac_address, entities.mac_address),
                os_info             = COALESCE(excluded.os_info, entities.os_info),
                is_critical_asset   = excluded.is_critical_asset,
                known_usernames     = excluded.known_usernames,
                known_ips           = excluded.known_ips,
                active_chain_ids    = excluded.active_chain_ids,
                engine_observations = excluded.engine_observations,
                tags                = excluded.tags,
                updated_at          = excluded.updated_at
        """, [
            entity.entity_id,
            entity.entity_type.value,
            entity.first_seen,
            entity.last_seen,
            entity.risk_score,
            entity.network_zone,
            entity.hostname,
            entity.mac_address,
            entity.os_info,
            entity.is_critical_asset,
            json.dumps(entity.known_usernames),
            json.dumps(entity.known_ips),
            json.dumps(entity.active_chain_ids),
            json.dumps({
                k: v.model_dump(mode="json") if hasattr(v, "model_dump") else v
                for k, v in entity.engine_observations.items()
            }),
            json.dumps(entity.tags),
            datetime.now(timezone.utc),
        ])

    def update_observation(
        self,
        entity_id: str,
        entity_type: EntityType,
        engine_id: EngineID,
        observation: EngineObservation,
        network_zone: str | None = None,
        hostname: str | None = None,
        mac_address: str | None = None,
        os_info: str | None = None,
        is_critical_asset: bool = False,
        additional_usernames: list[str] | None = None,
        additional_ips: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> Entity:
        """
        Record an engine's latest observation of an entity.
        This is the primary write method all engines call.

        Gets the existing entity if it exists, merges the new observation,
        recalculates the risk score, and writes back to the store.
        Returns the updated entity.
        """
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")

        entity = self.get(entity_id)

        if entity is None:
            entity = Entity(
                entity_id=entity_id,
                entity_type=entity_type,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )

        # Merge observation
        entity.engine_observations[engine_id.value] = observation

        # Merge optional fields - only overwrite if new value provided
        if network_zone:
            entity.network_zone = network_zone
        if hostname:
            entity.hostname = hostname
        if mac_address:
            entity.mac_address = mac_address
        if os_info:
            entity.os_info = os_info
        if is_critical_asset:
            entity.is_critical_asset = True
        if additional_usernames:
            for u in additional_usernames:
                if u not in entity.known_usernames:
                    entity.known_usernames.append(u)
        if additional_ips:
            for ip in additional_ips:
                if ip not in entity.known_ips:
                    entity.known_ips.append(ip)
        if tags:
            for t in tags:
                if t not in entity.tags:
                    entity.tags.append(t)

        self.upsert(entity)

        logger.debug(
            "Entity observation updated - entity=%s engine=%s risk=%.2f",
            entity_id,
            engine_id.value,
            entity.risk_score,
        )

        return entity

    def add_to_chain(self, entity_id: str, chain_id: str) -> None:
        """Add an attack chain ID to an entity's active chain list."""
        entity = self.get(entity_id)
        if entity and chain_id not in entity.active_chain_ids:
            entity.active_chain_ids.append(chain_id)
            self.upsert(entity)

    def remove_from_chain(self, entity_id: str, chain_id: str) -> None:
        """Remove an attack chain ID from an entity's active chain list."""
        entity = self.get(entity_id)
        if entity and chain_id in entity.active_chain_ids:
            entity.active_chain_ids.remove(chain_id)
            self.upsert(entity)

    def add_timeline_event(
        self,
        entity_id: str,
        engine_id: EngineID,
        event_type: str,
        description: str,
        severity: str,
        detection_code: str | None = None,
        chain_id: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """
        Add an event to the entity's behavioral timeline.
        The timeline is the full chronological history of everything
        REXDR has observed about this entity across all engines.
        """
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")

        import uuid
        self.conn.execute("""
            INSERT INTO entity_timeline (
                id, entity_id, timestamp, engine_id,
                event_type, description, severity,
                detection_code, chain_id, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            str(uuid.uuid4()),
            entity_id,
            datetime.now(timezone.utc),
            engine_id.value,
            event_type,
            description,
            severity,
            detection_code,
            chain_id,
            json.dumps(metadata or {}),
        ])

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    def get(self, entity_id: str) -> Entity | None:
        """
        Get a single entity by ID.
        Returns None if the entity does not exist in the store.
        """
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")

        row = self.conn.execute(
            "SELECT * FROM entities WHERE entity_id = ?",
            [entity_id]
        ).fetchone()

        if not row:
            return None

        return self._row_to_entity(row)

    def list_by_risk(
        self,
        limit: int = 100,
        min_score: float = 0.0,
        entity_type: EntityType | None = None,
    ) -> list[Entity]:
        """
        List entities sorted by risk score descending.
        Used by the frontend entity risk board and the correlation engine.
        """
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")

        query = "SELECT * FROM entities WHERE risk_score >= ?"
        params: list = [min_score]

        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type.value)

        query += " ORDER BY risk_score DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_entity(row) for row in rows]

    def list_in_chains(self) -> list[Entity]:
        """Return all entities that are part of an active attack chain."""
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")

        rows = self.conn.execute(
            "SELECT * FROM entities WHERE active_chain_ids != '[]' "
            "ORDER BY risk_score DESC"
        ).fetchall()
        return [self._row_to_entity(row) for row in rows]

    def get_timeline(
        self,
        entity_id: str,
        limit: int = 200,
    ) -> list[dict]:
        """
        Get the full behavioral timeline for an entity across all engines.
        Returns events in chronological order, most recent first.
        """
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")

        rows = self.conn.execute("""
            SELECT * FROM entity_timeline
            WHERE entity_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, [entity_id, limit]).fetchall()

        columns = [
            "id", "entity_id", "timestamp", "engine_id",
            "event_type", "description", "severity",
            "detection_code", "chain_id", "metadata"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def count(self) -> int:
        """Return total number of tracked entities."""
        if not self.conn:
            raise RuntimeError("EntityStore not connected.")
        result = self.conn.execute("SELECT COUNT(*) FROM entities").fetchone()
        return result[0] if result else 0

    def is_healthy(self) -> bool:
        """Returns True if the entity store is connected and responsive."""
        if not self.conn:
            return False
        try:
            self.conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _row_to_entity(self, row: tuple) -> Entity:
        """Convert a raw DuckDB row into an Entity model."""
        columns = [
            "entity_id", "entity_type", "first_seen", "last_seen",
            "risk_score", "network_zone", "hostname", "mac_address",
            "os_info", "is_critical_asset", "known_usernames",
            "known_ips", "active_chain_ids", "engine_observations",
            "tags", "updated_at"
        ]
        data = dict(zip(columns, row))

        # Deserialize JSON fields
        for field in ["known_usernames", "known_ips", "active_chain_ids", "tags"]:
            if isinstance(data[field], str):
                data[field] = json.loads(data[field])

        if isinstance(data["engine_observations"], str):
            raw_obs = json.loads(data["engine_observations"])
        else:
            raw_obs = data["engine_observations"] or {}

        parsed_obs = {}
        for k, v in raw_obs.items():
            if isinstance(v, dict):
                try:
                    parsed_obs[k] = EngineObservation(**v)
                except Exception:
                    parsed_obs[k] = v
            else:
                parsed_obs[k] = v

        data["engine_observations"] = parsed_obs
        data.pop("updated_at", None)

        return Entity(**data)