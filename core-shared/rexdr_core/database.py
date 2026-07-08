"""
rexdr_core
database.py - Base DuckDB class for all REXDR engines

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Provides the canonical base database class that every engine
          extends. Handles connection management, single-writer enforcement,
          schema initialization, Parquet archiving, and the DuckDB ATTACH
          pattern used by the correlation engine for cross-engine queries.
          No engine accesses DuckDB directly - they all go through this.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path

# -- Third Party -------------------------------------------------------------
import duckdb

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID, ENGINE_DB_FILES

# ============================================================================

logger = logging.getLogger(__name__)

# How many times to retry acquiring the DuckDB lock before raising
DB_LOCK_RETRIES = 3
DB_LOCK_RETRY_DELAY = 2.0  # seconds


class BaseDatabase(ABC):
    """
    Base DuckDB class for all REXDR engines.

    Every engine extends this class and implements schema_init().
    This class handles everything else - connection lifecycle,
    lock retry logic, Parquet archiving, and cross-engine ATTACH.

    Usage:
        class MyEngineDatabase(BaseDatabase):
            def schema_init(self) -> None:
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS events (...)"
                )
    """

    def __init__(self, engine_id: EngineID, data_dir: Path) -> None:
        self.engine_id = engine_id
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / ENGINE_DB_FILES[engine_id]
        self.conn: duckdb.DuckDBPyConnection | None = None
        self._attached_engines: list[EngineID] = []
        self.lock = threading.Lock()  # For thread-safe connection management

    # -------------------------------------------------------------------------
    # Connection management
    # -------------------------------------------------------------------------

    def connect(self) -> None:
        """
        Open the DuckDB connection with lock retry logic.
        Retries DB_LOCK_RETRIES times before raising.
        Calls schema_init() after a successful connection.
        """
        last_error = None

        for attempt in range(1, DB_LOCK_RETRIES + 1):
            try:
                self.conn = duckdb.connect(str(self.db_path))
                logger.info(
                    "Database connected - engine=%s path=%s",
                    self.engine_id.value,
                    self.db_path,
                )
                self.schema_init()
                return
            except duckdb.IOException as e:
                last_error = e
                logger.warning(
                    "Database lock attempt %d/%d failed - engine=%s error=%s",
                    attempt,
                    DB_LOCK_RETRIES,
                    self.engine_id.value,
                    str(e),
                )
                if attempt < DB_LOCK_RETRIES:
                    time.sleep(DB_LOCK_RETRY_DELAY)

        raise RuntimeError(
            f"Could not acquire DuckDB lock after {DB_LOCK_RETRIES} attempts "
            f"for engine {self.engine_id.value} at {self.db_path}. "
            f"Last error: {last_error}"
        )

    def close(self) -> None:
        """Close the DuckDB connection cleanly."""
        if self.conn:
            try:
                self.conn.close()
                logger.info(
                    "Database closed - engine=%s",
                    self.engine_id.value,
                )
            except Exception as e:
                logger.error(
                    "Error closing database - engine=%s error=%s",
                    self.engine_id.value,
                    str(e),
                )
            finally:
                self.conn = None

    def __enter__(self) -> "BaseDatabase":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # Thread-safe query execution
    # -------------------------------------------------------------------------

    def execute(self, query: str, params: list | None = None):
        """
        Thread-safe wrapper around self.conn.execute(). DuckDB's Python
        connection object is not safe for concurrent use across threads -
        engines that run a background harvester/sniffer thread alongside
        the async pipeline (both sharing self.conn) can otherwise get
        corrupted or truncated query results under real concurrent load,
        even though the underlying data on disk is completely correct.
        All engine database classes should call self.execute(...) instead
        of self.conn.execute(...) directly.
        """
        if not self.conn:
            raise RuntimeError("Database not connected.")
        with self._lock:
            if params is not None:
                return self.conn.execute(query, params)
            return self.conn.execute(query)

    # -------------------------------------------------------------------------
    # Schema initialization - engines must implement this
    # -------------------------------------------------------------------------

    @abstractmethod
    def schema_init(self) -> None:
        """
        Create all tables for this engine if they do not exist.
        Called automatically after connect(). Every engine implements this.
        Use CREATE TABLE IF NOT EXISTS - never DROP and recreate.
        """
        ...

    # -------------------------------------------------------------------------
    # Cross-engine ATTACH - used by the correlation engine
    # -------------------------------------------------------------------------

    def attach_engine(self, engine_id: EngineID) -> None:
        """
        Attach another engine's DuckDB file as a read-only database.
        Used by the SIEM correlation engine to run cross-engine SQL joins
        without copying data or making API calls.

        The attached database is accessible as engine_id.value in SQL:
            SELECT * FROM windows_event.events
            JOIN network_flow.flows ON ...
        """
        if not self.conn:
            raise RuntimeError("Cannot attach - database not connected.")

        if engine_id in self._attached_engines:
            logger.debug(
                "Engine already attached - engine=%s",
                engine_id.value,
            )
            return

        db_path = self.data_dir / ENGINE_DB_FILES[engine_id]

        if not db_path.exists():
            logger.warning(
                "Cannot attach engine - database file not found - engine=%s path=%s",
                engine_id.value,
                db_path,
            )
            return

        self.conn.execute(
            f"ATTACH '{db_path}' AS {engine_id.value} (READ_ONLY)"
        )
        self._attached_engines.append(engine_id)
        logger.info(
            "Engine attached - source=%s attached=%s",
            self.engine_id.value,
            engine_id.value,
        )

    def attach_all_engines(self) -> None:
        """
        Attach all other engine databases as read-only.
        Used by the SIEM correlation engine on startup.
        Skips engines whose database files do not exist yet.
        """
        from rexdr_core.identity import EngineID as EID
        for engine_id in EID:
            if engine_id != self.engine_id:
                self.attach_engine(engine_id)

    # -------------------------------------------------------------------------
    # Parquet archiving
    # -------------------------------------------------------------------------

    def archive_to_parquet(self, table_name: str, archive_dir: Path) -> Path:
        """
        Export a table to a timestamped Parquet file for long-term storage.
        Used by engines to archive data older than the rolling DuckDB window.
        Returns the path of the written Parquet file.
        """
        if not self.conn:
            raise RuntimeError("Cannot archive - database not connected.")

        archive_dir.mkdir(parents=True, exist_ok=True)
        timestamp = int(time.time())
        parquet_path = archive_dir / f"{table_name}_{timestamp}.parquet"

        self.conn.execute(
            f"COPY (SELECT * FROM {table_name}) "
            f"TO '{parquet_path}' (FORMAT PARQUET)"
        )
        logger.info(
            "Table archived to Parquet - engine=%s table=%s path=%s",
            self.engine_id.value,
            table_name,
            parquet_path,
        )
        return parquet_path

    def purge_old_records(
        self,
        table_name: str,
        timestamp_column: str,
        retention_days: int,
    ) -> int:
        """
        Delete records older than retention_days from a table.
        Call archive_to_parquet() before calling this if you want
        to preserve the data long-term.
        Returns the number of rows deleted.
        """
        if not self.conn:
            raise RuntimeError("Cannot purge - database not connected.")

        result = self.conn.execute(
            f"DELETE FROM {table_name} "
            f"WHERE {timestamp_column} < NOW() - INTERVAL '{retention_days} days' "
            f"RETURNING COUNT(*)"
        ).fetchone()

        deleted = result[0] if result else 0
        logger.info(
            "Old records purged - engine=%s table=%s deleted=%d retention_days=%d",
            self.engine_id.value,
            table_name,
            deleted,
            retention_days,
        )
        return deleted

    # -------------------------------------------------------------------------
    # Health check
    # -------------------------------------------------------------------------

    def is_healthy(self) -> bool:
        """
        Returns True if the database connection is open and responsive.
        Used by the Docker health check endpoint in each engine's API.
        """
        if not self.conn:
            return False
        try:
            self.conn.execute("SELECT 1")
            return True
        except Exception:
            return False