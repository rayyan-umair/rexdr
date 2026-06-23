"""
rexdr_core
entity_store_client.py - HTTP client for the Entity Store service

Author  : Rayyan Umair
Date    : 2026-06-23
Purpose : Replaces direct EntityStore instantiation in every engine.
          DuckDB enforces a single writer per file - entity_store.duckdb
          is shared platform-wide, so only the standalone Entity Store
          service may open it directly. Every other engine uses this
          HTTP client instead. Method signatures intentionally mirror
          EntityStore's so engine code barely changes - just the import
          and constructor.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Third Party -------------------------------------------------------------
import httpx

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID
from rexdr_core.schemas import Entity, EngineObservation, EntityType

# ============================================================================

logger = logging.getLogger(__name__)


class EntityStoreClient:
    """
    HTTP client for the standalone Entity Store service. Used by every
    engine in place of a direct EntityStore connection.

    Usage mirrors EntityStore's own interface:
        client = EntityStoreClient(base_url="http://entity-store:8008")
        client.update_observation(entity_id=..., entity_type=..., ...)
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def connect(self) -> None:
        """No-op for interface parity with EntityStore - HTTP is stateless."""
        pass

    def close(self) -> None:
        self._client.close()

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
    ) -> Entity | None:
        try:
            resp = self._client.post(
                f"{self.base_url}/observations",
                json={
                    "entity_id":             entity_id,
                    "entity_type":           entity_type.value,
                    "engine_id":             engine_id.value,
                    "observation":           observation.model_dump(mode="json"),
                    "network_zone":          network_zone,
                    "hostname":              hostname,
                    "mac_address":           mac_address,
                    "os_info":               os_info,
                    "is_critical_asset":     is_critical_asset,
                    "additional_usernames":  additional_usernames,
                    "additional_ips":        additional_ips,
                    "tags":                  tags,
                },
            )
            resp.raise_for_status()
            return Entity(**resp.json())
        except Exception as e:
            logger.error("EntityStoreClient.update_observation failed - error=%s", str(e))
            return None

    def add_to_chain(self, entity_id: str, chain_id: str) -> None:
        try:
            self._client.post(
                f"{self.base_url}/chains/add",
                json={"entity_id": entity_id, "chain_id": chain_id},
            )
        except Exception as e:
            logger.error("EntityStoreClient.add_to_chain failed - error=%s", str(e))

    def remove_from_chain(self, entity_id: str, chain_id: str) -> None:
        try:
            self._client.post(
                f"{self.base_url}/chains/remove",
                json={"entity_id": entity_id, "chain_id": chain_id},
            )
        except Exception as e:
            logger.error("EntityStoreClient.remove_from_chain failed - error=%s", str(e))

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
        try:
            self._client.post(
                f"{self.base_url}/timeline",
                json={
                    "entity_id":      entity_id,
                    "engine_id":      engine_id.value,
                    "event_type":     event_type,
                    "description":    description,
                    "severity":       severity,
                    "detection_code": detection_code,
                    "chain_id":       chain_id,
                    "metadata":       metadata,
                },
            )
        except Exception as e:
            logger.error("EntityStoreClient.add_timeline_event failed - error=%s", str(e))

    def get(self, entity_id: str) -> Entity | None:
        try:
            resp = self._client.get(f"{self.base_url}/entities/{entity_id}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return Entity(**resp.json())
        except Exception as e:
            logger.error("EntityStoreClient.get failed - error=%s", str(e))
            return None

    def is_healthy(self) -> bool:
        try:
            resp = self._client.get(f"{self.base_url}/health", timeout=3.0)
            return resp.status_code == 200 and resp.json().get("db_healthy", False)
        except Exception:
            return False