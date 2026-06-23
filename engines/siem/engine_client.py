"""
rexdr - SIEM Correlation Engine
engine_client.py - HTTP client for querying other engines' detections

Author  : Rayyan Umair
Date    : 2026-06-23
Purpose : Replaces direct DuckDB ATTACH access to other engines'
          database files. DuckDB enforces a single writer per file
          and does not support safe multi-process read access to a
          file another process holds open for writing - this is a
          hard platform constraint, not a configuration issue, and it
          is exactly the same constraint that required EntityStore to
          become its own service. SIEM now queries each engine's
          existing REST API instead of reaching into its private
          storage directly - the correct service boundary.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Third Party -------------------------------------------------------------
import httpx

# ============================================================================

logger = logging.getLogger(__name__)

# Engine name -> base URL. These are Docker Compose service names on the
# shared rexdr_internal bridge network, resolved via Docker's embedded DNS.
ENGINE_BASE_URLS = {
    "windows_event":   "http://windows-event:8000",
    "network_flow":    "http://host.docker.internal:8001",
    "dns":             "http://host.docker.internal:8003",
    "identity":        "http://identity:8004",
    "asset_discovery": "http://host.docker.internal:8006",
    "vulnerability":   "http://vulnerability:8007",
}


class EngineClient:
    """
    Queries every other engine's /detections REST endpoint and merges
    the results. This is the replacement for the DuckDB ATTACH pattern -
    same purpose (give SIEM visibility into every engine's open
    detections), different transport (HTTP instead of direct file access).
    """

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    # -------------------------------------------------------------------------
    # Cross-engine detection fetching
    # -------------------------------------------------------------------------

    def get_cross_engine_detections(
        self,
        entity_id: str,
        window_minutes: int,
        limit_per_engine: int = 200,
    ) -> list[dict]:
        """
        Fetch open detections for a specific entity across every engine.
        Replaces the old SQL UNION ALL over ATTACHed databases - same
        result shape, fetched over HTTP and filtered/merged in Python
        instead of in SQL.
        """
        all_detections: list[dict] = []

        for engine_name, base_url in ENGINE_BASE_URLS.items():
            try:
                resp = self._client.get(
                    f"{base_url}/detections",
                    params={"limit": limit_per_engine},
                )
                resp.raise_for_status()
                detections = resp.json().get("detections", [])
            except Exception as e:
                logger.warning(
                    "Could not fetch detections - engine=%s error=%s",
                    engine_name, str(e),
                )
                continue

            for d in detections:
                if d.get("entity_id") != entity_id:
                    continue
                if d.get("status") != "open":
                    continue
                if not self._within_window(d.get("timestamp"), window_minutes):
                    continue
                all_detections.append(d)

        all_detections.sort(key=lambda d: d.get("timestamp", ""))
        return all_detections

    def get_entities_with_recent_detections(
        self,
        window_minutes: int,
        limit_per_engine: int = 200,
    ) -> set[str]:
        """
        Get the distinct set of entity IDs with any open detection across
        every engine within the window. Replaces the old SQL UNION over
        ATTACHed databases - this is the candidate pool the correlation
        pass evaluates each cycle.
        """
        entity_ids: set[str] = set()

        for engine_name, base_url in ENGINE_BASE_URLS.items():
            try:
                resp = self._client.get(
                    f"{base_url}/detections",
                    params={"limit": limit_per_engine},
                )
                resp.raise_for_status()
                detections = resp.json().get("detections", [])
            except Exception as e:
                logger.warning(
                    "Could not fetch detections - engine=%s error=%s",
                    engine_name, str(e),
                )
                continue

            for d in detections:
                if d.get("status") != "open":
                    continue
                if not self._within_window(d.get("timestamp"), window_minutes):
                    continue
                entity_id = d.get("entity_id")
                if entity_id:
                    entity_ids.add(entity_id)

        return entity_ids

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _within_window(self, timestamp_str: str | None, window_minutes: int) -> bool:
        """Check if a detection's timestamp falls within the correlation window."""
        if not timestamp_str:
            return False

        from datetime import datetime, timezone

        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            return False

        now = datetime.now(timezone.utc)
        elapsed_minutes = (now - ts).total_seconds() / 60.0
        return 0 <= elapsed_minutes <= window_minutes