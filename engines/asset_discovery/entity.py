"""
rexdr - Network Discovery Engine
entity.py - Entity observation management for the Asset Discovery engine

Author  : Rayyan Umair
Date    : 2026-06-19
Purpose : Handles entity observation updates for the Asset Discovery
          engine. Every scanned asset becomes or updates an entity in
          the unified REXDR entity model, carrying hostname, MAC
          address, OS fingerprint, and zone data that other engines
          rely on for richer context.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Map the terrain before the enemy does."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from rexdr_core.formula import severity_to_contribution, stack_contributions
from rexdr_core.identity import EngineID
from rexdr_core.schemas import Detection, EngineObservation, EntityType
from asset_discovery.database import AssetDiscoveryDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class AssetDiscoveryEntityManager:
    """
    Manages entity observations for the Asset Discovery engine.
    Every scanned asset enriches the shared entity store with
    hostname, MAC address, OS fingerprint, and network zone -
    context that other engines benefit from but cannot discover
    themselves.
    """

    def __init__(self, db: AssetDiscoveryDatabase, entity_store: EntityStoreClient) -> None:
        self.db = db
        self.entity_store = entity_store

    def process(self, asset: dict, detections: list[Detection]) -> None:
        """Process a scanned asset and its detections into entity observations."""
        entity_id = asset.get("ip_address")
        if not entity_id:
            return

        try:
            self._update_entity(entity_id, asset, detections)
        except Exception as e:
            logger.error(
                "Failed to update entity observation - entity=%s error=%s",
                entity_id, str(e),
            )

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _update_entity(
        self,
        entity_id: str,
        asset: dict,
        detections: list[Detection],
    ) -> None:
        entity_detections = [d for d in detections if d.entity_id == entity_id]

        risk_contribution = 0.0
        behavioral_flags: list[str] = []
        latest_detection_code: str | None = None

        for detection in entity_detections:
            risk_contribution = stack_contributions(
                risk_contribution,
                severity_to_contribution(detection.severity),
            )
            behavioral_flags.append(detection.detection_code)
            latest_detection_code = detection.detection_code

        # -- Update engine-local observation -----------------------------------
        self.db.upsert_entity_observation(
            entity_id           = entity_id,
            entity_type         = EntityType.IP_ADDRESS,
            risk_contribution    = risk_contribution,
            behavioral_flags     = behavioral_flags,
            latest_detection     = latest_detection_code,
        )

        # -- Update shared entity store with enrichment data ---------------------
        observation = EngineObservation(
            engine_id              = EngineID.ASSET_DISCOVERY,
            risk_contribution      = risk_contribution,
            behavioral_flags       = behavioral_flags,
            latest_detection_code  = latest_detection_code,
        )

        self.entity_store.update_observation(
            entity_id     = entity_id,
            entity_type   = EntityType.IP_ADDRESS,
            engine_id     = EngineID.ASSET_DISCOVERY,
            observation   = observation,
            network_zone  = asset.get("network_zone"),
            hostname      = asset.get("hostname"),
            mac_address   = asset.get("mac_address"),
            os_info       = asset.get("os_fingerprint"),
            tags          = behavioral_flags,
        )

        for detection in entity_detections:
            self.entity_store.add_timeline_event(
                entity_id      = entity_id,
                engine_id      = EngineID.ASSET_DISCOVERY,
                event_type     = detection.detection_code,
                description    = detection.description,
                severity       = detection.severity.value,
                detection_code = detection.detection_code,
            )

        logger.debug(
            "Entity observation updated - entity=%s risk=%.2f flags=%s",
            entity_id, risk_contribution, behavioral_flags,
        )