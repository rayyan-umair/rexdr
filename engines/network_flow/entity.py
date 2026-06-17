"""
rexdr - Network Flow Intelligence Engine
entity.py - Entity observation management for the Network Flow engine

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Handles all entity observation updates for the Network Flow
          engine. Translates detection results and flow data into entity
          store updates. This is the bridge between the detection layer
          and the unified REXDR entity model. Every IP that Network Flow
          sees gets its observation updated here so the rest of the
          platform has an accurate, up-to-date picture.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store import EntityStore
from rexdr_core.formula import severity_to_contribution, stack_contributions
from rexdr_core.identity import EngineID
from rexdr_core.schemas import Detection, EngineObservation, EntityType
from network_flow.database import NetworkFlowDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class NetworkFlowEntityManager:
    """
    Manages entity observations for the Network Flow engine.

    Updates both the engine-local entity observation table and
    the shared REXDR entity store after every processed flow.
    """

    def __init__(
        self,
        db: NetworkFlowDatabase,
        entity_store: EntityStore,
    ) -> None:
        self.db = db
        self.entity_store = entity_store

    def process(self, flow: dict, detections: list[Detection]) -> None:
        """
        Process a flow and its detections into entity observations.
        The source IP is always tracked. The destination IP is tracked
        only if it is internal - external destinations are not entities
        in their own right, just observed traffic targets.
        """
        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]
        is_external = flow.get("is_external", False)

        try:
            self._update_entity(
                entity_id   = src_ip,
                flow        = flow,
                detections  = detections,
                is_source   = True,
            )
        except Exception as e:
            logger.error(
                "Failed to update source entity - entity=%s error=%s",
                src_ip, str(e),
            )

        if not is_external:
            try:
                self._update_entity(
                    entity_id   = dst_ip,
                    flow        = flow,
                    detections  = detections,
                    is_source   = False,
                )
            except Exception as e:
                logger.error(
                    "Failed to update destination entity - entity=%s error=%s",
                    dst_ip, str(e),
                )

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _update_entity(
        self,
        entity_id: str,
        flow: dict,
        detections: list[Detection],
        is_source: bool,
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

        if flow.get("is_cross_zone"):
            if "cross_zone" not in behavioral_flags:
                behavioral_flags.append("cross_zone")

        if flow.get("threat_intel_match"):
            if "threat_intel_match" not in behavioral_flags:
                behavioral_flags.append("threat_intel_match")

        bytes_sent     = flow.get("bytes_sent", 0) if is_source else 0
        bytes_received = flow.get("bytes_sent", 0) if not is_source else 0
        destination_ip = flow["dst_ip"] if is_source else None

        # -- Update engine-local observation -------------------------------
        self.db.upsert_entity_observation(
            entity_id          = entity_id,
            entity_type        = EntityType.IP_ADDRESS,
            risk_contribution  = risk_contribution,
            behavioral_flags   = behavioral_flags,
            latest_detection   = latest_detection_code,
            bytes_sent         = bytes_sent,
            bytes_received     = bytes_received,
            destination_ip     = destination_ip,
        )

        # -- Update shared entity store --------------------------------------
        observation = EngineObservation(
            engine_id              = EngineID.NETWORK_FLOW,
            risk_contribution      = risk_contribution,
            behavioral_flags       = behavioral_flags,
            latest_detection_code  = latest_detection_code,
        )

        network_zone = flow.get("zone_source") if is_source else flow.get("zone_destination")

        self.entity_store.update_observation(
            entity_id     = entity_id,
            entity_type   = EntityType.IP_ADDRESS,
            engine_id     = EngineID.NETWORK_FLOW,
            observation   = observation,
            network_zone  = network_zone,
            tags          = behavioral_flags,
        )

        # -- Add to entity timeline -------------------------------------------
        for detection in entity_detections:
            self.entity_store.add_timeline_event(
                entity_id      = entity_id,
                engine_id      = EngineID.NETWORK_FLOW,
                event_type     = detection.detection_code,
                description    = detection.description,
                severity       = detection.severity.value,
                detection_code = detection.detection_code,
            )

        logger.debug(
            "Entity observation updated - entity=%s risk=%.2f flags=%s",
            entity_id, risk_contribution, behavioral_flags,
        )