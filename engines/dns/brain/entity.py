"""
rexdr - DNS Behavioral Intelligence Engine
entity.py - Entity observation management for the DNS engine

Author  : Rayyan Umair
Date    : 2026-06-16
Purpose : Handles all entity observation updates for the DNS engine.
          Translates detection results and query data into entity
          store updates - the bridge between the detection layer and
          the unified REXDR entity model.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Hunt the whisper."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store import EntityStore
from rexdr_core.formula import severity_to_contribution, stack_contributions
from rexdr_core.identity import EngineID
from rexdr_core.schemas import Detection, EngineObservation, EntityType
from dns.brain.database import DnsDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class DnsEntityManager:
    """
    Manages entity observations for the DNS engine.
    Updates both the engine-local entity observation table and
    the shared REXDR entity store after every processed query.
    """

    def __init__(self, db: DnsDatabase, entity_store: EntityStore) -> None:
        self.db = db
        self.entity_store = entity_store

    def process(self, query: dict, detections: list[Detection]) -> None:
        """Process a query and its detections into entity observations."""
        src_ip = query.get("source_ip")
        if not src_ip:
            return

        try:
            self._update_entity(src_ip, query, detections)
        except Exception as e:
            logger.error(
                "Failed to update entity observation - entity=%s error=%s",
                src_ip, str(e),
            )

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _update_entity(
        self,
        entity_id: str,
        query: dict,
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

        if query.get("is_rare_tld") and "rare_tld" not in behavioral_flags:
            behavioral_flags.append("rare_tld")

        nxdomain_increment = 1 if query.get("response_code") == "NXDOMAIN" else 0
        queried_domain = query.get("query_name")

        # -- Update engine-local observation -----------------------------------
        self.db.upsert_entity_observation(
            entity_id           = entity_id,
            entity_type         = EntityType.IP_ADDRESS,
            risk_contribution   = risk_contribution,
            behavioral_flags    = behavioral_flags,
            latest_detection    = latest_detection_code,
            nxdomain_increment  = nxdomain_increment,
            queried_domain      = queried_domain,
        )

        # -- Update shared entity store ------------------------------------------
        observation = EngineObservation(
            engine_id              = EngineID.DNS,
            risk_contribution      = risk_contribution,
            behavioral_flags       = behavioral_flags,
            latest_detection_code  = latest_detection_code,
        )

        self.entity_store.update_observation(
            entity_id    = entity_id,
            entity_type  = EntityType.IP_ADDRESS,
            engine_id    = EngineID.DNS,
            observation  = observation,
            tags         = behavioral_flags,
        )

        # -- Add to entity timeline --------------------------------------------
        for detection in entity_detections:
            self.entity_store.add_timeline_event(
                entity_id      = entity_id,
                engine_id      = EngineID.DNS,
                event_type     = detection.detection_code,
                description    = detection.description,
                severity       = detection.severity.value,
                detection_code = detection.detection_code,
            )

        logger.debug(
            "Entity observation updated - entity=%s risk=%.2f flags=%s",
            entity_id, risk_contribution, behavioral_flags,
        )