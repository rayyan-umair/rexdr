"""
rexdr - Active Directory Intelligence Engine
entity.py - Entity observation management for the Identity engine

Author  : Rayyan Umair
Date    : 2026-06-18
Updated : 2026-07-14 - process(), process_detection_only(), and their
          internal helpers are now async, and all entity_store calls
          are awaited, matching EntityStoreClient's conversion to
          httpx.AsyncClient.
Purpose : Handles all entity observation updates for the Identity
          engine. Translates detection results and event/diff data
          into entity store updates - the bridge between the detection
          layer and the unified REXDR entity model.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from rexdr_core.formula import severity_to_contribution, stack_contributions
from rexdr_core.identity import EngineID
from rexdr_core.schemas import Detection, EngineObservation, EntityType, NormalizedTelemetryPayload
from identity.database import IdentityDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class IdentityEntityManager:
    """
    Manages entity observations for the Identity engine.
    Updates both the engine-local entity observation table and
    the shared REXDR entity store after every processed event.
    """

    def __init__(self, db: IdentityDatabase, entity_store: EntityStoreClient) -> None:
        self.db = db
        self.entity_store = entity_store

    async def process(
        self,
        payload: NormalizedTelemetryPayload,
        detections: list[Detection],
    ) -> None:
        """Process an event and its detections into entity observations."""
        username = payload.username
        if not username or username.endswith("$"):
            return

        try:
            await self._update_entity(username, payload, detections)
        except Exception as e:
            logger.error(
                "Failed to update entity observation - entity=%s error=%s",
                username, str(e),
            )

    async def process_detection_only(self, detection: Detection) -> None:
        """
        Process a standalone detection not tied to a normalized event -
        used for AD-002 group diff detections which originate from the
        domain snapshot engine, not from a live event stream.
        """
        try:
            await self._apply_detection(detection.entity_id, [detection])
        except Exception as e:
            logger.error(
                "Failed to update entity from standalone detection - entity=%s error=%s",
                detection.entity_id, str(e),
            )

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    async def _update_entity(
        self,
        entity_id: str,
        payload: NormalizedTelemetryPayload,
        detections: list[Detection],
    ) -> None:
        entity_detections = [d for d in detections if d.entity_id == entity_id]
        new_auth_host = (
            payload.destination_host
            if payload.event_type in ("successful_logon", "network_logon")
            else None
        )
        await self._apply_detection(entity_id, entity_detections, new_auth_host=new_auth_host)

    async def _apply_detection(
        self,
        entity_id: str,
        entity_detections: list[Detection],
        new_auth_host: str | None = None,
        new_group: str | None = None,
    ) -> None:
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
            entity_type         = EntityType.USER_ACCOUNT,
            risk_contribution    = risk_contribution,
            behavioral_flags     = behavioral_flags,
            latest_detection     = latest_detection_code,
            new_group            = new_group,
            new_auth_host         = new_auth_host,
        )

        # -- Update shared entity store ------------------------------------------
        observation = EngineObservation(
            engine_id              = EngineID.IDENTITY,
            risk_contribution      = risk_contribution,
            behavioral_flags       = behavioral_flags,
            latest_detection_code  = latest_detection_code,
        )

        await self.entity_store.update_observation(
            entity_id    = entity_id,
            entity_type  = EntityType.USER_ACCOUNT,
            engine_id    = EngineID.IDENTITY,
            observation  = observation,
            tags         = behavioral_flags,
        )

        # -- Add to entity timeline --------------------------------------------
        for detection in entity_detections:
            await self.entity_store.add_timeline_event(
                entity_id      = entity_id,
                engine_id      = EngineID.IDENTITY,
                event_type     = detection.detection_code,
                description    = detection.description,
                severity       = detection.severity.value,
                detection_code = detection.detection_code,
            )

        logger.debug(
            "Entity observation updated - entity=%s risk=%.2f flags=%s",
            entity_id, risk_contribution, behavioral_flags,
        )