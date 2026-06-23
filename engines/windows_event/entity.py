"""
rexdr - Windows Event Intelligence Engine
entity.py - Entity observation management for the Windows Event engine

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Handles all entity observation updates for the Windows Event
          engine. Translates detection results and normalized events into
          entity store updates. This is the bridge between the detection
          layer and the unified REXDR entity model. Every entity that
          Windows Event sees gets its observation updated here so the
          rest of the platform has an accurate, up-to-date picture of
          every identity on the network.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store_client import EntityStoreClient
from rexdr_core.formula import severity_to_contribution, stack_contributions
from rexdr_core.identity import EngineID
from rexdr_core.schemas import (
    Detection,
    EngineObservation,
    EntityType,
    NormalizedTelemetryPayload,
)
from windows_event.database import WindowsEventDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class WindowsEventEntityManager:
    """
    Manages entity observations for the Windows Event engine.

    Two responsibilities:
    1. Update the engine-local entity observation table in
       windows_event.duckdb after every processed event.
    2. Update the shared REXDR entity store so all other engines
       and the frontend have the current picture of this entity.

    Called by the intelligence pipeline after every event is
    normalized and detections have been run.
    """

    def __init__(
        self,
        db: WindowsEventDatabase,
        entity_store: EntityStoreClient,
    ) -> None:
        self.db = db
        self.entity_store = entity_store

    def process(
        self,
        payload: NormalizedTelemetryPayload,
        detections: list[Detection],
    ) -> None:
        """
        Process an event and its detections into entity observations.
        Updates both the local engine database and the shared entity store.
        Called once per normalized event after detection logic runs.
        """
        entities_to_update = self._extract_entities(payload, detections)

        for entity_id, entity_type, context in entities_to_update:
            try:
                self._update_entity(
                    entity_id   = entity_id,
                    entity_type = entity_type,
                    payload     = payload,
                    detections  = detections,
                    context     = context,
                )
            except Exception as e:
                logger.error(
                    "Failed to update entity observation - entity=%s error=%s",
                    entity_id,
                    str(e),
                )

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _extract_entities(
        self,
        payload: NormalizedTelemetryPayload,
        detections: list[Detection],
    ) -> list[tuple[str, EntityType, dict]]:
        """
        Extract all entities from the event that need observation updates.
        A single event can involve multiple entities - source IP, username,
        destination host - each gets its own observation update.
        Returns list of (entity_id, entity_type, context_dict) tuples.
        """
        entities = []
        seen = set()

        def add(entity_id: str | None, entity_type: EntityType, context: dict) -> None:
            if entity_id and entity_id not in seen:
                entities.append((entity_id, entity_type, context))
                seen.add(entity_id)

        # Source IP
        add(
            payload.source_ip,
            EntityType.IP_ADDRESS,
            {"role": "source", "zone": payload.zone_source},
        )

        # Username
        add(
            payload.username,
            EntityType.USER_ACCOUNT,
            {"role": "actor", "source_ip": payload.source_ip},
        )

        # Destination host
        add(
            payload.destination_host,
            EntityType.HOSTNAME,
            {"role": "target", "zone": payload.zone_destination},
        )

        # Source host if different from source IP
        if payload.source_host and payload.source_host != payload.source_ip:
            add(
                payload.source_host,
                EntityType.HOSTNAME,
                {"role": "source_host", "zone": payload.zone_source},
            )

        return entities

    def _update_entity(
        self,
        entity_id: str,
        entity_type: EntityType,
        payload: NormalizedTelemetryPayload,
        detections: list[Detection],
        context: dict,
    ) -> None:
        """
        Update both the engine-local observation and the shared entity store
        for a single entity extracted from the event.
        """
        # Calculate how much this event contributes to entity risk
        entity_detections = [
            d for d in detections if d.entity_id == entity_id
        ]

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

        # Add cross-zone flag if applicable
        if payload.is_cross_zone:
            if "cross_zone" not in behavioral_flags:
                behavioral_flags.append("cross_zone")

        # Determine failed logon increment
        failed_logon_increment = (
            1 if payload.event_type in ("failed_logon", "kerberos_pre_auth_failed")
            and entity_type == EntityType.IP_ADDRESS
            else 0
        )

        # Determine logon host for lateral movement tracking
        logon_host = (
            payload.destination_host
            if payload.event_type in (
                "successful_logon", "network_logon", "explicit_credential_logon"
            )
            and entity_type == EntityType.USER_ACCOUNT
            else None
        )

        # -- Update engine-local observation ---------------------------------
        self.db.upsert_entity_observation(
            entity_id             = entity_id,
            entity_type           = entity_type,
            risk_contribution     = risk_contribution,
            behavioral_flags      = behavioral_flags,
            latest_detection      = latest_detection_code,
            failed_logon_increment = failed_logon_increment,
            logon_host            = logon_host,
        )

        # -- Update shared entity store --------------------------------------
        observation = EngineObservation(
            engine_id              = EngineID.WINDOWS_EVENT,
            risk_contribution      = risk_contribution,
            behavioral_flags       = behavioral_flags,
            latest_detection_code  = latest_detection_code,
        )

        additional_ips = (
            [payload.source_ip]
            if entity_type == EntityType.USER_ACCOUNT and payload.source_ip
            else None
        )

        additional_usernames = (
            [payload.username]
            if entity_type == EntityType.IP_ADDRESS and payload.username
            else None
        )

        self.entity_store.update_observation(
            entity_id            = entity_id,
            entity_type          = entity_type,
            engine_id            = EngineID.WINDOWS_EVENT,
            observation          = observation,
            network_zone         = context.get("zone"),
            additional_usernames = additional_usernames,
            additional_ips       = additional_ips,
            tags                 = behavioral_flags,
        )

        # -- Add to entity timeline -----------------------------------------
        if entity_detections:
            for detection in entity_detections:
                self.entity_store.add_timeline_event(
                    entity_id      = entity_id,
                    engine_id      = EngineID.WINDOWS_EVENT,
                    event_type     = detection.detection_code,
                    description    = detection.description,
                    severity       = detection.severity.value,
                    detection_code = detection.detection_code,
                )
        else:
            self.entity_store.add_timeline_event(
                entity_id  = entity_id,
                engine_id  = EngineID.WINDOWS_EVENT,
                event_type = payload.event_type,
                description = payload.description,
                severity   = payload.severity.value,
            )

        logger.debug(
            "Entity observation updated - entity=%s type=%s risk=%.2f flags=%s",
            entity_id,
            entity_type.value,
            risk_contribution,
            behavioral_flags,
        )