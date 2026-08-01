"""
rexdr - Active Directory Intelligence Engine
entity.py - Entity observation management for the Identity engine

Author  : Rayyan Umair
Date    : 2026-06-18
Updated : 2026-07-14 - process(), process_detection_only(), and their
          internal helpers are now async, and all entity_store calls
          are awaited, matching EntityStoreClient's conversion to
          httpx.AsyncClient.
Updated : 2026-08-01 - Added normalize_username(). The same account was
          being tracked as several separate entities depending on which
          event reported it, and machine accounts were slipping past the
          trailing-$ filter because the $ sits before the realm suffix.
          Every one of those was a candidate entity for cross-engine
          correlation, able to form its own chain and case file.
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

# Built-in Windows accounts that appear constantly in the Security log but
# never represent a real identity worth tracking, correlating on, or
# containing. Each was previously stored as a distinct entity and was
# eligible to form its own cross-engine attack chain.
BUILTIN_ACCOUNTS = {
    "system",
    "local system",
    "local service",
    "network service",
    "anonymous logon",
    "iusr",
    "guest",
}

# Per-session pseudo-accounts Windows creates and discards constantly.
BUILTIN_PREFIXES = ("umfd-", "dwm-", "font driver host")


def normalize_username(raw: str | None) -> str | None:
    """
    Reduce a Windows username to a single canonical entity id.

    The same account is reported several different ways depending on which
    event produced it - 'Administrator', 'administrator', and
    'Administrator@REXDRLAB.LOCAL' are one identity but were tracked as
    three separate entities, each able to form its own attack chain and
    generate its own case file.

    Returns None for anything that should not be tracked at all: machine
    accounts and built-in service accounts.
    """
    if not raw:
        return None

    name = raw.strip()
    if not name:
        return None

    # UPN realm suffix: Administrator@REXDRLAB.LOCAL -> Administrator
    if "@" in name:
        name = name.split("@", 1)[0]

    # NetBIOS prefix: REXDRLAB\Administrator -> Administrator
    if "\\" in name:
        name = name.rsplit("\\", 1)[1]

    name = name.strip()
    if not name:
        return None

    # Machine accounts carry a trailing $ - but it sits before any realm
    # suffix, so this has to run after the suffix is stripped. Checking the
    # raw string misses LAB-DC01$@REXDRLAB.LOCAL entirely, which is exactly
    # how domain controllers ended up tracked as user entities.
    if name.endswith("$"):
        return None

    lowered = name.lower()

    if lowered in BUILTIN_ACCOUNTS:
        return None

    if any(lowered.startswith(prefix) for prefix in BUILTIN_PREFIXES):
        return None

    return lowered


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
        username = normalize_username(payload.username)
        if username is None:
            return

        try:
            await self._update_entity(username, payload, detections)
        except Exception as e:
            logger.error(
                "Failed to update entity observation - entity=%s error=%s",
                username, str(e),
            )

    async def process_detection_only(
        self,
        detection: Detection,
        new_group: str | None = None,
    ) -> None:
        """
        Process a standalone detection not tied to a normalized event -
        used for AD-002 group diff detections which originate from the
        domain snapshot engine, not from a live event stream. new_group
        is the group this entity's membership changed in, so it gets
        recorded in the entity's known_groups history.
        """
        entity_id = normalize_username(detection.entity_id)
        if entity_id is None:
            return

        try:
            await self._apply_detection(entity_id, [detection], new_group=new_group)
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
        entity_detections = [d for d in detections if d.entity_id == payload.username]
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