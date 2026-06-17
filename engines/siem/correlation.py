"""
rexdr - SIEM Correlation Engine
correlation.py - Cross-engine attack chain builder

Author  : Rayyan Umair
Date    : 2026-06-15
Purpose : The core differentiator of REXDR. Builds cross-engine attack
          chains by correlating detections from multiple engines against
          the same entity within a time window. Generates the 5W+H
          investigation narrative for every chain. This is what makes
          REXDR an upgrade over eight standalone tools - no individual
          engine can see what this module sees.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store import EntityStore
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AttackChain, ChainSeverity, Detection, EntityType
from siem.config import settings
from siem.database import SiemDatabase

# ============================================================================

logger = logging.getLogger(__name__)

# Severity escalation - more engines and higher severities push the chain up
SEVERITY_RANK = {
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}


class ChainBuilder:
    """
    Builds cross-engine attack chains by correlating detections
    against the same entity across multiple engines.

    The core insight: an event in isolation may be low severity,
    but the same entity triggering detections in two or more
    distinct engines within a correlation window is a categorically
    different and more severe signal - a campaign, not a blip.
    """

    def __init__(self, db: SiemDatabase, entity_store: EntityStore) -> None:
        self.db = db
        self.entity_store = entity_store

    def run_correlation_pass(self) -> list[AttackChain]:
        """
        Run a full correlation pass across all entities with recent
        detections. Called periodically by the pipeline on
        chain_check_interval_seconds. Returns any newly created chains.
        """
        candidate_entities = self.db.get_entities_with_recent_detections(
            window_minutes=settings.correlation_window_minutes,
        )

        new_chains: list[AttackChain] = []

        for entity_id in candidate_entities:
            chain = self._evaluate_entity(entity_id)
            if chain:
                new_chains.append(chain)

        if new_chains:
            logger.info(
                "Correlation pass complete - new_chains=%d candidates=%d",
                len(new_chains), len(candidate_entities),
            )

        return new_chains

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _evaluate_entity(self, entity_id: str) -> AttackChain | None:
        """
        Evaluate a single entity for cross-engine chain formation.
        Returns a new AttackChain if criteria are met, None otherwise.
        Skips entities that already have an active chain.
        """
        if self.db.chain_exists_for_entity(entity_id):
            return None

        detection_rows = self.db.get_cross_engine_detections(
            entity_id      = entity_id,
            window_minutes = settings.correlation_window_minutes,
        )

        if not detection_rows:
            return None

        distinct_engines = {row["engine_id"] for row in detection_rows}

        if len(distinct_engines) < settings.chain_min_engines:
            return None

        return self._build_chain(entity_id, detection_rows, distinct_engines)

    def _build_chain(
        self,
        entity_id: str,
        detection_rows: list[dict],
        distinct_engines: set[str],
    ) -> AttackChain:
        """
        Construct the AttackChain object from correlated detection rows.
        Calculates aggregate severity and generates the 5W+H narrative.
        """
        severity = self._calculate_chain_severity(detection_rows, distinct_engines)

        mitre_tactics = list({
            row["mitre_tactic"] for row in detection_rows if row.get("mitre_tactic")
        })
        mitre_techniques = list({
            row["mitre_technique"] for row in detection_rows if row.get("mitre_technique")
        })

        title = self._generate_title(detection_rows, distinct_engines)
        narrative = self._generate_narrative(entity_id, detection_rows, distinct_engines)

        # Build lightweight Detection stubs for the chain record
        # Full evidence stays in each engine's own database - the chain
        # references detection_ids, not full duplicated objects
        detections = [
            Detection(
                detection_code  = row["detection_code"],
                engine_id       = EngineID(row["engine_id"]),
                timestamp       = row["timestamp"],
                severity        = row["severity"],
                title           = row["title"],
                description     = row["description"],
                entity_id       = row["entity_id"],
                entity_type     = EntityType(row["entity_type"]),
                mitre_tactic    = row.get("mitre_tactic"),
                mitre_technique = row.get("mitre_technique"),
            )
            for row in detection_rows
        ]

        chain = AttackChain(
            severity              = severity,
            title                 = title,
            narrative             = narrative,
            entity_id             = entity_id,
            contributing_engines  = [EngineID(e) for e in distinct_engines],
            detections            = detections,
            mitre_tactics         = mitre_tactics,
            mitre_techniques      = mitre_techniques,
        )

        self.db.insert_chain(chain)
        self.entity_store.add_to_chain(entity_id, str(chain.chain_id))

        return chain

    def _calculate_chain_severity(
        self,
        detection_rows: list[dict],
        distinct_engines: set[str],
    ) -> ChainSeverity:
        """
        Calculate the chain's severity. A chain is always at least as
        severe as its highest individual detection, and escalates one
        level when three or more engines are involved - reflecting
        that breadth across the kill chain is itself a severity signal.
        """
        max_rank = max(
            SEVERITY_RANK.get(row["severity"], 1) for row in detection_rows
        )

        if len(distinct_engines) >= 3:
            max_rank = min(max_rank + 1, 4)

        rank_to_severity = {
            1: ChainSeverity.LOW,
            2: ChainSeverity.MEDIUM,
            3: ChainSeverity.HIGH,
            4: ChainSeverity.CRITICAL,
        }
        return rank_to_severity[max_rank]

    def _generate_title(
        self,
        detection_rows: list[dict],
        distinct_engines: set[str],
    ) -> str:
        """Generate a short, descriptive chain title from contributing detection codes."""
        codes = sorted({row["detection_code"] for row in detection_rows})
        engine_count = len(distinct_engines)
        return f"Cross-Engine Campaign - {engine_count} Engines - {', '.join(codes[:4])}"

    def _generate_narrative(
        self,
        entity_id: str,
        detection_rows: list[dict],
        distinct_engines: set[str],
    ) -> str:
        """
        Generate the full 5W+H investigation narrative for this chain.
        This is the core investigation experience REXDR provides that
        no individual engine could produce on its own.
        """
        sorted_rows = sorted(detection_rows, key=lambda r: r["timestamp"])
        first = sorted_rows[0]
        last = sorted_rows[-1]

        engines_display = ", ".join(sorted(distinct_engines))

        sequence_lines = []
        for i, row in enumerate(sorted_rows, start=1):
            sequence_lines.append(
                f"  {i}. [{row['timestamp']}] {row['engine_id']} fired "
                f"{row['detection_code']} ({row['severity']}): {row['title']}"
            )

        narrative = (
            f"WHO: Entity {entity_id} is the common subject of this campaign.\n\n"
            f"WHAT: {len(detection_rows)} detections fired across {len(distinct_engines)} "
            f"distinct REXDR engines ({engines_display}), correlated into a single "
            f"cross-engine attack chain.\n\n"
            f"WHEN: Activity began at {first['timestamp']} and was most recently "
            f"observed at {last['timestamp']}.\n\n"
            f"WHERE: Detections originated from the {engines_display} intelligence "
            f"layers monitoring this entity.\n\n"
            f"WHY: No single engine's detection alone reached chain-forming severity. "
            f"The correlation of {len(distinct_engines)} independent engines flagging "
            f"the same entity within the configured correlation window is what "
            f"elevated this from isolated low-confidence signals into a confirmed "
            f"multi-stage campaign.\n\n"
            f"HOW: Detection sequence in chronological order:\n" + "\n".join(sequence_lines)
        )

        return narrative