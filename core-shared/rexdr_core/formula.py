"""
rexdr_core
formula.py - Entity risk scoring formula for the REXDR platform

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Provides the canonical risk scoring function used by all
          engines to calculate and update entity risk scores.
          This is the single source of truth for how risk is calculated
          across the entire platform. No engine implements its own
          scoring logic. Every risk score in REXDR comes from here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import math
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.schemas import (
    AlertSeverity,
    Entity,
    EngineObservation,
)

# ============================================================================

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Severity weights - how much each severity level contributes to risk
# -------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[AlertSeverity, float] = {
    AlertSeverity.INFO:     2.0,
    AlertSeverity.LOW:      10.0,
    AlertSeverity.MEDIUM:   25.0,
    AlertSeverity.HIGH:     50.0,
    AlertSeverity.CRITICAL: 85.0,
}

# Maximum risk contribution a single engine can add
ENGINE_MAX_CONTRIBUTION = 100.0

# How quickly risk decays when an entity is quiet - per hour
DECAY_RATE_PER_HOUR = 0.05

# Multiplier applied when entity is a critical asset
CRITICAL_ASSET_MULTIPLIER = 1.4

# Multiplier applied when a cross-zone event is detected
CROSS_ZONE_MULTIPLIER = 1.3

# Multiplier applied when entity is part of an active attack chain
ACTIVE_CHAIN_MULTIPLIER = 1.5

# Maximum possible risk score
RISK_SCORE_MAX = 100.0
RISK_SCORE_MIN = 0.0


# ============================================================================
# Core scoring function
# ============================================================================

def calculate_entity_risk_score(entity: Entity) -> float:
    """
    Calculate the composite risk score for an entity across all engines.

    The score is a weighted combination of:
    - Each engine's individual risk contribution
    - Time-based decay since last detection
    - Critical asset multiplier
    - Cross-zone event multiplier
    - Active attack chain multiplier

    Returns a float between 0.0 and 100.0.
    Higher is more dangerous. 0.0 means no risk signals.
    """

    if not entity.engine_observations:
        return RISK_SCORE_MIN

    # -- Step 1: Sum engine contributions ------------------------------------
    raw_score = _sum_engine_contributions(entity)

    # -- Step 2: Apply time decay --------------------------------------------
    raw_score = _apply_time_decay(raw_score, entity.last_seen)

    # -- Step 3: Apply context multipliers -----------------------------------
    raw_score = _apply_context_multipliers(raw_score, entity)

    # -- Step 4: Clamp to valid range ----------------------------------------
    final_score = max(RISK_SCORE_MIN, min(RISK_SCORE_MAX, raw_score))

    logger.debug(
        "Risk score calculated - entity=%s score=%.2f",
        entity.entity_id,
        final_score,
    )

    return round(final_score, 2)


# ============================================================================
# Internal helpers
# ============================================================================

def _sum_engine_contributions(entity: Entity) -> float:
    """
    Sum the risk contributions from all engine observations.
    Each engine contributes up to ENGINE_MAX_CONTRIBUTION.
    Multiple engines contributing simultaneously compounds the score.
    """
    total = 0.0

    for obs in entity.engine_observations.values():
        if isinstance(obs, dict):
            contribution = obs.get("risk_contribution", 0.0)
        else:
            contribution = obs.risk_contribution

        contribution = max(0.0, min(ENGINE_MAX_CONTRIBUTION, contribution))
        total += contribution

    return total


def _apply_time_decay(score: float, last_seen: datetime) -> float:
    """
    Apply exponential decay based on how long ago the entity was last seen.
    An entity that has been quiet decays toward 0 over time.
    Decay rate: DECAY_RATE_PER_HOUR per hour of silence.
    """
    if score <= 0.0:
        return score

    now = datetime.now(timezone.utc)

    # Handle naive datetimes
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)

    hours_since = (now - last_seen).total_seconds() / 3600.0

    if hours_since <= 0:
        return score

    decay_factor = math.exp(-DECAY_RATE_PER_HOUR * hours_since)
    decayed_score = score * decay_factor

    logger.debug(
        "Decay applied - hours_since=%.2f decay_factor=%.4f original=%.2f decayed=%.2f",
        hours_since,
        decay_factor,
        score,
        decayed_score,
    )

    return decayed_score


def _apply_context_multipliers(score: float, entity: Entity) -> float:
    """
    Apply situational multipliers that elevate risk based on context.
    Multipliers stack multiplicatively - a critical asset in an active
    chain on a cross-zone event receives the full compound multiplier.
    """
    if score <= 0.0:
        return score

    multiplier = 1.0

    if entity.is_critical_asset:
        multiplier *= CRITICAL_ASSET_MULTIPLIER
        logger.debug("Critical asset multiplier applied - entity=%s", entity.entity_id)

    if entity.active_chain_ids:
        multiplier *= ACTIVE_CHAIN_MULTIPLIER
        logger.debug(
            "Active chain multiplier applied - entity=%s chains=%d",
            entity.entity_id,
            len(entity.active_chain_ids),
        )

    # Cross-zone flag is checked from engine observations
    for obs in entity.engine_observations.values():
        flags = obs.get("behavioral_flags", []) if isinstance(obs, dict) else obs.behavioral_flags
        if "cross_zone" in flags:
            multiplier *= CROSS_ZONE_MULTIPLIER
            logger.debug(
                "Cross-zone multiplier applied - entity=%s",
                entity.entity_id,
            )
            break

    return score * multiplier


# ============================================================================
# Severity to contribution helper
# ============================================================================

def severity_to_contribution(severity: AlertSeverity) -> float:
    """
    Convert a detection severity into a risk contribution value.
    Used by engines when updating their observation's risk_contribution.
    Multiple detections of the same severity stack with diminishing returns.
    """
    return SEVERITY_WEIGHTS.get(severity, 0.0)


def stack_contributions(existing: float, new_contribution: float) -> float:
    """
    Stack a new contribution onto an existing engine risk contribution
    with diminishing returns. Prevents a single engine from driving
    the score to 100 through repeated low-severity detections.

    Formula: existing + new * (1 - existing / ENGINE_MAX_CONTRIBUTION)
    """
    headroom = 1.0 - (existing / ENGINE_MAX_CONTRIBUTION)
    stacked = existing + (new_contribution * headroom)
    return min(stacked, ENGINE_MAX_CONTRIBUTION)