"""
rexdr_core
__init__.py - REXDR core shared library entry point

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Exposes the public API of the rexdr_core package.
          All engines import from here. Nothing outside this package
          should import from submodules directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import METADATA, VERSION, EngineID
from rexdr_core.schemas import (
    NormalizedTelemetryPayload,
    Alert,
    AlertSeverity,
    Entity,
    EntityType,
    AttackChain,
    ChainSeverity,
    Detection,
    NetworkZone,
    EngineObservation,
    CaseFile,
)
from rexdr_core.database import BaseDatabase
from rexdr_core.settings import BaseEngineSettings
from rexdr_core.formula import calculate_entity_risk_score
from rexdr_core.entity_store import EntityStoreClient
from rexdr_core.ai_client import AIClient


__all__ = [
    "METADATA", "VERSION", "EngineID",
    "NormalizedTelemetryPayload", "Alert", "AlertSeverity",
    "Entity", "EntityType", "AttackChain", "ChainSeverity",
    "Detection", "NetworkZone", "EngineObservation", "CaseFile",
    "BaseDatabase", "BaseEngineSettings",
    "calculate_entity_risk_score", "EntityStoreClient",
    "AIClient"
]