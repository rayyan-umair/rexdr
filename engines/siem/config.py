"""
rexdr - SIEM Correlation Engine
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-15
Purpose : Defines all configuration for the SIEM Correlation engine.
          Extends BaseEngineSettings with Sigma rule loading, ZeroMQ
          subscription, and cross-engine correlation settings.
          This engine is the only one that attaches to every other
          engine's database for cross-engine SQL correlation.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
from pathlib import Path

# -- Third Party -------------------------------------------------------------
from pydantic import Field

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID
from rexdr_core.settings import BaseEngineSettings

# ============================================================================


class SiemSettings(BaseEngineSettings):
    """
    Configuration for the SIEM Correlation engine.
    Extends BaseEngineSettings with Sigma rules, ZeroMQ subscriptions,
    and chain correlation thresholds.
    """

    # Engine identity - fixed, not configurable
    engine_id: EngineID = EngineID.SIEM
    api_port:  int      = Field(default=8002)

    # -------------------------------------------------------------------------
    # ZeroMQ subscriptions - SIEM listens to all capture-layer engines
    # -------------------------------------------------------------------------

    zmq_subscriber_ports: list[int] = Field(
        default=[5555, 5557, 5558],
        description="ZeroMQ ports SIEM subscribes to - windows_event, dns, identity.",
    )

    # -------------------------------------------------------------------------
    # Sigma rules
    # -------------------------------------------------------------------------

    sigma_rules_path: Path = Field(
        default=Path("/config/sigma_rules"),
        description="Directory containing Sigma YAML rule files.",
    )

    sigma_hot_reload_seconds: int = Field(
        default=60,
        description="How often in seconds to check for Sigma rule file changes.",
    )

    # -------------------------------------------------------------------------
    # Cross-engine correlation
    # -------------------------------------------------------------------------

    correlation_window_minutes: int = Field(
        default=60,
        description="Time window in minutes to look for related detections across engines.",
    )

    chain_min_engines: int = Field(
        default=2,
        description="Minimum number of distinct engines required to form an attack chain.",
    )

    chain_check_interval_seconds: int = Field(
        default=15,
        description="How often in seconds the chain builder runs.",
    )

    # -------------------------------------------------------------------------
    # Replay
    # -------------------------------------------------------------------------

    replay_path: Path = Field(
        default=Path("/app/replay/sample_attack_log.json"),
        description="Path to the sample attack log used for rule testing and demos.",
    )


# Singleton settings instance
settings = SiemSettings()