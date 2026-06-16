"""
rexdr - Windows Event Intelligence Engine
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Defines all configuration for the Windows Event Intelligence
          engine. Extends BaseEngineSettings with Windows-specific fields.
          All values read from environment variables or the .env file.
          Nothing is hardcoded. Nothing is assumed about the environment.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

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


class WindowsEventSettings(BaseEngineSettings):
    """
    Configuration for the Windows Event Intelligence engine.
    Extends BaseEngineSettings with WinRM, collection, and
    detection-specific settings.
    """

    # Engine identity - fixed, not configurable
    engine_id: EngineID = EngineID.WINDOWS_EVENT
    api_port: int = Field(default=8000)
    zmq_publisher_port: int | None = Field(default=5555)

    # -------------------------------------------------------------------------
    # WinRM / target configuration
    # -------------------------------------------------------------------------

    winrm_targets_path: Path = Field(
        default=Path("/config/targets.yaml"),
        description="Path to targets.yaml listing all Windows machines to collect from.",
    )

    winrm_username: str = Field(
        ...,
        description="Domain or local admin username for WinRM authentication.",
    )

    winrm_password: str = Field(
        ...,
        description="Password for WinRM authentication.",
    )

    winrm_port: int = Field(
        default=5985,
        description="WinRM port. 5985 for HTTP, 5986 for HTTPS.",
    )

    winrm_use_ssl: bool = Field(
        default=False,
        description="Use HTTPS for WinRM connections.",
    )

    winrm_max_concurrent: int = Field(
        default=10,
        description=(
            "Maximum concurrent WinRM connections. "
            "Keep below the WinRM MaxConcurrentUsers limit on target machines."
        ),
    )

    # -------------------------------------------------------------------------
    # Collection settings
    # -------------------------------------------------------------------------

    collection_interval_critical: int = Field(
        default=60,
        description="Collection interval in seconds for critical priority targets.",
    )

    collection_interval_high: int = Field(
        default=180,
        description="Collection interval in seconds for high priority targets.",
    )

    collection_interval_normal: int = Field(
        default=300,
        description="Collection interval in seconds for normal priority targets.",
    )

    max_events_per_collection: int = Field(
        default=1000,
        description="Maximum events to pull per collection cycle per target.",
    )

    event_logs: list[str] = Field(
        default=["Security", "System", "Application"],
        description="Windows event logs to collect from each target.",
    )

    # -------------------------------------------------------------------------
    # Detection thresholds
    # -------------------------------------------------------------------------

    brute_force_threshold: int = Field(
        default=5,
        description="Number of failed logons in the time window to trigger LC-001.",
    )

    brute_force_window_minutes: int = Field(
        default=5,
        description="Time window in minutes for brute force detection.",
    )

    lateral_movement_window_minutes: int = Field(
        default=10,
        description="Time window in minutes for lateral movement detection.",
    )

    lateral_movement_host_threshold: int = Field(
        default=3,
        description="Number of distinct hosts in the window to trigger LC-003.",
    )

    # -------------------------------------------------------------------------
    # ZeroMQ
    # -------------------------------------------------------------------------

    zmq_host: str = Field(
        default="0.0.0.0",
        description="ZeroMQ PUB bind host.",
    )


# Singleton settings instance used by all modules in this engine
settings = WindowsEventSettings()