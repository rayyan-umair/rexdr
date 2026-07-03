"""
rexdr - Network Flow Intelligence Engine
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Defines all configuration for the Network Flow Intelligence
          engine. Extends BaseEngineSettings with packet capture,
          flow analysis, and detection-specific fields.
          All values read from environment variables or the .env file.
          Nothing is hardcoded. Nothing is assumed about the environment.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

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


class NetworkFlowSettings(BaseEngineSettings):
    """
    Configuration for the Network Flow Intelligence engine.
    Extends BaseEngineSettings with capture and detection settings.
    """

    # Engine identity - fixed, not configurable
    engine_id: EngineID = EngineID.NETWORK_FLOW
    api_port:  int      = Field(default=8001)

    # -------------------------------------------------------------------------
    # Capture settings
    # -------------------------------------------------------------------------

    capture_interface: str = Field(
        default="eth0",
        description="Network interface to capture packets from.",
    )

    capture_filter: str = Field(
        default="",
        description="BPF filter string applied to the capture. Empty means capture all.",
    )

    pcap_replay_path: Path | None = Field(
        default=None,
        description="Path to a PCAP file for replay mode. None means live capture.",
    )

    flow_timeout_seconds: int = Field(
        default=120,
        description="How long in seconds before an idle flow is considered closed.",
    )

    max_packet_size: int = Field(
        default=65535,
        description="Maximum packet size in bytes to capture.",
    )

    # -------------------------------------------------------------------------
    # Threat intelligence
    # -------------------------------------------------------------------------

    known_bad_path: Path = Field(
        default=Path("/app/intel/known_bad.txt"),
        description="Path to the known-bad IP and domain list.",
    )

    # -------------------------------------------------------------------------
    # Network zones
    # -------------------------------------------------------------------------

    zones_config_path: Path = Field(
        default=Path("/config/zones.yaml"),
        description="Path to the network zone definitions file.",
    )

    # -------------------------------------------------------------------------
    # Detection thresholds
    # -------------------------------------------------------------------------

    port_scan_threshold: int = Field(
        default=15,
        description="Number of distinct ports in the window to trigger STRIKE-001.",
    )

    port_scan_window_seconds: int = Field(
        default=60,
        description="Time window in seconds for port scan detection.",
    )

    beacon_interval_min_seconds: int = Field(
        default=25,
        description="Minimum interval in seconds to consider traffic as beaconing.",
    )

    beacon_interval_max_seconds: int = Field(
        default=3600,
        description="Maximum interval in seconds to consider traffic as beaconing.",
    )

    beacon_count_threshold: int = Field(
        default=5,
        description="Minimum number of timed connections to trigger STRIKE-002.",
    )

    beacon_dedup_window_minutes: int = Field(
    default=60,
    description="Minutes to suppress duplicate beaconing detections for the same src/dst pair.",
    )

    high_transfer_threshold_mb: float = Field(
        default=100.0,
        description="Outbound transfer threshold in MB to trigger STRIKE-003.",
    )

    internal_pivot_connection_threshold: int = Field(
        default=5,
        description="Number of distinct internal destinations to trigger STRIKE-004.",
    )

    internal_pivot_window_seconds: int = Field(
        default=120,
        description="Time window in seconds for internal pivot detection.",
    )


# Singleton settings instance
settings = NetworkFlowSettings()