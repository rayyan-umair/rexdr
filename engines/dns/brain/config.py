"""
rexdr - DNS Behavioral Intelligence Engine
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-16
Purpose : Defines all configuration for the DNS Behavioral Intelligence
          engine. Extends BaseEngineSettings with entropy scoring,
          record type tracking, and detection thresholds.
          All values read from environment variables or the .env file.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Hunt the whisper."

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


class DnsSettings(BaseEngineSettings):
    """
    Configuration for the DNS Behavioral Intelligence engine.
    Extends BaseEngineSettings with entropy and detection thresholds.
    """

    # Engine identity - fixed, not configurable
    engine_id: EngineID = EngineID.DNS
    api_port:  int      = Field(default=8003)
    zmq_publisher_port: int | None = Field(default=5557)

    # -------------------------------------------------------------------------
    # Threat intelligence
    # -------------------------------------------------------------------------

    rare_tlds_path: Path = Field(
        default=Path("/app/intel/rare_tlds.txt"),
        description="Path to the list of rare or commonly abused TLDs.",
    )

    # -------------------------------------------------------------------------
    # Detection thresholds
    # -------------------------------------------------------------------------

    entropy_threshold: float = Field(
        default=4.2,
        description="Shannon entropy threshold above which a subdomain is flagged - DNS-001.",
    )

    record_type_spike_threshold: int = Field(
        default=20,
        description="Number of TXT/NULL/AAAA records in the window to trigger DNS-002.",
    )

    record_type_spike_window_seconds: int = Field(
        default=300,
        description="Time window in seconds for record type spike detection.",
    )

    record_type_spike_dedup_window_minutes: int = Field(
        default=60,
        description="Minutes to suppress duplicate DNS-002 detections for the same source_ip and record_type pair.",
    )

    entropy_dedup_window_minutes: int = Field(
        default=60,
        description="Minutes to suppress duplicate DNS-001 detections for the same source_ip and query_name pair.",
    )

    beacon_interval_min_seconds: int = Field(
        default=25,
        description="Minimum interval in seconds to consider DNS queries as beaconing.",
    )

    beacon_interval_max_seconds: int = Field(
        default=3600,
        description="Maximum interval in seconds to consider DNS queries as beaconing.",
    )

    beacon_count_threshold: int = Field(
        default=5,
        description="Minimum number of timed queries to trigger DNS-003.",
    )

    nxdomain_storm_threshold: int = Field(
        default=10,
        description="Number of NXDOMAIN responses in the window to trigger DNS-004.",
    )

    nxdomain_storm_window_seconds: int = Field(
        default=60,
        description="Time window in seconds for NXDOMAIN storm detection.",
    )


# Singleton settings instance
settings = DnsSettings()