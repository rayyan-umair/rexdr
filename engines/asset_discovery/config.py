"""
rexdr - Network Discovery Engine
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-19
Purpose : Defines all configuration for the Network Discovery engine.
          Extends BaseEngineSettings with scan scheduling, subnet
          targets, and new-device detection settings.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Map the terrain before the enemy does."

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


class AssetDiscoverySettings(BaseEngineSettings):
    """
    Configuration for the Network Discovery engine.
    Extends BaseEngineSettings with scan scope and scheduling settings.
    """

    # Engine identity - fixed, not configurable
    engine_id: EngineID = EngineID.ASSET_DISCOVERY
    api_port:  int      = Field(default=8006)

    # -------------------------------------------------------------------------
    # Scan targets
    # -------------------------------------------------------------------------

    scan_targets_path: Path = Field(
        default=Path("/config/targets.yaml"),
        description="Path to targets.yaml. Subnets are derived from configured target IPs and zones.yaml CIDRs.",
    )

    zones_config_path: Path = Field(
        default=Path("/config/zones.yaml"),
        description="Path to zones.yaml - CIDR ranges scanned are derived from configured zones.",
    )

    # -------------------------------------------------------------------------
    # Scheduling
    # -------------------------------------------------------------------------

    scan_interval_minutes: int = Field(
        default=60,
        description="How often in minutes to run a full network discovery scan.",
    )

    scan_timing_template: str = Field(
        default="-T3",
        description="Nmap timing template - T2 (polite) through T4 (aggressive). T3 is the nmap default.",
    )

    scan_ports: str = Field(
        default="1-1024,3389,5985,8000-8010",
        description="Port range to scan on each discovered host.",
    )

    # -------------------------------------------------------------------------
    # New device detection
    # -------------------------------------------------------------------------

    alert_on_new_device: bool = Field(
        default=True,
        description="Generate a detection when a previously unseen device appears on a monitored zone.",
    )

    alert_on_new_device_staff_zone: bool = Field(
        default=True,
        description="Elevate severity for new devices appearing specifically on staff or server zones.",
    )


# Singleton settings instance
settings = AssetDiscoverySettings()