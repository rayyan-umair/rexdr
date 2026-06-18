"""
rexdr - Incident Response Orchestration Engine
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Defines all configuration for the Incident Response
          Orchestration engine. Extends BaseEngineSettings with
          playbook loading, forensic case file, and containment
          integration settings.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

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


class ResponseSettings(BaseEngineSettings):
    """
    Configuration for the Incident Response Orchestration engine.
    Extends BaseEngineSettings with playbook and case file settings.
    """

    # Engine identity - fixed, not configurable
    engine_id: EngineID = EngineID.RESPONSE
    api_port:  int      = Field(default=8005)

    # -------------------------------------------------------------------------
    # ZeroMQ subscriptions - response listens to SIEM and identity
    # -------------------------------------------------------------------------

    zmq_subscriber_ports: list[int] = Field(
        default=[5555, 5557, 5558],
        description="ZeroMQ ports response subscribes to.",
    )

    # -------------------------------------------------------------------------
    # Playbooks
    # -------------------------------------------------------------------------

    playbooks_path: Path = Field(
        default=Path("/config/playbooks"),
        description="Directory containing YAML playbook files.",
    )

    playbook_hot_reload_seconds: int = Field(
        default=60,
        description="How often in seconds to check for playbook file changes.",
    )

    # -------------------------------------------------------------------------
    # Forensic case files
    # -------------------------------------------------------------------------

    cases_dir: Path = Field(
        default=Path("/cases"),
        description="Directory where immutable forensic case files are written.",
    )

    # -------------------------------------------------------------------------
    # Containment integrations
    # -------------------------------------------------------------------------

    identity_engine_url: str = Field(
        default="http://identity:8004",
        description="Base URL for the Identity engine API - used for AD account lockdown.",
    )

    auto_contain_critical: bool = Field(
        default=True,
        description="Automatically execute containment playbooks for critical severity chains.",
    )

    auto_contain_high: bool = Field(
        default=False,
        description="Automatically execute containment playbooks for high severity chains.",
    )

    # -------------------------------------------------------------------------
    # Orchestrator
    # -------------------------------------------------------------------------

    orchestrator_poll_interval_seconds: int = Field(
        default=10,
        description="How often in seconds the orchestrator checks for new chains to respond to.",
    )

    siem_engine_url: str = Field(
        default="http://siem:8002",
        description="Base URL for the SIEM engine API - used to fetch active chains.",
    )


# Singleton settings instance
settings = ResponseSettings()