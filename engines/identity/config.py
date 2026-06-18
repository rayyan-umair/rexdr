"""
rexdr - Active Directory Intelligence Engine
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Defines all configuration for the Active Directory
          Intelligence engine. Extends BaseEngineSettings with LDAP,
          WinRM, domain snapshot, and detection-specific fields.
          All values read from environment variables or the .env file.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

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


class IdentitySettings(BaseEngineSettings):
    """
    Configuration for the Active Directory Intelligence engine.
    Extends BaseEngineSettings with LDAP, WinRM, and detection settings.
    """

    # Engine identity - fixed, not configurable
    engine_id: EngineID = EngineID.IDENTITY
    api_port:  int      = Field(default=8004)
    zmq_publisher_port: int | None = Field(default=5558)

    # -------------------------------------------------------------------------
    # WinRM / target configuration
    # -------------------------------------------------------------------------

    winrm_targets_path: Path = Field(
        default=Path("/config/targets.yaml"),
        description="Path to targets.yaml listing domain controllers to collect from.",
    )

    winrm_username: str = Field(
        ...,
        description="Domain admin username for WinRM authentication.",
    )

    winrm_password: str = Field(
        ...,
        description="Password for WinRM authentication.",
    )

    winrm_port: int = Field(default=5985)
    winrm_use_ssl: bool = Field(default=False)

    # -------------------------------------------------------------------------
    # LDAP configuration
    # -------------------------------------------------------------------------

    ldap_base_dn: str = Field(
        ...,
        description="LDAP base distinguished name, e.g. DC=corp,DC=local",
    )

    ldap_domain: str = Field(
        ...,
        description="Active Directory domain name, e.g. corp.local",
    )

    ldap_port: int = Field(default=389)
    ldap_use_ssl: bool = Field(default=False)

    # -------------------------------------------------------------------------
    # Snapshot and polling
    # -------------------------------------------------------------------------

    domain_snapshot_interval_minutes: int = Field(
        default=15,
        description="How often in minutes to take a full domain group membership snapshot.",
    )

    event_poll_interval_seconds: int = Field(
        default=60,
        description="How often in seconds to poll domain controllers for new security events.",
    )

    # -------------------------------------------------------------------------
    # Detection thresholds
    # -------------------------------------------------------------------------

    high_value_groups: list[str] = Field(
        default=[
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "backup operators", "account operators",
        ],
        description="Group names considered high-value for AD-002 severity escalation.",
    )

    kerberoast_ticket_threshold: int = Field(
        default=5,
        description="Number of TGS requests for service accounts in the window to trigger AD-001.",
    )

    kerberoast_window_minutes: int = Field(
        default=10,
        description="Time window in minutes for Kerberoasting detection.",
    )

    anomalous_auth_new_host_threshold: int = Field(
        default=3,
        description="Number of new, never-before-seen hosts a user authenticates to before AD-003 fires.",
    )


# Singleton settings instance
settings = IdentitySettings()