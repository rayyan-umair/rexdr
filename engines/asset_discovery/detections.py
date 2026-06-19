"""
rexdr - Network Discovery Engine
detections.py - Detection logic for the Asset Discovery engine

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Implements new-device detection for the Network Discovery
          engine. Fires when a device appears on a monitored network
          zone that has never been seen in a previous scan cycle.
          Severity escalates for staff and server zones versus guest
          or low-trust zones.

          DISC-001  New Device Detected

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Map the terrain before the enemy does."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Internal ----------------------------------------------------------------
from rexdr_core.formula import severity_to_contribution
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, Detection, EntityType
from asset_discovery.config import settings

# ============================================================================

logger = logging.getLogger(__name__)

# Zone IDs considered high-sensitivity for new device alerts
HIGH_SENSITIVITY_ZONE_KEYWORDS = ("staff", "server", "admin", "dc")


class AssetDiscoveryDetections:
    """
    Detection engine for Network Discovery.
    Single detection - DISC-001 New Device Detected - fired when
    a previously unseen asset appears in a scan result.
    """

    def run(self, asset: dict, is_new: bool) -> list[Detection]:
        """Run new-device detection against a scanned asset result."""
        detections: list[Detection] = []

        disc001 = self._disc001_new_device(asset, is_new)
        if disc001:
            detections.append(disc001)
            logger.info(
                "Detection fired - code=%s entity=%s severity=%s",
                disc001.detection_code, disc001.entity_id, disc001.severity.value,
            )

        return detections

    # -------------------------------------------------------------------------
    # DISC-001 - New Device Detected
    # -------------------------------------------------------------------------

    def _disc001_new_device(self, asset: dict, is_new: bool) -> Detection | None:
        """
        DISC-001 - New Device Detected
        Fires when a device not present in the known asset inventory
        appears on a monitored network zone. Severity is elevated for
        staff, server, or admin zones since unauthorized devices on
        these segments represent a more serious risk than on guest
        or low-trust networks.

        MITRE: T1592 - Gather Victim Host Information (defender-side framing:
        unauthorized asset presence)
        """
        if not is_new or not settings.alert_on_new_device:
            return None

        ip_address = asset.get("ip_address")
        if not ip_address:
            return None

        zone = (asset.get("network_zone") or "").lower()
        is_high_sensitivity = any(keyword in zone for keyword in HIGH_SENSITIVITY_ZONE_KEYWORDS)

        severity = (
            AlertSeverity.HIGH
            if is_high_sensitivity and settings.alert_on_new_device_staff_zone
            else AlertSeverity.LOW
        )

        open_ports_str = ", ".join(str(p) for p in asset.get("open_ports", [])[:10])

        hostname = asset.get("hostname")
        hostname_str = f"({hostname}) " if hostname else ""

        description      = (
                f"Previously unseen device {ip_address} "
                f"{hostname_str}"
                f"appeared on network zone '{asset.get('network_zone', 'unknown')}'."
                f"{' This zone is high-sensitivity.' if is_high_sensitivity else ''} "
                f"Open ports: {open_ports_str or 'none detected'}. "
                f"OS fingerprint: {asset.get('os_fingerprint', 'unknown')}."
            ),