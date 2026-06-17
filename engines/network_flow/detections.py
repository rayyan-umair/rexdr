"""
rexdr - Network Flow Intelligence Engine
detections.py - Detection logic for the Network Flow engine

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Implements all five detection algorithms for the Network Flow
          Intelligence engine. Each detection is a self-contained method
          that receives an enriched flow, queries the database for
          context, and returns a Detection object if the threshold is met.
          All detections follow the ENGINE-NNN code format.

          STRIKE-001  Port Scan
          STRIKE-002  Beaconing
          STRIKE-003  High Outbound Transfer
          STRIKE-004  Internal Pivot
          STRIKE-005  Known-Bad Destination

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import statistics

# -- Internal ----------------------------------------------------------------
from rexdr_core.formula import severity_to_contribution
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, Detection, EntityType
from network_flow.config import settings
from network_flow.database import NetworkFlowDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class NetworkFlowDetections:
    """
    Detection engine for Network Flow Intelligence.
    Receives enriched flow dicts and runs all applicable
    detection algorithms against each one.
    """

    def __init__(self, db: NetworkFlowDatabase) -> None:
        self.db = db

    def run(self, flow: dict) -> list[Detection]:
        """
        Run all detection algorithms against a flow.
        Returns a list of Detection objects - empty if nothing fired.
        """
        detections: list[Detection] = []

        strike001 = self._strike001_port_scan(flow)
        strike002 = self._strike002_beaconing(flow)
        strike003 = self._strike003_high_outbound_transfer(flow)
        strike004 = self._strike004_internal_pivot(flow)
        strike005 = self._strike005_known_bad_destination(flow)

        for detection in [strike001, strike002, strike003, strike004, strike005]:
            if detection:
                detections.append(detection)
                logger.info(
                    "Detection fired - code=%s entity=%s severity=%s",
                    detection.detection_code,
                    detection.entity_id,
                    detection.severity.value,
                )

        return detections

    # -------------------------------------------------------------------------
    # STRIKE-001 - Port Scan
    # -------------------------------------------------------------------------

    def _strike001_port_scan(self, flow: dict) -> Detection | None:
        """
        STRIKE-001 - Port Scan Detection
        Fires when a source IP probes more than port_scan_threshold
        distinct destination ports within port_scan_window_seconds.

        MITRE: T1046 - Network Service Discovery
        """
        src_ip = flow["src_ip"]

        port_count = self.db.get_port_scan_count(
            src_ip         = src_ip,
            window_seconds = settings.port_scan_window_seconds,
        )

        if port_count < settings.port_scan_threshold:
            return None

        severity = (
            AlertSeverity.HIGH
            if port_count >= settings.port_scan_threshold * 3
            else AlertSeverity.MEDIUM
        )

        return Detection(
            detection_code   = "STRIKE-001",
            engine_id        = EngineID.NETWORK_FLOW,
            severity         = severity,
            title            = "Port Scan Detected",
            description      = (
                f"Source {src_ip} probed {port_count} distinct ports within "
                f"{settings.port_scan_window_seconds} seconds. "
                f"Threshold is {settings.port_scan_threshold}. "
                f"Consistent with reconnaissance or vulnerability scanning activity."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Discovery",
            mitre_technique  = "T1046",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # STRIKE-002 - Beaconing
    # -------------------------------------------------------------------------

    def _strike002_beaconing(self, flow: dict) -> Detection | None:
        """
        STRIKE-002 - Beaconing Detection
        Fires when connections from src_ip to dst_ip occur at regular,
        timed intervals consistent with C2 heartbeat behavior.
        Uses coefficient of variation to detect timing regularity.

        MITRE: T1071 - Application Layer Protocol (C2)
        """
        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]

        if flow.get("is_external") is not True:
            return None

        intervals = self.db.get_connection_intervals(
            src_ip = src_ip,
            dst_ip = dst_ip,
            limit  = settings.beacon_count_threshold + 5,
        )

        if len(intervals) < settings.beacon_count_threshold:
            return None

        avg_interval = statistics.mean(intervals)

        if not (settings.beacon_interval_min_seconds <= avg_interval <= settings.beacon_interval_max_seconds):
            return None

        # Coefficient of variation - low value means highly regular timing
        if avg_interval == 0:
            return None

        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        coefficient_of_variation = std_dev / avg_interval

        # CV below 0.3 indicates suspiciously regular timing - C2 heartbeat pattern
        if coefficient_of_variation >= 0.3:
            return None

        severity = (
            AlertSeverity.CRITICAL
            if coefficient_of_variation < 0.1
            else AlertSeverity.HIGH
        )

        return Detection(
            detection_code   = "STRIKE-002",
            engine_id        = EngineID.NETWORK_FLOW,
            severity         = severity,
            title            = "Beaconing Detected",
            description      = (
                f"Source {src_ip} shows {len(intervals)} connections to {dst_ip} "
                f"with highly regular timing - average interval {avg_interval:.1f}s, "
                f"coefficient of variation {coefficient_of_variation:.3f}. "
                f"This timing regularity is consistent with C2 beacon heartbeat traffic."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Command and Control",
            mitre_technique  = "T1071",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # STRIKE-003 - High Outbound Transfer
    # -------------------------------------------------------------------------

    def _strike003_high_outbound_transfer(self, flow: dict) -> Detection | None:
        """
        STRIKE-003 - High Outbound Transfer Detection
        Fires when a source IP's total outbound transfer to external
        destinations exceeds high_transfer_threshold_mb within a window.

        MITRE: T1041 - Exfiltration Over C2 Channel
        """
        src_ip = flow["src_ip"]

        if flow.get("is_external") is not True:
            return None

        total_bytes = self.db.get_outbound_bytes(
            src_ip         = src_ip,
            window_seconds = settings.port_scan_window_seconds * 10,
        )

        total_mb = total_bytes / (1024 * 1024)

        if total_mb < settings.high_transfer_threshold_mb:
            return None

        severity = (
            AlertSeverity.CRITICAL
            if total_mb >= settings.high_transfer_threshold_mb * 5
            else AlertSeverity.HIGH
        )

        return Detection(
            detection_code   = "STRIKE-003",
            engine_id        = EngineID.NETWORK_FLOW,
            severity         = severity,
            title            = "High Outbound Transfer Detected",
            description      = (
                f"Source {src_ip} transferred {total_mb:.1f} MB to external "
                f"destinations. Threshold is {settings.high_transfer_threshold_mb} MB. "
                f"Volume anomaly consistent with potential data exfiltration."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Exfiltration",
            mitre_technique  = "T1041",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # STRIKE-004 - Internal Pivot
    # -------------------------------------------------------------------------

    def _strike004_internal_pivot(self, flow: dict) -> Detection | None:
        """
        STRIKE-004 - Internal Pivot Detection
        Fires when a source IP connects to more than
        internal_pivot_connection_threshold distinct internal destinations
        within internal_pivot_window_seconds. Indicates lateral movement.

        MITRE: T1021 - Remote Services
        """
        src_ip = flow["src_ip"]

        if flow.get("is_external") is True:
            return None

        destinations = self.db.get_distinct_internal_destinations(
            src_ip         = src_ip,
            window_seconds = settings.internal_pivot_window_seconds,
        )

        if len(destinations) < settings.internal_pivot_connection_threshold:
            return None

        severity = (
            AlertSeverity.CRITICAL
            if len(destinations) >= settings.internal_pivot_connection_threshold * 2
            else AlertSeverity.HIGH
        )

        return Detection(
            detection_code   = "STRIKE-004",
            engine_id        = EngineID.NETWORK_FLOW,
            severity         = severity,
            title            = "Internal Pivot Detected",
            description      = (
                f"Source {src_ip} connected to {len(destinations)} distinct internal "
                f"hosts within {settings.internal_pivot_window_seconds} seconds: "
                f"{', '.join(destinations[:10])}. "
                f"This pattern is consistent with lateral movement via network pivoting."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Lateral Movement",
            mitre_technique  = "T1021",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # STRIKE-005 - Known-Bad Destination
    # -------------------------------------------------------------------------

    def _strike005_known_bad_destination(self, flow: dict) -> Detection | None:
        """
        STRIKE-005 - Known-Bad Destination Detection
        Fires immediately when a flow's destination matches an entry
        in the threat intelligence known-bad indicator list.

        MITRE: T1071 - Application Layer Protocol
        """
        if not flow.get("threat_intel_match"):
            return None

        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]
        matched_indicator = flow.get("matched_indicator", dst_ip)

        return Detection(
            detection_code   = "STRIKE-005",
            engine_id        = EngineID.NETWORK_FLOW,
            severity         = AlertSeverity.CRITICAL,
            title            = "Known-Bad Destination Contacted",
            description      = (
                f"Source {src_ip} communicated with {dst_ip}, which matches "
                f"a known-bad threat intelligence indicator: {matched_indicator}. "
                f"This is a confirmed indicator of compromise."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Command and Control",
            mitre_technique  = "T1071",
            risk_contribution = severity_to_contribution(AlertSeverity.CRITICAL),
        )