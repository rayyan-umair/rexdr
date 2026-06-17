"""
rexdr - Network Flow Intelligence Engine
inspector.py - Deep packet inspection and threat intel matching

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Enriches flow records with threat intelligence matching,
          network zone tagging, and normalization into
          NormalizedTelemetryPayload. Loads the known-bad indicator
          list once at startup and checks every flow against it.
          This is the intelligence enrichment layer that sits between
          raw flow capture and detection logic.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
from datetime import datetime, timezone
from pathlib import Path

# -- Third Party -------------------------------------------------------------
import yaml

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, NetworkZone, NormalizedTelemetryPayload
from network_flow.capture import is_private_ip
from network_flow.config import settings

# ============================================================================

logger = logging.getLogger(__name__)


class FlowInspector:
    """
    Enriches and normalizes flow records.

    Loads the known-bad indicator list and network zone definitions
    once at startup. Every flow passed to inspect() is checked against
    threat intel and tagged with its source and destination zones.
    """

    def __init__(self) -> None:
        self.known_bad: set[str] = self._load_known_bad()
        self.zones: list[NetworkZone] = self._load_zones()

    # -------------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------------

    def _load_known_bad(self) -> set[str]:
        """Load the known-bad IP and domain list from disk."""
        path = settings.known_bad_path
        if not path.exists():
            logger.warning("Known-bad indicator file not found - path=%s", path)
            return set()

        indicators = set()
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    indicators.add(line)

        logger.info("Known-bad indicators loaded - count=%d", len(indicators))
        return indicators

    def _load_zones(self) -> list[NetworkZone]:
        """Load network zone definitions from zones.yaml."""
        path = settings.zones_config_path
        if not path.exists():
            logger.warning("Zones config not found - path=%s", path)
            return []

        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        zones = [NetworkZone(**z) for z in data.get("zones", [])]
        logger.info("Network zones loaded - count=%d", len(zones))
        return zones

    # -------------------------------------------------------------------------
    # Zone matching
    # -------------------------------------------------------------------------

    def _match_zone(self, ip: str) -> str | None:
        """Match an IP address to a configured network zone by CIDR."""
        import ipaddress

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for zone in self.zones:
            try:
                network = ipaddress.ip_network(zone.cidr, strict=False)
                if addr in network:
                    return zone.zone_id
            except ValueError:
                continue

        return None

    # -------------------------------------------------------------------------
    # Threat intel matching
    # -------------------------------------------------------------------------

    def _check_threat_intel(self, ip: str) -> str | None:
        """Check if an IP matches a known-bad indicator. Returns the match or None."""
        if ip in self.known_bad:
            return ip
        return None

    # -------------------------------------------------------------------------
    # Inspection
    # -------------------------------------------------------------------------

    def inspect(self, flow: dict) -> dict:
        """
        Enrich a flow dict with zone tags and threat intel match.
        Returns the enriched flow dict ready for database insertion.
        """
        src_zone = self._match_zone(flow["src_ip"])
        dst_zone = self._match_zone(flow["dst_ip"])

        flow["zone_source"]      = src_zone
        flow["zone_destination"] = dst_zone
        flow["is_cross_zone"]    = (
            src_zone is not None
            and dst_zone is not None
            and src_zone != dst_zone
        )

        threat_match = self._check_threat_intel(flow["dst_ip"])
        flow["threat_intel_match"] = threat_match is not None
        flow["matched_indicator"]  = threat_match

        return flow

    def to_normalized_payload(self, flow: dict) -> NormalizedTelemetryPayload:
        """Convert an enriched flow dict into a NormalizedTelemetryPayload."""
        severity = AlertSeverity.INFO

        if flow.get("threat_intel_match"):
            severity = AlertSeverity.HIGH
        elif flow.get("is_cross_zone"):
            severity = AlertSeverity.LOW

        tags = [f"protocol:{flow.get('protocol', 'unknown').lower()}"]
        if flow.get("is_cross_zone"):
            tags.append("cross_zone")
        if flow.get("threat_intel_match"):
            tags.append("threat_intel_match")
        if flow.get("is_external"):
            tags.append("external")

        description = (
            f"Flow {flow['src_ip']}:{flow.get('src_port', 0)} -> "
            f"{flow['dst_ip']}:{flow.get('dst_port', 0)} "
            f"({flow.get('protocol', 'unknown')}) "
            f"{flow.get('packet_count', 0)} packets, "
            f"{flow.get('bytes_sent', 0)} bytes"
        )

        if flow.get("threat_intel_match"):
            description += f" | THREAT INTEL MATCH: {flow.get('matched_indicator')}"

        return NormalizedTelemetryPayload(
            engine_id        = EngineID.NETWORK_FLOW,
            timestamp        = flow.get("start_time", datetime.now(timezone.utc)),
            source_ip        = flow["src_ip"],
            destination_ip   = flow["dst_ip"],
            event_type       = "network_flow",
            description      = description,
            raw_data         = flow,
            zone_source      = flow.get("zone_source"),
            zone_destination = flow.get("zone_destination"),
            is_cross_zone    = flow.get("is_cross_zone", False),
            tags             = tags,
            severity         = severity,
        )