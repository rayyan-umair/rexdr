"""
rexdr - DNS Behavioral Intelligence Engine
detections.py - Detection logic for the DNS engine

Author  : Rayyan Umair
Date    : 2026-06-16
Purpose : Implements all five detection algorithms for the DNS
          Behavioral Intelligence engine. Each detection is a
          self-contained method that receives an enriched query,
          queries the database for context, and returns a Detection
          object if the threshold is met. All detections follow the
          ENGINE-NNN code format.

          DNS-001  High Entropy Subdomain
          DNS-002  Record Type Frequency Spike
          DNS-003  DNS Beaconing
          DNS-004  NXDOMAIN Storm
          DNS-005  Rare TLD Anomaly

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Hunt the whisper."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import statistics

# -- Internal ----------------------------------------------------------------
from rexdr_core.formula import severity_to_contribution
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, Detection, EntityType
from dns.config import settings
from dns.database import DnsDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class DnsDetections:
    """
    Detection engine for DNS Behavioral Intelligence.
    Receives enriched query dicts and runs all applicable
    detection algorithms against each one.
    """

    def __init__(self, db: DnsDatabase) -> None:
        self.db = db

    def run(self, query: dict) -> list[Detection]:
        """
        Run all detection algorithms against a DNS query.
        Returns a list of Detection objects - empty if nothing fired.
        """
        detections: list[Detection] = []

        dns001 = self._dns001_high_entropy(query)
        dns002 = self._dns002_record_type_spike(query)
        dns003 = self._dns003_beaconing(query)
        dns004 = self._dns004_nxdomain_storm(query)
        dns005 = self._dns005_rare_tld(query)

        for detection in [dns001, dns002, dns003, dns004, dns005]:
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
    # DNS-001 - High Entropy Subdomain
    # -------------------------------------------------------------------------

    def _dns001_high_entropy(self, query: dict) -> Detection | None:
        """
        DNS-001 - High Entropy Subdomain Detection
        Fires when a queried subdomain's Shannon entropy exceeds
        entropy_threshold, indicating likely DGA malware or DNS tunneling.

        MITRE: T1568.002 - Dynamic Resolution - Domain Generation Algorithms
        """
        entropy = query.get("entropy_score", 0.0)

        if entropy < settings.entropy_threshold:
            return None

        src_ip = query.get("source_ip")
        if not src_ip:
            return None

        severity = (
            AlertSeverity.HIGH
            if entropy >= settings.entropy_threshold + 0.8
            else AlertSeverity.MEDIUM
        )

        return Detection(
            detection_code   = "DNS-001",
            engine_id        = EngineID.DNS,
            severity         = severity,
            title            = "High Entropy Subdomain Detected",
            description      = (
                f"Source {src_ip} queried {query.get('query_name')} with "
                f"Shannon entropy {entropy:.2f}, exceeding threshold "
                f"{settings.entropy_threshold}. Consistent with DGA malware "
                f"or DNS tunneling exfiltration."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Command and Control",
            mitre_technique  = "T1568.002",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # DNS-002 - Record Type Frequency Spike
    # -------------------------------------------------------------------------

    def _dns002_record_type_spike(self, query: dict) -> Detection | None:
        """
        DNS-002 - Record Type Frequency Spike Detection
        Fires when a source IP generates an abnormal volume of TXT,
        NULL, or AAAA record queries - record types commonly abused
        for DNS-based data encoding and exfiltration channels.

        MITRE: T1071.004 - Application Layer Protocol - DNS
        """
        query_type = query.get("query_type", "").upper()

        if query_type not in ("TXT", "NULL", "AAAA"):
            return None

        src_ip = query.get("source_ip")
        if not src_ip:
            return None

        count = self.db.get_record_type_count(
            source_ip      = src_ip,
            record_type    = query_type,
            window_seconds = settings.record_type_spike_window_seconds,
        )

        if count < settings.record_type_spike_threshold:
            return None

        severity = (
            AlertSeverity.HIGH
            if count >= settings.record_type_spike_threshold * 2
            else AlertSeverity.MEDIUM
        )

        return Detection(
            detection_code   = "DNS-002",
            engine_id        = EngineID.DNS,
            severity         = severity,
            title            = "DNS Record Type Frequency Spike",
            description      = (
                f"Source {src_ip} generated {count} {query_type} record "
                f"queries within {settings.record_type_spike_window_seconds} "
                f"seconds. This record type is commonly abused for DNS-based "
                f"data encoding and covert exfiltration channels."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Exfiltration",
            mitre_technique  = "T1071.004",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # DNS-003 - DNS Beaconing
    # -------------------------------------------------------------------------

    def _dns003_beaconing(self, query: dict) -> Detection | None:
        """
        DNS-003 - DNS Beaconing Detection
        Fires when queries from a source to the same domain occur at
        regular, timed intervals consistent with C2 heartbeat behavior
        over a DNS-based command channel.

        MITRE: T1071.004 - Application Layer Protocol - DNS
        """
        src_ip     = query.get("source_ip")
        query_name = query.get("query_name")

        if not src_ip or not query_name:
            return None

        intervals = self.db.get_query_intervals(
            source_ip  = src_ip,
            query_name = query_name,
            limit      = settings.beacon_count_threshold + 5,
        )

        if len(intervals) < settings.beacon_count_threshold:
            return None

        avg_interval = statistics.mean(intervals)

        if not (settings.beacon_interval_min_seconds <= avg_interval <= settings.beacon_interval_max_seconds):
            return None

        if avg_interval == 0:
            return None

        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        coefficient_of_variation = std_dev / avg_interval

        if coefficient_of_variation >= 0.3:
            return None

        severity = (
            AlertSeverity.CRITICAL
            if coefficient_of_variation < 0.1
            else AlertSeverity.HIGH
        )

        return Detection(
            detection_code   = "DNS-003",
            engine_id        = EngineID.DNS,
            severity         = severity,
            title            = "DNS Beaconing Detected",
            description      = (
                f"Source {src_ip} queried {query_name} {len(intervals)} times "
                f"with highly regular timing - average interval "
                f"{avg_interval:.1f}s, coefficient of variation "
                f"{coefficient_of_variation:.3f}. Consistent with DNS-based "
                f"C2 heartbeat traffic."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Command and Control",
            mitre_technique  = "T1071.004",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # DNS-004 - NXDOMAIN Storm
    # -------------------------------------------------------------------------

    def _dns004_nxdomain_storm(self, query: dict) -> Detection | None:
        """
        DNS-004 - NXDOMAIN Storm Detection
        Fires when a source IP generates an abnormal volume of failed
        (NXDOMAIN) lookups within a short window - a strong indicator
        of DGA malware cycling through generated domain candidates.

        MITRE: T1568.002 - Dynamic Resolution - Domain Generation Algorithms
        """
        if query.get("response_code") != "NXDOMAIN":
            return None

        src_ip = query.get("source_ip")
        if not src_ip:
            return None

        count = self.db.get_recent_nxdomain_count(
            source_ip      = src_ip,
            window_seconds = settings.nxdomain_storm_window_seconds,
        )

        if count < settings.nxdomain_storm_threshold:
            return None

        severity = (
            AlertSeverity.HIGH
            if count >= settings.nxdomain_storm_threshold * 3
            else AlertSeverity.MEDIUM
        )

        return Detection(
            detection_code   = "DNS-004",
            engine_id        = EngineID.DNS,
            severity         = severity,
            title            = "NXDOMAIN Storm Detected",
            description      = (
                f"Source {src_ip} generated {count} NXDOMAIN responses "
                f"within {settings.nxdomain_storm_window_seconds} seconds. "
                f"Threshold is {settings.nxdomain_storm_threshold}. Pattern "
                f"is consistent with DGA malware cycling through generated "
                f"domain candidates."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Command and Control",
            mitre_technique  = "T1568.002",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # DNS-005 - Rare TLD Anomaly
    # -------------------------------------------------------------------------

    def _dns005_rare_tld(self, query: dict) -> Detection | None:
        """
        DNS-005 - Rare TLD Anomaly Detection
        Fires when a query resolves against a TLD on the known-abused
        rare TLD list. Many free or low-trust TLDs are disproportionately
        used for malicious infrastructure due to low registration cost
        and minimal verification requirements.

        MITRE: T1583.001 - Acquire Infrastructure - Domains
        """
        if not query.get("is_rare_tld"):
            return None

        src_ip = query.get("source_ip")
        if not src_ip:
            return None

        return Detection(
            detection_code   = "DNS-005",
            engine_id        = EngineID.DNS,
            severity         = AlertSeverity.LOW,
            title            = "Rare TLD Anomaly Detected",
            description      = (
                f"Source {src_ip} queried {query.get('query_name')}, which "
                f"resolves under TLD '.{query.get('tld')}' - a top-level "
                f"domain disproportionately associated with malicious "
                f"infrastructure due to low registration barriers."
            ),
            entity_id        = src_ip,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [],
            mitre_tactic     = "Resource Development",
            mitre_technique  = "T1583.001",
            risk_contribution = severity_to_contribution(AlertSeverity.LOW),
        )