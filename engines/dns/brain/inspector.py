"""
rexdr - DNS Behavioral Intelligence Engine
inspector.py - Entropy scoring and rare TLD checking

Author  : Rayyan Umair
Date    : 2026-06-16
Purpose : Calculates Shannon entropy for DNS subdomains, checks queries
          against the rare/abused TLD list, and normalizes raw queries
          into NormalizedTelemetryPayload. This is the intelligence
          enrichment layer that sits between raw query capture and
          detection logic.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Hunt the whisper."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import math
from collections import Counter
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, NormalizedTelemetryPayload
from dns.config import settings

# ============================================================================

logger = logging.getLogger(__name__)


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    High entropy subdomains (random-looking character distributions)
    are a strong indicator of DGA (Domain Generation Algorithm) malware
    or DNS tunneling, since legitimate hostnames tend to be readable
    and have lower entropy.
    """
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


class DnsInspector:
    """
    Enriches and normalizes DNS queries.

    Loads the rare TLD list once at startup. Every query passed to
    inspect() gets an entropy score calculated and is checked against
    the rare TLD list.
    """

    def __init__(self) -> None:
        self.rare_tlds: set[str] = self._load_rare_tlds()

    # -------------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------------

    def _load_rare_tlds(self) -> set[str]:
        """Load the rare/abused TLD list from disk."""
        path = settings.rare_tlds_path
        if not path.exists():
            logger.warning("Rare TLDs file not found - path=%s", path)
            return set()

        tlds = set()
        with open(path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    tlds.add(line)

        logger.info("Rare TLDs loaded - count=%d", len(tlds))
        return tlds

    # -------------------------------------------------------------------------
    # Inspection
    # -------------------------------------------------------------------------

    def inspect(self, query: dict) -> dict:
        """
        Enrich a raw DNS query dict with entropy score, TLD, and
        subdomain depth. Returns the enriched dict ready for storage.
        """
        query_name = query.get("query_name", "")
        parts = query_name.rstrip(".").split(".")

        tld = parts[-1].lower() if len(parts) >= 1 else ""
        subdomain_depth = max(0, len(parts) - 2)

        # Calculate entropy on the leftmost (most specific) subdomain label
        # since that's where DGA and tunneling encoding typically appears
        target_label = parts[0] if parts else ""
        entropy_score = calculate_shannon_entropy(target_label)

        query["tld"]             = tld
        query["subdomain_depth"] = subdomain_depth
        query["entropy_score"]   = entropy_score
        query["is_rare_tld"]     = tld in self.rare_tlds

        return query

    def to_normalized_payload(self, query: dict) -> NormalizedTelemetryPayload:
        """Convert an enriched DNS query dict into a NormalizedTelemetryPayload."""
        severity = AlertSeverity.INFO

        if query.get("entropy_score", 0.0) >= settings.entropy_threshold:
            severity = AlertSeverity.MEDIUM
        if query.get("is_rare_tld"):
            severity = AlertSeverity.LOW if severity == AlertSeverity.INFO else severity
        if query.get("response_code") == "NXDOMAIN":
            severity = AlertSeverity.LOW if severity == AlertSeverity.INFO else severity

        tags = [f"qtype:{query.get('query_type', 'unknown')}"]
        if query.get("is_rare_tld"):
            tags.append("rare_tld")
        if query.get("entropy_score", 0.0) >= settings.entropy_threshold:
            tags.append("high_entropy")
        if query.get("response_code") == "NXDOMAIN":
            tags.append("nxdomain")

        description = (
            f"DNS query {query.get('query_name')} "
            f"({query.get('query_type', 'unknown')}) from {query.get('source_ip')} "
            f"| entropy={query.get('entropy_score', 0.0):.2f} "
            f"| response={query.get('response_code', 'unknown')}"
        )

        return NormalizedTelemetryPayload(
            engine_id      = EngineID.DNS,
            timestamp      = query.get("timestamp", datetime.now(timezone.utc)),
            source_ip      = query.get("source_ip"),
            event_type     = "dns_query",
            description    = description,
            raw_data       = query,
            tags           = tags,
            severity       = severity,
        )