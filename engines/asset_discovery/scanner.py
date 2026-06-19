"""
rexdr - Network Discovery Engine
scanner.py - Nmap-based network and asset scanning

Author  : Rayyan Umair
Date    : 2026-06-19
Purpose : Performs network discovery and port scanning using python-nmap.
          Derives the subnets to scan from zones.yaml CIDR definitions.
          Returns structured scan results - open ports, services, OS
          fingerprint - ready for database storage and entity tracking.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Map the terrain before the enemy does."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import ipaddress
import logging

# -- Third Party -------------------------------------------------------------
import nmap
import yaml

# -- Internal ----------------------------------------------------------------
from asset_discovery.config import settings

# ============================================================================

logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Performs scheduled network discovery scans across all configured
    zones. Uses python-nmap for host discovery, port scanning, service
    detection, and OS fingerprinting.
    """

    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        self.zones = self._load_zones()

    # -------------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------------

    def _load_zones(self) -> list[dict]:
        """Load network zone CIDR definitions from zones.yaml."""
        path = settings.zones_config_path
        if not path.exists():
            logger.warning("Zones config not found - path=%s", path)
            return []

        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        zones = data.get("zones", [])
        logger.info("Network zones loaded for scanning - count=%d", len(zones))
        return zones

    def _match_zone(self, ip: str) -> str | None:
        """Match a discovered IP to its configured network zone."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for zone in self.zones:
            try:
                network = ipaddress.ip_network(zone["cidr"], strict=False)
                if addr in network:
                    return zone["zone_id"]
            except (ValueError, KeyError):
                continue

        return None

    # -------------------------------------------------------------------------
    # Scanning
    # -------------------------------------------------------------------------

    def scan_all_zones(self) -> list[dict]:
        """
        Run a full discovery and port scan across every configured
        zone's CIDR range. Returns a list of structured asset dicts.
        """
        all_results: list[dict] = []

        for zone in self.zones:
            cidr = zone.get("cidr")
            if not cidr:
                continue

            results = self._scan_subnet(cidr)
            all_results.extend(results)

        logger.info("Scan complete across all zones - hosts_found=%d", len(all_results))
        return all_results

    def _scan_subnet(self, cidr: str) -> list[dict]:
        """Scan a single subnet and return structured results for each live host."""
        try:
            arguments = f"{settings.scan_timing_template} -O -sV -p {settings.scan_ports}"
            self.nm.scan(hosts=cidr, arguments=arguments)
        except Exception as e:
            logger.error("Nmap scan failed - cidr=%s error=%s", cidr, str(e))
            return []

        results = []

        for host in self.nm.all_hosts():
            if self.nm[host].state() != "up":
                continue

            host_data = self._extract_host_data(host)
            results.append(host_data)

        return results

    def _extract_host_data(self, host: str) -> dict:
        """Extract structured data for a single scanned host."""
        host_info = self.nm[host]

        hostname = None
        if host_info.get("hostnames"):
            hostname = host_info["hostnames"][0].get("name") or None

        mac_address = None
        if "mac" in host_info.get("addresses", {}):
            mac_address = host_info["addresses"]["mac"]

        os_fingerprint = None
        if host_info.get("osmatch"):
            os_fingerprint = host_info["osmatch"][0].get("name")

        open_ports = []
        services = {}

        for proto in host_info.all_protocols():
            ports = host_info[proto].keys()
            for port in ports:
                port_info = host_info[proto][port]
                if port_info.get("state") == "open":
                    open_ports.append(int(port))
                    service_name = port_info.get("name", "unknown")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    services[str(port)] = f"{service_name} {product} {version}".strip()

        return {
            "ip_address":      host,
            "hostname":        hostname,
            "mac_address":     mac_address,
            "os_fingerprint":  os_fingerprint,
            "open_ports":      sorted(open_ports),
            "services":        services,
            "network_zone":    self._match_zone(host),
        }