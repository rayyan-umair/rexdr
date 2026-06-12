"""
rexdr_core
identity.py - Platform identity, constants, and engine registry

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Defines the canonical identity of the REXDR platform.
          Contains the version string, platform metadata, and the
          EngineID registry that every engine uses to identify itself.
          Nothing in this file changes at runtime. It is read-only
          platform-wide truth.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
from enum import Enum

# ============================================================================

VERSION = "1.0.0"

METADATA = {
    "name": "REXDR",
    "full_name": "Real-time Extended Detection and Response",
    "version": VERSION,
    "author": "Rayyan Umair",
    "contact": "rayyanxumair@gmail.com",
    "github": "github.com/rayyan-umair/rexdr",
    "license": "Proprietary - All Rights Reserved",
    "description": (
        "A unified commercial-grade XDR platform. Eight intelligence engines "
        "running in complete harmony - Windows events, network flows, DNS, "
        "Active Directory, SIEM correlation, incident response, asset discovery, "
        "and vulnerability intelligence - all sharing a single entity model, "
        "cross-correlating in real time."
    ),
}


class EngineID(str, Enum):
    """
    Canonical identifiers for every engine inside REXDR.
    Used as keys in entity observations, attack chains,
    ZeroMQ topics, and DuckDB ATTACH references.
    All engines must identify themselves using this enum.
    """

    WINDOWS_EVENT   = "windows_event"
    NETWORK_FLOW    = "network_flow"
    DNS             = "dns"
    SIEM            = "siem"
    IDENTITY        = "identity"
    RESPONSE        = "response"
    ASSET_DISCOVERY = "asset_discovery"
    VULNERABILITY   = "vulnerability"


# Human-readable engine names - used in UI and reports
ENGINE_DISPLAY_NAMES = {
    EngineID.WINDOWS_EVENT:   "Windows Event Intelligence",
    EngineID.NETWORK_FLOW:    "Network Flow Intelligence",
    EngineID.DNS:             "DNS Behavioral Intelligence",
    EngineID.SIEM:            "Sigma Correlation Engine",
    EngineID.IDENTITY:        "Active Directory Intelligence",
    EngineID.RESPONSE:        "Incident Response Orchestration",
    EngineID.ASSET_DISCOVERY: "Network Discovery",
    EngineID.VULNERABILITY:   "Vulnerability Intelligence",
}

# ZeroMQ topic prefixes - one per engine
ENGINE_ZMQ_TOPICS = {
    EngineID.WINDOWS_EVENT:   b"windows_event",
    EngineID.NETWORK_FLOW:    b"network_flow",
    EngineID.DNS:             b"dns",
    EngineID.SIEM:            b"siem",
    EngineID.IDENTITY:        b"identity",
    EngineID.RESPONSE:        b"response",
    EngineID.ASSET_DISCOVERY: b"asset_discovery",
    EngineID.VULNERABILITY:   b"vulnerability",
}

# DuckDB file names - one per engine
ENGINE_DB_FILES = {
    EngineID.WINDOWS_EVENT:   "windows_event.duckdb",
    EngineID.NETWORK_FLOW:    "network_flow.duckdb",
    EngineID.DNS:             "dns.duckdb",
    EngineID.SIEM:            "siem.duckdb",
    EngineID.IDENTITY:        "identity.duckdb",
    EngineID.RESPONSE:        "response.duckdb",
    EngineID.ASSET_DISCOVERY: "asset_discovery.duckdb",
    EngineID.VULNERABILITY:   "vulnerability.duckdb",
}

# API ports - one per engine
ENGINE_PORTS = {
    EngineID.WINDOWS_EVENT:   8000,
    EngineID.NETWORK_FLOW:    8001,
    EngineID.SIEM:            8002,
    EngineID.DNS:             8003,
    EngineID.IDENTITY:        8004,
    EngineID.RESPONSE:        8005,
    EngineID.ASSET_DISCOVERY: 8006,
    EngineID.VULNERABILITY:   8007,
}

# ZeroMQ ports - capture to intelligence layer
ENGINE_ZMQ_PORTS = {
    EngineID.WINDOWS_EVENT: 5555,
    EngineID.DNS:           5557,
    EngineID.IDENTITY:      5558,
}